package signingkeys

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/ericfitz/agentmesh/internal/auth/keys"
	"github.com/ericfitz/agentmesh/internal/auth/token"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/keyprovider"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
)

// MinLeafValidity and MaxLeafValidity bound Options.LeafValidity (W).
const (
	MinLeafValidity = 2 * time.Hour
	MaxLeafValidity = 720 * time.Hour
)

// The start states of a Manager (section 4.6). Each is returned as is or
// wrapped with %w and the detail.
var (
	// ErrNoIntermediate: no stored intermediate matches the configured key.
	ErrNoIntermediate = errors.New("signingkeys: no stored intermediate certificate matches the configured intermediate key: " +
		"make a request with `agentmesh server admin ca csr`, have the root sign it, and store the certificate with `agentmesh server admin ca install`")
	// ErrIntermediateExpired: the matching intermediates are all outside their validity.
	ErrIntermediateExpired = errors.New("signingkeys: every intermediate certificate of the configured key is expired or not yet valid")
	// ErrIntermediateRevoked: the stored root CRL revokes the configured key.
	ErrIntermediateRevoked = errors.New("signingkeys: the stored root CRL revokes the configured intermediate key")
	// ErrRootExpired: the pinned root certificate is past its "not after".
	ErrRootExpired = errors.New("signingkeys: the pinned root certificate has expired")
)

// msgNotCertKey names the failed issue of a key service that signs with a key
// other than the certificate's.
const msgNotCertKey = "the configured key is not the certificate's key"

// Options configures New.
type Options struct {
	Trust        Trust         // Provider is required
	LeafValidity time.Duration // W: 2 to 720 hours
	OnChange     func()        // runs after this process's leaf or its view of the trust material changed; nil is fine
}

// leafKey is the leaf this process signs with and the private key it alone
// holds. The key lives in a Manager and nowhere else (never stored, never
// logged).
type leafKey struct {
	gen        uint64 // the load generation at the swap
	thumbprint string
	verified   pki.Verified
	signer     leafSigner
}

// leafSigner signs with an in-memory Ed25519 key; it is a token.ContextSigner.
type leafSigner struct{ priv ed25519.PrivateKey }

func (s leafSigner) Public() crypto.PublicKey { return s.priv.Public() }

func (s leafSigner) SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	return s.priv.Sign(rand.Reader, digest, opts)
}

// Manager issues this process's leaf certificate and publishes the verified
// leaves of the stored trust material as the issuer's key set (ADR 0019
// section 4.6). Concurrency (Plan ruling 33): mu guards mem, mat, cur, prev,
// loaded, gen, revoked and onChange and is never held while the intermediate key
// signs; issueMu is held for the whole of each operation that issues a leaf.
type Manager struct {
	trust    Trust
	validity time.Duration

	issueMu sync.Mutex

	mu       sync.Mutex
	mem      Memory
	mat      Material
	loaded   bool
	gen      uint64          // number of loads so far
	revoked  map[string]bool // verified leaves of the last load by thumbprint: revoked or not
	cur      *leafKey
	prev     *leafKey
	onChange func()
}

var _ token.KeySource = (*Manager)(nil)

// New loads the trust material, picks the intermediate (Trust.Pick; Decision
// 48) and issues the first leaf. Its errors are one of ErrNoIntermediate,
// ErrIntermediateExpired, ErrIntermediateRevoked and ErrRootExpired, an error
// that wraps keyprovider.ErrUnavailable, or a Store failure.
func New(ctx context.Context, o Options) (*Manager, error) {
	if o.Trust.Core == nil || o.Trust.Root == nil {
		return nil, errors.New("signingkeys: the trust rules need a core and a root certificate")
	}
	if o.Trust.Provider == nil {
		return nil, errors.New("signingkeys: a key provider is required")
	}
	if o.LeafValidity < MinLeafValidity || o.LeafValidity > MaxLeafValidity {
		return nil, fmt.Errorf("signingkeys: the leaf validity is %s, want %s to %s", o.LeafValidity, MinLeafValidity, MaxLeafValidity)
	}
	m := &Manager{trust: o.Trust, validity: o.LeafValidity, onChange: o.OnChange}
	if _, err := m.reload(ctx); err != nil {
		return nil, err
	}
	if err := m.issue(ctx); err != nil {
		return nil, err
	}
	return m, nil
}

// SetOnChange replaces the function that runs after this process's leaf or its
// view of the trust material changed.
func (m *Manager) SetOnChange(f func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.onChange = f
}

// Trust returns the Trust the manager was made with.
func (m *Manager) Trust() Trust { return m.trust }

// usable reports whether l can sign now: its chain is inside its period with
// the token leeway and it is not revoked. A leaf issued since the last load is
// usable (the load has not seen its row yet); after a load that no longer
// verifies it, it is not (the key set has no Active either). Caller holds mu.
func (m *Manager) usable(l *leafKey, now time.Time) bool {
	if l == nil || !l.verified.ValidAt(now, token.Leeway) {
		return false
	}
	if l.gen == m.gen {
		return true
	}
	revoked, verified := m.revoked[l.thumbprint]
	return verified && !revoked
}

// Current is the thumbprint and "not after" of the leaf this process signs
// with; "" when nothing can sign (none, expired or revoked).
func (m *Manager) Current() (thumbprint string, notAfter time.Time) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.usable(m.cur, m.trust.Now()) {
		return "", time.Time{}
	}
	return m.cur.thumbprint, m.cur.verified.NotAfter
}

// LoadKeys implements token.KeySource: it reloads, then returns the set.
func (m *Manager) LoadKeys(ctx context.Context) (token.KeySet, error) {
	// The reload and the set are one hold of mu: a leaf swapped in by issue
	// between them would be missing from the loaded material, and the set
	// would carry no Active and no Signer although a leaf can sign.
	m.mu.Lock()
	defer m.mu.Unlock()
	if _, err := m.reloadLocked(ctx); err != nil {
		return token.KeySet{}, err
	}
	return m.keySet(m.trust.Now()), nil
}

// keySet is every leaf of the loaded material that is not revoked and whose
// period contains now with token.Leeway; Active and Signer are the current
// leaf's when it is among them. The current leaf is listed first. Caller holds
// mu.
func (m *Manager) keySet(now time.Time) token.KeySet {
	var set token.KeySet
	for _, l := range m.mat.Leaves {
		if l.Revoked || !l.Verified.ValidAt(now, token.Leeway) {
			continue
		}
		k := token.Key{
			KID:       pki.Thumbprint(l.Verified.Leaf.Raw),
			Algorithm: keys.EdDSA,
			Public:    l.Verified.Leaf.PublicKey,
			Chain:     [][]byte{l.Verified.Leaf.Raw, l.Verified.Intermediate.Raw},
			NotBefore: l.Verified.NotBefore,
			NotAfter:  l.Verified.NotAfter,
		}
		if m.cur != nil && k.KID == m.cur.thumbprint {
			set.Active, set.Signer = k, m.cur.signer
			set.Keys = append([]token.Key{k}, set.Keys...)
			continue
		}
		set.Keys = append(set.Keys, k)
	}
	return set
}

// reload is the load without reactions: Trust.Load with the manager's Memory,
// then the snapshot is swapped. changed: the trust number or the set of
// verified leaves differs from the last load. LoadKeys here and Step in Task
// 18 call it; Task 19 builds the exported Reload on it (the reactions) and
// moves both callers to that.
func (m *Manager) reload(ctx context.Context) (changed bool, err error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.reloadLocked(ctx)
}

// reloadLocked is reload for a caller that holds mu; Task 19's Reload builds
// on it.
func (m *Manager) reloadLocked(ctx context.Context) (changed bool, err error) {
	mat, err := m.trust.Load(ctx, &m.mem)
	if err != nil {
		return false, err
	}
	revoked := make(map[string]bool, len(mat.Leaves))
	for _, l := range mat.Leaves {
		revoked[pki.Thumbprint(l.Verified.Leaf.Raw)] = l.Revoked
	}
	changed = !m.loaded || mat.Number != m.mat.Number || len(revoked) != len(m.revoked)
	for tp := range revoked {
		if _, ok := m.revoked[tp]; !ok {
			changed = true
		}
	}
	m.mat, m.revoked, m.loaded = mat, revoked, true
	m.gen++
	return changed, nil
}

// check applies the start rules to what Pick found (the manager writes no
// matching rule of its own: Plan ruling 12).
func (m *Manager) check(p Picked, mat Material) error {
	now := m.trust.Now()
	if now.After(m.trust.Root.NotAfter) {
		return fmt.Errorf("%w: it expired at %s", ErrRootExpired, m.trust.Root.NotAfter.UTC().Format(time.RFC3339))
	}
	if len(p.Configured) == 0 {
		return ErrNoIntermediate
	}
	if p.Use == nil {
		return ErrIntermediateExpired
	}
	if mat.RevokedKeys[keyIDOf(p.Use)] {
		return ErrIntermediateRevoked
	}
	return nil
}

// signerFor opens the picked intermediate's key (Decision 48): the file form
// reads the key file, a key service signs with the reference the row pins.
func (m *Manager) signerFor(ctx context.Context, p Picked) (keyprovider.Signer, error) {
	var key keyprovider.Key
	if m.trust.Provider.Name() == keyprovider.NameFile {
		k, err := m.trust.nextKey(ctx)
		if err != nil {
			return nil, err
		}
		key = k
	} else {
		pub, ok := p.Use.PublicKey.(*ecdsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("signingkeys: the intermediate's key is %T, want ECDSA", p.Use.PublicKey)
		}
		k, err := keyprovider.ExternalKey(pub, p.KeyRef)
		if err != nil {
			return nil, fmt.Errorf("signingkeys: %w", err)
		}
		key = k
	}
	s, err := m.trust.Provider.Signer(ctx, key)
	if err != nil {
		return nil, fmt.Errorf("signingkeys: open the intermediate key: %w", err)
	}
	return s, nil
}

// issue issues a leaf and makes it current (section 4.6, in this order): an
// Ed25519 key in memory; pki.IssueLeaf with the intermediate's signer under
// SignTimeout (the "not after" is cut to the intermediate's there); the chain
// check of the new leaf at the current time; the row, in one transaction;
// only then the new leaf is current and the former one the previous. The row
// does not change the trust number. issueMu is held throughout and mu only to
// read the snapshot and to swap the leaf in.
func (m *Manager) issue(ctx context.Context) error {
	m.issueMu.Lock()
	defer m.issueMu.Unlock()

	m.mu.Lock()
	mat := m.mat
	m.mu.Unlock()
	p, err := m.trust.Pick(ctx, mat)
	if err != nil {
		return err
	}
	if err := m.check(p, mat); err != nil {
		return err
	}
	now := m.trust.Now()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return fmt.Errorf("signingkeys: generate the leaf key: %w", err)
	}
	signCtx, cancel := context.WithTimeout(ctx, SignTimeout)
	defer cancel()
	signer, err := m.signerFor(signCtx, p)
	if err != nil {
		return err
	}
	if !samePublic(signer.Public(), p.Use.PublicKey) {
		m.trust.Log.Error(msgNotCertKey, "intermediate", pki.Thumbprint(p.Use.Raw))
		return fmt.Errorf("signingkeys: %s", msgNotCertKey)
	}
	leaf, err := pki.IssueLeaf(p.Use, CryptoSigner(signCtx, signer), pub, now, m.validity)
	if err != nil {
		return fmt.Errorf("signingkeys: sign the leaf: %w", err)
	}
	v, err := pki.VerifyChain([]*x509.Certificate{leaf, p.Use}, m.trust.Root, m.trust.Installation, now, token.Leeway)
	if err != nil {
		m.trust.Log.Error(msgNotCertKey, "intermediate", pki.Thumbprint(p.Use.Raw), "reason", err.Error())
		return fmt.Errorf("signingkeys: %s: %w", msgNotCertKey, err)
	}
	thumb := pki.Thumbprint(leaf.Raw)
	row := store.TrustCertificate{
		Kind: store.TrustLeaf, Thumbprint: thumb, DER: leaf.Raw, IssuerKey: keyIDOf(p.Use),
		NotAfter: leaf.NotAfter.UnixMilli(), CreatedAt: m.trust.NowMs(),
	}
	// No trust lock: a leaf row is append-only under a random serial and does not
	// change the trust number (section 4.9: the bundle carries no leaf).
	err = m.trust.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.PutTrustCertificate(ctx, row)
		return err
	})
	if err != nil {
		return core.FromStore(err)
	}

	m.mu.Lock()
	m.prev, m.cur = m.cur, &leafKey{gen: m.gen, thumbprint: thumb, verified: v, signer: leafSigner{priv: priv}}
	notify := m.onChange
	m.mu.Unlock()
	if notify != nil {
		notify()
	}
	return nil
}
