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
	"sync/atomic"
	"time"

	"github.com/ericfitz/agentmesh/internal/auth/keys"
	"github.com/ericfitz/agentmesh/internal/auth/token"
	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/keyprovider"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
)

// runParkedHook, when set (export_test.go), is called by Run just before it waits.
var runParkedHook func()

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
	// OnChange runs after this process's leaf or its view of the trust material
	// changed; nil is fine. Reload, a renewal and RotateSigningKey call it
	// synchronously, so inside RotateSigningKey it runs while the manager's
	// issuing mutex and the "trust" lock are held: the callback must not take
	// either of them or call back into the manager's issuing paths (Step,
	// RotateSigningKey). Current, LoadKeys and Reload are safe to call.
	OnChange func()
}

// leafKey is the leaf this process signs with and the private key it alone
// holds. The key lives in a Manager and nowhere else (never stored, never
// logged).
type leafKey struct {
	gen        uint64 // the load generation at the swap
	issuedAt   time.Time
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

	// Renewal state (Step; guarded by mu): the time of the last reload Step ran,
	// the time of a pending retry (zero: none) and the last failed issue.
	lastReload time.Time
	retryAt    time.Time
	// retryOutside: the retry was timed while the clock was outside the current leaf's period.
	retryOutside bool
	failure      *Failure

	// stopped is "" or why the manager no longer issues or signs (Reload; guarded
	// by mu). wake is the one-slot channel Reload fills when it makes an issue
	// due and Run waits on.
	stopped string
	wake    chan struct{}

	// bundle is the snapshot of the last load (Bundle). It is read without mu, so
	// a reader never waits for a load that holds mu across a Store read.
	bundle atomic.Pointer[bus.TrustBundle]

	// inUse is the intermediate the last successful Pick chose (the last one
	// chosen while none is valid: it then shows as expired; guarded by mu).
	inUse *x509.Certificate
	// signing is the snapshot Signing reads, rebuilt by publishLocked at every
	// change of the state it summarizes.
	signing atomic.Pointer[signingSnap]
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
	m := &Manager{trust: o.Trust, validity: o.LeafValidity, onChange: o.OnChange, wake: make(chan struct{}, 1)}
	if err := m.reloadAtStart(ctx); err != nil {
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
// the token leeway and it is not revoked. A leaf the last load saw is usable
// when it verified and is not revoked; one issued since is usable (the load
// has not seen its row yet); after a load that no longer verifies it, it is not
// (the key set has no Active either). Caller holds mu.
func (m *Manager) usable(l *leafKey, now time.Time) bool {
	if l == nil || m.stopped != "" || !l.verified.ValidAt(now, token.Leeway) {
		return false
	}
	if revoked, seen := m.revoked[l.thumbprint]; seen {
		return !revoked
	}
	return l.gen == m.gen
}

// inPeriod reports whether l is current as the renewal rules count it: the
// clock is inside its period (no leeway) and the last load did not find it
// revoked, so a revoked leaf is treated as an expired one. Caller holds mu.
func (m *Manager) inPeriod(l *leafKey, now time.Time) bool {
	return l != nil && l.verified.ValidAt(now, 0) && !m.revoked[l.thumbprint]
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

// LoadKeys implements token.KeySource: it reloads (Reload), then returns the
// set.
func (m *Manager) LoadKeys(ctx context.Context) (token.KeySet, error) {
	// The reload and the set are one hold of mu: a leaf swapped in by issue
	// between them would be missing from the loaded material, and the set
	// would carry no Active and no Signer although a leaf can sign.
	m.mu.Lock()
	r, err := m.reloadReactLocked(ctx)
	if err != nil {
		m.mu.Unlock()
		return token.KeySet{}, err
	}
	set := m.keySet(m.trust.Now())
	m.mu.Unlock()
	m.finishReload(ctx, r)
	return set, nil
}

// keySet is every leaf of the loaded material that is not revoked and whose
// period contains now with token.Leeway; Active and Signer are the current
// leaf's when it is among them. The current leaf is listed first. Caller holds
// mu.
func (m *Manager) keySet(now time.Time) token.KeySet {
	var set token.KeySet
	if m.stopped == "root_expired" {
		return set
	}
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
		if m.stopped == "" && m.cur != nil && k.KID == m.cur.thumbprint {
			set.Active, set.Signer = k, m.cur.signer
			set.Keys = append([]token.Key{k}, set.Keys...)
			continue
		}
		set.Keys = append(set.Keys, k)
	}
	return set
}

// reloadLocked is the load without reactions: Trust.Load with the manager's
// Memory, then the snapshot is swapped. changed: the trust number, the set of
// verified leaves or one leaf's revoked flag differs from the last load (never
// the first load). Reload and LoadKeys build on it; caller holds mu.
func (m *Manager) reloadLocked(ctx context.Context) (changed bool, err error) {
	mat, err := m.trust.Load(ctx, &m.mem)
	if err != nil {
		return false, err
	}
	revoked := make(map[string]bool, len(mat.Leaves))
	for _, l := range mat.Leaves {
		revoked[pki.Thumbprint(l.Verified.Leaf.Raw)] = l.Revoked
	}
	changed = m.loaded && (mat.Number != m.mat.Number || len(revoked) != len(m.revoked))
	if m.loaded {
		for tp, r := range revoked {
			if old, ok := m.revoked[tp]; !ok || old != r {
				changed = true
			}
		}
	}
	m.mat, m.revoked, m.loaded = mat, revoked, true
	b := m.trust.bundleOf(mat)
	m.bundle.Store(&b)
	m.gen++
	// No publishLocked here: the snapshot Signing reads also holds the intermediate,
	// which only reactLocked updates, so every caller publishes after its reaction
	// (reactLocked, or writeBack for a refresh alone) and a reader never sees the
	// new numbers with the old intermediate.
	return changed, nil
}

// check applies the start rules to what Pick found (the manager writes no
// matching rule of its own: Plan ruling 12).
func (t Trust) check(p Picked, mat Material) error {
	now := t.Now()
	if now.After(t.Root.NotAfter) {
		return fmt.Errorf("%w: it expired at %s", ErrRootExpired, t.Root.NotAfter.UTC().Format(time.RFC3339))
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
func (t Trust) signerFor(ctx context.Context, p Picked) (keyprovider.Signer, error) {
	var key keyprovider.Key
	if t.Provider.Name() == keyprovider.NameFile {
		k, err := t.nextKey(ctx)
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
	s, err := t.Provider.Signer(ctx, key)
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
	return m.issueLocked(ctx)
}

// issueLocked is issue for a caller that holds issueMu. A leaf it inserts while
// another process runs a rotation or revocation is not on the leaf CRL that
// process builds (the CRL lists the unexpired leaf rows it read, and the row
// lands after), and stays unrevoked: this is the spec's behavior (section 4.8
// step 5 lists the rows present when the CRL is built), and the leaf is the
// issuer's own, made after the revocation was decided (issue #44, M5).
func (m *Manager) issueLocked(ctx context.Context) error {
	m.mu.Lock()
	mat := m.mat
	m.mu.Unlock()
	pl, err := m.mintLeaf(ctx, mat)
	if err != nil {
		return err
	}
	// No trust lock: a leaf row is append-only under a random serial and does not
	// change the trust number (section 4.9: the bundle carries no leaf).
	err = m.trust.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.PutTrustCertificate(ctx, pl.row)
		return err
	})
	if err != nil {
		return core.FromStore(err)
	}
	if notify := m.adopt(pl); notify != nil {
		notify()
	}
	return nil
}

// pendingLeaf is a leaf that is signed and has passed the chain check but has no
// row yet: the intermediate it was signed under (Picked), the row to store and
// the key the manager signs with once the row is stored.
type pendingLeaf struct {
	picked Picked
	row    store.TrustCertificate
	key    *leafKey
}

// mintLeaf is the signing half of an issue, over the loaded material mat: pick
// the intermediate, an Ed25519 key in memory, pki.IssueLeaf with the
// intermediate's signer under SignTimeout and the chain check of the new leaf
// at the current time. It writes nothing and changes no state of the manager
// (RotateSigningKey stores the row inside its own transaction). Caller holds
// issueMu.
func (m *Manager) mintLeaf(ctx context.Context, mat Material) (pendingLeaf, error) {
	p, err := m.trust.Pick(ctx, mat)
	if err != nil {
		return pendingLeaf{}, err
	}
	if err := m.trust.check(p, mat); err != nil {
		return pendingLeaf{}, err
	}
	now := m.trust.Now()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return pendingLeaf{}, fmt.Errorf("signingkeys: generate the leaf key: %w", err)
	}
	signCtx, cancel := context.WithTimeout(ctx, SignTimeout)
	defer cancel()
	signer, err := m.trust.signerFor(signCtx, p)
	if err != nil {
		return pendingLeaf{}, err
	}
	if !samePublic(signer.Public(), p.Use.PublicKey) {
		m.trust.Log.Error(msgNotCertKey, "intermediate", pki.Thumbprint(p.Use.Raw))
		return pendingLeaf{}, fmt.Errorf("signingkeys: %s", msgNotCertKey)
	}
	leaf, err := pki.IssueLeaf(p.Use, CryptoSigner(signCtx, signer), pub, now, m.validity)
	if err != nil {
		return pendingLeaf{}, fmt.Errorf("signingkeys: sign the leaf: %w", err)
	}
	v, err := pki.VerifyChain([]*x509.Certificate{leaf, p.Use}, m.trust.Root, m.trust.Installation, now, token.Leeway)
	if err != nil {
		m.trust.Log.Error(msgNotCertKey, "intermediate", pki.Thumbprint(p.Use.Raw), "reason", err.Error())
		return pendingLeaf{}, fmt.Errorf("signingkeys: %s: %w", msgNotCertKey, err)
	}
	thumb := pki.Thumbprint(leaf.Raw)
	return pendingLeaf{
		picked: p,
		row: store.TrustCertificate{
			Kind: store.TrustLeaf, Thumbprint: thumb, DER: leaf.Raw, IssuerKey: keyIDOf(p.Use),
			NotAfter: leaf.NotAfter.UnixMilli(), CreatedAt: m.trust.NowMs(),
		},
		key: &leafKey{issuedAt: now, thumbprint: thumb, verified: v, signer: leafSigner{priv: priv}},
	}, nil
}

// adopt makes a minted leaf, whose row is stored, the current one and the
// former one the previous, and clears the last failed issue. It returns the
// OnChange function for the caller to run when it holds no lock of the
// manager's own that OnChange must not take (see Options.OnChange).
func (m *Manager) adopt(pl pendingLeaf) (notify func()) {
	m.mu.Lock()
	defer m.mu.Unlock()
	pl.key.gen = m.gen
	m.prev, m.cur = m.cur, pl.key
	m.failure, m.retryAt = nil, time.Time{}
	m.publishLocked()
	return m.onChange
}
