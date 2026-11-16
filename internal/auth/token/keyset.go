package token

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/ericfitz/agentmesh/internal/auth/keys"
)

// The issuer's timing constants (signing-keys plan, Task 2).
const (
	// ReloadInterval is how long the cached key set serves before the next
	// access reloads it.
	ReloadInterval = 30 * time.Second
	// UnknownKeyReloadInterval is the least time between two reloads forced by
	// a bearer whose kid is not in the cached set.
	UnknownKeyReloadInterval = 5 * time.Second
	// SignTimeout bounds one signature.
	SignTimeout = 10 * time.Second
	// LoadTimeout bounds one load of the key set (the Store read and the
	// providers' signer construction); it has the value of SignTimeout.
	LoadTimeout = SignTimeout
)

// ErrSignerUnavailable marks a Mint that could not sign: the key set has no
// usable signer, or the signer failed or timed out. Verification is not
// affected.
var ErrSignerUnavailable = errors.New("token: signing key unavailable")

// Key is one published public key of the issuer.
type Key struct {
	// KID is the RFC 7638 thumbprint of Public (keys.KID).
	// With a Chain, KID is the base64url SHA-256 of Chain[0] (the x5t#S256 value).
	KID       string
	Algorithm keys.Algorithm
	Public    crypto.PublicKey
	// Chain is the certificate chain of the leaf key, DER, the leaf first, then the intermediate. It
	// is required: validate refuses a key without one.
	Chain [][]byte
	// NotBefore and NotAfter are the period in which the chain is valid (pki.Verified); zero: unbounded.
	NotBefore, NotAfter time.Time
}

// zero reports whether k is the zero Key (an Active a verify-only set leaves unset).
func (k Key) zero() bool {
	return k.KID == "" && k.Algorithm == "" && k.Public == nil && k.Chain == nil && k.NotBefore.IsZero() && k.NotAfter.IsZero()
}

// validAt reports whether now, with Leeway, is inside the key's certificate
// period (zero bounds are open).
func (k Key) validAt(now time.Time) bool {
	if !k.NotBefore.IsZero() && now.Add(Leeway).Before(k.NotBefore) {
		return false
	}
	return k.NotAfter.IsZero() || !now.Add(-Leeway).After(k.NotAfter)
}

// thumbprintS256 is the base64url SHA-256 of a DER certificate.
func thumbprintS256(der []byte) string {
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ContextSigner signs a message under a context. Like crypto.Signer for an
// Ed25519 key, it returns the raw signature.
type ContextSigner interface {
	Public() crypto.PublicKey
	SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

// KeySet is what a KeySource reports.
type KeySet struct {
	// Active is the key Signer signs with (a keyring may report the last
	// usable retiring key here when no active key is usable).
	Active Key
	// Signer is nil when no key is usable: Mint then fails with
	// ErrSignerUnavailable while Verify and JWKS keep working. A set with a nil
	// Signer may have a zero Active, and then no keys at all (a process that can
	// sign nothing).
	Signer ContextSigner
	// Keys is every published key, Active included, in the order JWKS lists them.
	Keys []Key
}

// KeySource loads the issuer's key set.
type KeySource interface {
	LoadKeys(ctx context.Context) (KeySet, error)
}

// validate admits a key set: every key has a certificate chain, its kid is the
// thumbprint of its leaf certificate and its algorithm the key's (EdDSA),
// kids are distinct, and a non-nil Signer holds Active's key, which is one of
// Keys. A set with a nil Signer may have a zero Active and no keys.
func (s KeySet) validate() error {
	if len(s.Keys) == 0 && (s.Signer != nil || !s.Active.zero()) {
		return errors.New("token: key set has no keys")
	}
	seen := map[string]bool{}
	for _, k := range s.Keys {
		if err := checkKey(k); err != nil {
			return err
		}
		if seen[k.KID] {
			return fmt.Errorf("token: key set lists kid %q twice", k.KID)
		}
		seen[k.KID] = true
	}
	if s.Signer == nil && s.Active.zero() {
		return nil
	}
	if err := checkKey(s.Active); err != nil {
		return fmt.Errorf("active key: %w", err)
	}
	if !seen[s.Active.KID] {
		return fmt.Errorf("token: active kid %q is not in the key set", s.Active.KID)
	}
	if s.Signer != nil {
		// The thumbprint is the certificate's, so the signer is compared by key.
		if p, ok := s.Signer.Public().(ed25519.PublicKey); !ok || !p.Equal(s.Active.Public) {
			return fmt.Errorf("token: signer does not hold the active key %q", s.Active.KID)
		}
	}
	return nil
}

func checkKey(k Key) error {
	alg, err := keys.AlgorithmOf(k.Public)
	if err != nil {
		return fmt.Errorf("token: key %q: %w", k.KID, err)
	}
	if alg != k.Algorithm {
		return fmt.Errorf("token: key %q: algorithm %q, but the key is %q", k.KID, k.Algorithm, alg)
	}
	if len(k.Chain) == 0 {
		return fmt.Errorf("token: key %q has no certificate chain", k.KID)
	}
	return checkCertKey(k)
}

// checkCertKey checks a key with a chain: an Ed25519 leaf declared EdDSA whose
// certificate holds Public, with the leaf's thumbprint as KID. (The chain
// itself is checked by pki.VerifyChain, not here.)
func checkCertKey(k Key) error {
	if k.Algorithm != keys.EdDSA {
		return fmt.Errorf("token: key %q: a certificate key is EdDSA, not %q", k.KID, k.Algorithm)
	}
	cert, err := x509.ParseCertificate(k.Chain[0])
	if err != nil {
		return fmt.Errorf("token: key %q: leaf certificate: %w", k.KID, err)
	}
	certPub, ok := cert.PublicKey.(ed25519.PublicKey)
	if !ok {
		return fmt.Errorf("token: key %q: the leaf certificate key is not Ed25519", k.KID)
	}
	pub, ok := k.Public.(ed25519.PublicKey)
	if !ok || !bytes.Equal(pub, certPub) {
		return fmt.Errorf("token: key %q: the key is not the leaf certificate's", k.KID)
	}
	for n, der := range k.Chain[1:] {
		if _, err := x509.ParseCertificate(der); err != nil {
			return fmt.Errorf("token: key %q: certificate %d of the chain: %w", k.KID, n+1, err)
		}
	}
	if want := thumbprintS256(k.Chain[0]); k.KID != want {
		return fmt.Errorf("token: key %q is not its certificate thumbprint %q", k.KID, want)
	}
	return nil
}

// ctxSigner adapts a ContextSigner to the crypto.Signer go-jose's opaque
// signer needs, signing under ctx bounded by SignTimeout.
type ctxSigner struct {
	ctx context.Context //nolint:containedctx // one signature's context, built per Mint
	s   ContextSigner
}

func (c ctxSigner) Public() crypto.PublicKey { return c.s.Public() }

func (c ctxSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return c.s.SignContext(c.ctx, digest, opts)
}
