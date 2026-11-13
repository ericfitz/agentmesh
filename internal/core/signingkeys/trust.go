package signingkeys

import (
	"context"
	"crypto"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"sync"
	"time"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/keyprovider"
)

// LockName is the Store lock that serializes every change to the trust
// material (ADR 0019 section 4.5).
const LockName = "trust"

// SignTimeout bounds one use of the intermediate key (what NextTimeout is
// today).
const SignTimeout = 30 * time.Second

// LockTTL is the lease of the trust lock (Plan ruling 30).
const LockTTL = 4 * SignTimeout

// ErrCheck marks a refused install: the host command exits 2.
var ErrCheck = errors.New("signingkeys: check failed")

// Trust is the rules over the stored trust material. The host commands and the
// manager call it; it checks no caller (they are trusted or have checked
// already).
type Trust struct {
	*core.Core
	Root         *x509.Certificate
	Installation string
	// Provider is nil where nothing signs and nothing is matched against the
	// configured key (signing-key list).
	Provider keyprovider.Provider
}

// holders is the set of owner names that hold the trust lock in this process.
// Store.TryLock renews for the same owner, so the Store lock alone does not
// keep two callers of one process apart.
var holders = struct {
	sync.Mutex
	owners map[string]bool
}{owners: map[string]bool{}}

func enter(owner string) bool {
	holders.Lock()
	defer holders.Unlock()
	if holders.owners[owner] {
		return false
	}
	holders.owners[owner] = true
	return true
}

func leave(owner string) {
	holders.Lock()
	defer holders.Unlock()
	delete(holders.owners, owner)
}

func lockHeld() error {
	return core.E(bus.CodeUnavailable, "the trust lock is held by another caller; try again")
}

// withLock runs fn while this caller holds the trust lock, in this process and
// in the Store, and releases it afterwards. Held by another owner, or by
// another caller in this process: a retryable unavailable, and fn does not
// run. renew extends the lease to now+LockTTL and fails with the same error
// when the lock was lost.
func (t Trust) withLock(ctx context.Context, fn func(renew func(context.Context) error) error) error {
	owner := t.Owner
	if !enter(owner) {
		return lockHeld()
	}
	defer leave(owner)
	take := func(ctx context.Context) error {
		now := t.NowMs()
		held, err := t.Store.TryLock(ctx, LockName, owner, now, now+LockTTL.Milliseconds())
		if err != nil {
			return core.FromStore(err)
		}
		if !held {
			return lockHeld()
		}
		return nil
	}
	if err := take(ctx); err != nil {
		return err
	}
	defer func() {
		if err := t.Store.Unlock(context.WithoutCancel(ctx), LockName, owner); err != nil {
			t.Log.Warn("the trust lock was not released", "error", err.Error())
		}
	}()
	return fn(take)
}

type cryptoSigner struct {
	ctx context.Context
	s   keyprovider.Signer
}

func (c cryptoSigner) Public() crypto.PublicKey { return c.s.Public() }

func (c cryptoSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return c.s.SignContext(c.ctx, digest, opts)
}

// CryptoSigner adapts a keyprovider.Signer to crypto.Signer under ctx, for
// x509.Create*.
func CryptoSigner(ctx context.Context, s keyprovider.Signer) crypto.Signer {
	return cryptoSigner{ctx: ctx, s: s}
}

// providerError maps the key service's outage to a retryable unavailable and
// leaves every other failure as it is.
func providerError(err error) error {
	if errors.Is(err, keyprovider.ErrUnavailable) {
		return &bus.Error{Code: bus.CodeUnavailable, Message: "the signing key provider is unavailable", Retryable: true, Cause: err}
	}
	return err
}

// nextKey is Provider.Next bounded by SignTimeout.
func (t Trust) nextKey(ctx context.Context) (keyprovider.Key, error) {
	if t.Provider == nil {
		return keyprovider.Key{}, errors.New("signingkeys: no key provider is configured")
	}
	ctx, cancel := context.WithTimeout(ctx, SignTimeout)
	defer cancel()
	k, err := t.Provider.Next(ctx)
	if err != nil {
		return keyprovider.Key{}, providerError(err)
	}
	return k, nil
}

func samePublic(a, b crypto.PublicKey) bool {
	eq, ok := a.(interface{ Equal(crypto.PublicKey) bool })
	return ok && eq.Equal(b)
}

// matcher answers Configured for many certificates with at most one use of the
// provider (Decision 48).
func (t Trust) matcher(ctx context.Context) (func(cert *x509.Certificate, keyRef string) bool, error) {
	if t.Provider == nil {
		return nil, errors.New("signingkeys: no key provider is configured")
	}
	if t.Provider.Name() == keyprovider.NameFile {
		k, err := t.nextKey(ctx)
		if err != nil {
			return nil, err
		}
		return func(cert *x509.Certificate, _ string) bool { return samePublic(k.Public, cert.PublicKey) }, nil
	}
	name := t.Provider.Name()
	return func(_ *x509.Certificate, keyRef string) bool {
		if keyRef == "" {
			return false
		}
		scheme, err := keyprovider.SchemeOf(keyRef)
		return err == nil && scheme == name
	}, nil
}

// Configured reports whether a stored intermediate matches the configured key
// (Decision 48). File form (Provider.Name() is keyprovider.NameFile): the
// certificate's public key is the key file's (one Provider.Next, a file read,
// bounded by SignTimeout). Key service: keyRef is not empty and
// keyprovider.SchemeOf(keyRef) is Provider.Name(); the service is not called.
// A nil Provider is an error.
func (t Trust) Configured(ctx context.Context, cert *x509.Certificate, keyRef string) (bool, error) {
	match, err := t.matcher(ctx)
	if err != nil {
		return false, err
	}
	return match(cert, keyRef), nil
}

// Picked is the stored intermediates that match the configured key, and the
// one to sign with.
type Picked struct {
	Configured []*x509.Certificate // every one Configured accepts, in row order
	Use        *x509.Certificate   // of those valid at the core's clock, the one with the latest "not before"; nil: none
	KeyRef     string              // Use's key_ref; "" with the file form
}

// Pick is the one place that chooses the intermediate a process signs with
// (Decision 48). It reads the key file once, whatever the number of rows.
func (t Trust) Pick(ctx context.Context, m Material) (Picked, error) {
	match, err := t.matcher(ctx)
	if err != nil {
		return Picked{}, err
	}
	now := t.Now()
	var p Picked
	for _, c := range m.Intermediates {
		ref := m.KeyRefs[thumbprintOf(c)]
		if !match(c, ref) {
			continue
		}
		p.Configured = append(p.Configured, c)
		if now.Before(c.NotBefore) || now.After(c.NotAfter) {
			continue
		}
		if p.Use == nil || c.NotBefore.After(p.Use.NotBefore) {
			p.Use, p.KeyRef = c, ref
		}
	}
	return p, nil
}

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrCheck, fmt.Sprintf(format, args...))
}
