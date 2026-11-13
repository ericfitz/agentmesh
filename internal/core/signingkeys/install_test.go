package signingkeys_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/keyprovider/kmsfake"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
	"github.com/ericfitz/agentmesh/internal/trusttest"
)

func TestInstallIntermediate(t *testing.T) {
	ctx := context.Background()
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	type tc struct {
		name  string
		cert  func(t *testing.T, e *env) *x509.Certificate
		is    error  // the pki error that stays reachable; nil for the checks of install.go
		text  string // the message, as a substring
		setup func(t *testing.T, e *env)
	}
	own := func(e *env) *ecdsa.PublicKey { return interKey(t, e.f).Public().(*ecdsa.PublicKey) }
	cases := []tc{
		// The seven of pki.CheckIntermediate, with Task 3's texts.
		{name: "not-the-pinned-root", is: pki.ErrChainSignature, text: "does not chain to the pinned root",
			cert: func(t *testing.T, e *env) *x509.Certificate { return trusttest.New(t, e.clk.now()).Intermediate }},
		{name: "path-length", is: pki.ErrIntermediateProfile, text: "is not a CA with path length 0",
			cert: func(t *testing.T, e *env) *x509.Certificate {
				return craft(t, e.f, own(e), func(c *x509.Certificate) { c.MaxPathLen = 1; c.MaxPathLenZero = false })
			}},
		{name: "crl-usage", is: pki.ErrIntermediateProfile, text: "lacks the certificate signing or the CRL signing usage",
			cert: func(t *testing.T, e *env) *x509.Certificate {
				return craft(t, e.f, own(e), func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCertSign })
			}},
		{name: "no-ski", is: pki.ErrIntermediateProfile, text: "has no subject key identifier",
			cert: func(t *testing.T, e *env) *x509.Certificate { return craft(t, e.f, own(e), emptySKI) }},
		{name: "not-p256", is: pki.ErrIntermediateProfile, text: "its key is not ECDSA P-256",
			cert: func(t *testing.T, e *env) *x509.Certificate { return craft(t, e.f, p384.Public(), nil) }},
		{name: "installation", is: pki.ErrInstallation, text: `names installation "other", expected "test-installation"`,
			cert: func(t *testing.T, e *env) *x509.Certificate {
				return craft(t, e.f, own(e), func(c *x509.Certificate) { c.Subject.CommonName = "other" })
			}},
		{name: "extended-key-usage", is: pki.ErrExtKeyUsage, text: "lacks the agentmesh extended key usage",
			cert: func(t *testing.T, e *env) *x509.Certificate {
				return craft(t, e.f, own(e), func(c *x509.Certificate) { c.UnknownExtKeyUsage = nil })
			}},
		// The four of install.go.
		{name: "not-yet-valid", text: "is not valid now",
			cert: func(t *testing.T, e *env) *x509.Certificate { return e.f.Renew(t, e.clk.now().Add(time.Hour), 30) }},
		{name: "expired", text: "is not valid now",
			cert: func(t *testing.T, e *env) *x509.Certificate {
				return craft(t, e.f, own(e), func(c *x509.Certificate) { c.NotAfter = e.clk.now().Add(-time.Minute) })
			}},
		{name: "not-the-configured-key", text: "its public key is not the configured intermediate key",
			cert: func(t *testing.T, e *env) *x509.Certificate { return craft(t, e.f, newP256(t).Public(), nil) }},
		{name: "ski-differs", text: "its subject key identifier differs from the stored certificates of the same key",
			setup: func(t *testing.T, e *env) { e.f.Install(t, e.c) },
			cert: func(t *testing.T, e *env) *x509.Certificate {
				return craft(t, e.f, own(e), func(c *x509.Certificate) { c.SubjectKeyId = []byte("0123456789abcdefghij") })
			}},
		{name: "key-revoked", text: "its key is revoked by the stored root CRL",
			setup: func(t *testing.T, e *env) {
				e.f.Install(t, e.c)
				if _, err := e.tr.InstallRootCRL(ctx, e.f.RevokeIntermediate(t, e.clk.now())); err != nil {
					t.Fatal(err)
				}
			},
			cert: func(t *testing.T, e *env) *x509.Certificate { return e.f.Renew(t, e.clk.now(), 30) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			if c.setup != nil {
				c.setup(t, e)
			}
			before, nrows := e.trustNumber(t), len(e.rows(t, store.TrustIntermediate))
			changed, err := e.tr.InstallIntermediate(ctx, c.cert(t, e))
			if changed {
				t.Fatal("changed is true on a refusal")
			}
			wantCheck(t, err, c.text)
			if c.is != nil && !errors.Is(err, c.is) {
				t.Fatalf("err = %v, want it to wrap %v", err, c.is)
			}
			if e.trustNumber(t) != before || len(e.rows(t, store.TrustIntermediate)) != nrows {
				t.Fatal("a refused install changed the store")
			}
		})
	}

	t.Run("nil-certificate", func(t *testing.T) {
		e := newEnv(t)
		if _, err := e.tr.InstallIntermediate(ctx, nil); err == nil {
			t.Fatal("nil certificate accepted")
		}
	})

	t.Run("good", func(t *testing.T) {
		e := newEnv(t)
		changed, err := e.tr.InstallIntermediate(ctx, e.f.Intermediate)
		if err != nil || !changed {
			t.Fatalf("%v, %v", changed, err)
		}
		rows := e.rows(t, store.TrustIntermediate)
		if len(rows) != 1 || rows[0].Thumbprint != pki.Thumbprint(e.f.Intermediate.Raw) || rows[0].KeyRef != "" ||
			rows[0].NotAfter != e.f.Intermediate.NotAfter.UnixMilli() {
			t.Fatalf("rows = %+v", rows)
		}
		n := e.trustNumber(t)
		if n < e.nowMs() {
			t.Fatalf("trust number %d, want at least the clock %d", n, e.nowMs())
		}
		changed, err = e.tr.InstallIntermediate(ctx, e.f.Intermediate)
		if err != nil || changed {
			t.Fatalf("again: %v, %v", changed, err)
		}
		if e.trustNumber(t) != n || len(e.rows(t, store.TrustIntermediate)) != 1 {
			t.Fatal("the second install changed the store")
		}
	})

	t.Run("renewal-of-the-same-key", func(t *testing.T) {
		e := newEnv(t)
		e.f.Install(t, e.c)
		changed, err := e.tr.InstallIntermediate(ctx, e.f.Renew(t, e.clk.now(), 30))
		if err != nil || !changed || len(e.rows(t, store.TrustIntermediate)) != 2 {
			t.Fatalf("%v, %v", changed, err)
		}
	})

	t.Run("two-at-once", func(t *testing.T) {
		e := newEnv(t)
		var wg sync.WaitGroup
		type result struct {
			changed bool
			err     error
		}
		res := make([]result, 2)
		for i := range res {
			wg.Add(1)
			go func() {
				defer wg.Done()
				res[i].changed, res[i].err = e.tr.InstallIntermediate(ctx, e.f.Intermediate)
			}()
		}
		wg.Wait()
		installed := 0
		for _, r := range res {
			if r.err != nil {
				wantUnavailable(t, r.err)
			} else if r.changed {
				installed++
			}
		}
		if installed != 1 {
			t.Fatalf("%d calls installed, want 1 (%+v)", installed, res)
		}
		if n := len(e.rows(t, store.TrustIntermediate)); n != 1 {
			t.Fatalf("rows = %d", n)
		}
	})
}

func TestInstallIntermediateKeyService(t *testing.T) {
	e := newEnv(t)
	fake := kmsfake.New("")
	e.tr.Provider = fake
	key := mustNext(t, fake)
	cert := craft(t, e.f, key.Public, nil)
	changed, err := e.tr.InstallIntermediate(context.Background(), cert)
	if err != nil || !changed {
		t.Fatalf("%v, %v", changed, err)
	}
	rows := e.rows(t, store.TrustIntermediate)
	if len(rows) != 1 || rows[0].KeyRef != key.Ref || key.Ref == "" {
		t.Fatalf("rows = %+v, want key_ref %q", rows, key.Ref)
	}
	other := craft(t, e.f, newP256(t).Public(), nil)
	if _, err := e.tr.InstallIntermediate(context.Background(), other); err == nil {
		t.Fatal("a certificate of another key was installed")
	}
}

func TestInstallRootCRL(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	now := e.clk.now()
	crl := e.f.RevokeIntermediate(t, now)
	n := pki.CRLNumber(crl)

	changed, err := e.tr.InstallRootCRL(ctx, crl)
	if err != nil || !changed {
		t.Fatalf("%v, %v", changed, err)
	}
	num := e.trustNumber(t)
	if num == 0 {
		t.Fatal("the trust number was not raised")
	}
	if changed, err = e.tr.InstallRootCRL(ctx, crl); err != nil || changed {
		t.Fatalf("again: %v, %v", changed, err)
	}
	if e.trustNumber(t) != num {
		t.Fatal("an unchanged install raised the trust number")
	}

	lower, err := pki.ParseCRL(crlBy(t, e.f.Root, rootKey(t, e.f), n-1, now))
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.tr.InstallRootCRL(ctx, lower)
	wantCheck(t, err, "is not above the stored")
	same, err := pki.ParseCRL(crlBy(t, e.f.Root, rootKey(t, e.f), n, now))
	if err != nil {
		t.Fatal(err)
	}
	_, err = e.tr.InstallRootCRL(ctx, same)
	wantCheck(t, err, "is not above the stored")
	foreign := trusttest.New(t, now).RevokeIntermediate(t, now)
	_, err = e.tr.InstallRootCRL(ctx, foreign)
	wantCheck(t, err, "is not signed by the pinned root")
	higher, err := pki.ParseCRL(crlBy(t, e.f.Root, rootKey(t, e.f), n+5, now))
	if err != nil {
		t.Fatal(err)
	}
	if changed, err = e.tr.InstallRootCRL(ctx, higher); err != nil || !changed {
		t.Fatalf("higher: %v, %v", changed, err)
	}
	if e.trustNumber(t) <= num {
		t.Fatal("the trust number did not rise")
	}
}

func TestTrustLockHeld(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	other := openAt(t, e.path)
	lease := signingkeys.LockTTL.Milliseconds()
	held, err := other.TryLock(ctx, signingkeys.LockName, "another-process", e.nowMs(), e.nowMs()+lease)
	if err != nil || !held {
		t.Fatalf("the second handle did not take the lock: %v, %v", held, err)
	}
	crl := e.f.RevokeIntermediate(t, e.clk.now())

	if changed, err := e.tr.InstallIntermediate(ctx, e.f.Intermediate); changed {
		t.Fatal("changed while the lock was held")
	} else {
		wantUnavailable(t, err)
	}
	if changed, err := e.tr.InstallRootCRL(ctx, crl); changed {
		t.Fatal("changed while the lock was held")
	} else {
		wantUnavailable(t, err)
	}
	if n := len(e.rows(t, store.TrustIntermediate)); n != 0 || e.trustNumber(t) != 0 {
		t.Fatalf("stored %d rows, number %d", n, e.trustNumber(t))
	}

	// A killed holder leaves a lease that ends by the clock.
	e.clk.advance(signingkeys.LockTTL + time.Second)
	if changed, err := e.tr.InstallIntermediate(ctx, e.f.Intermediate); err != nil || !changed {
		t.Fatalf("after the lease: %v, %v", changed, err)
	}
	if changed, err := e.tr.InstallRootCRL(ctx, crl); err != nil || !changed {
		t.Fatalf("root CRL after the lease: %v, %v", changed, err)
	}
	// The lock is released after each install.
	held, err = other.TryLock(ctx, signingkeys.LockName, "another-process", e.nowMs(), e.nowMs()+lease)
	if err != nil || !held {
		t.Fatalf("the trust lock was not released: %v, %v", held, err)
	}
}
