package signingkeys_test

import (
	"context"
	"crypto/x509"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/auth/token"
	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/fileacl"
	"github.com/ericfitz/agentmesh/internal/keyprovider"
	"github.com/ericfitz/agentmesh/internal/keyprovider/kmsfake"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/pki/rootca"
	"github.com/ericfitz/agentmesh/internal/store"
)

// keyServiceEnv is an env whose intermediate key sits behind a kmsfake alias: the
// certificate is installed with the reference the row pins, and "root" is an
// administrator.
func keyServiceEnv(t *testing.T) (*env, *kmsfake.Fake) {
	t.Helper()
	e := newEnv(t)
	fake := kmsfake.New("")
	e.tr.Provider = fake
	if _, err := e.tr.InstallIntermediate(context.Background(), craft(t, e.f, mustNext(t, fake).Public, nil)); err != nil {
		t.Fatal(err)
	}
	e.admin(t, "root")
	return e, fake
}

// wantCalls fails unless the fake received exactly want more calls than before.
func wantCalls(t *testing.T, fake *kmsfake.Fake, before, want int, what string) {
	t.Helper()
	if got := fake.Calls() - before; got != want {
		t.Fatalf("%s: %d key service calls, want %d", what, got, want)
	}
}

// TestKeyServiceIntermediate pins section 4.6 for the key service form: every
// signature of a leaf or of a leaf CRL is one call of the service, an outage
// follows the retry schedule and a forced renewal fails retryably without a
// change, and a leaf the pinned reference signs with another key is never used
// (Ruling 9).
func TestKeyServiceIntermediate(t *testing.T) {
	ctx := context.Background()

	t.Run("one call per signature", func(t *testing.T) {
		e, fake := keyServiceEnv(t)
		calls := fake.Calls()
		m := e.newManager(t) // the first leaf
		wantCalls(t, fake, calls, 1, "the first leaf")
		first, _ := m.Current()
		if first == "" || len(e.leafRows(t)) != 1 {
			t.Fatalf("current %q, %d rows", first, len(e.leafRows(t)))
		}

		calls = fake.Calls()
		e.at(84 * time.Hour) // W/2
		m.Step(ctx)
		wantCalls(t, fake, calls, 1, "a renewal")
		if second, _ := m.Current(); second == "" || second == first || len(e.leafRows(t)) != 2 {
			t.Fatalf("after the renewal: current %q, %d rows", second, len(e.leafRows(t)))
		}

		calls = fake.Calls()
		res, err := e.tr.Revoke(ctx, e.mem, signingkeys.RevokeInput{All: true})
		if err != nil || len(res.Revoked) != 2 {
			t.Fatalf("Revoke = %+v, %v", res, err)
		}
		wantCalls(t, fake, calls, 1, "a leaf CRL")
		var crls []store.TrustCRL
		if err := e.st.Read(ctx, func(ctx context.Context, tx store.Tx) error {
			var err error
			crls, err = tx.CRLs(ctx)
			return err
		}); err != nil {
			t.Fatal(err)
		}
		listed := 0
		for _, r := range crls {
			if r.Kind != store.TrustLeafCRL {
				continue
			}
			crl, err := pki.ParseCRL(r.DER)
			if err != nil {
				t.Fatal(err)
			}
			listed = len(crl.RevokedCertificateEntries)
		}
		if listed != 2 {
			t.Fatalf("the leaf CRL lists %d serial numbers, want 2", listed)
		}
	})

	t.Run("down at a renewal follows the retry schedule", func(t *testing.T) {
		e, fake := keyServiceEnv(t)
		m := e.newManager(t)
		first, _ := m.Current()
		failedAt := func() time.Time {
			f, ok := m.LastFailure()
			if !ok {
				return time.Time{}
			}
			return f.At
		}
		start := time.UnixMilli(startMs)

		fake.SetDown(true)
		e.at(84 * time.Hour)
		m.Step(ctx)
		if !failedAt().Equal(start.Add(84 * time.Hour)) {
			t.Fatalf("no attempt at W/2: %v", failedAt())
		}
		retry1 := 84*time.Hour + 10*time.Hour + 30*time.Minute
		e.at(retry1 - time.Second)
		m.Step(ctx)
		if !failedAt().Equal(start.Add(84 * time.Hour)) {
			t.Fatalf("an attempt before the retry time: %v", failedAt())
		}
		e.at(retry1)
		m.Step(ctx)
		if !failedAt().Equal(start.Add(retry1)) {
			t.Fatalf("no attempt at the first retry time: %v", failedAt())
		}
		if f, _ := m.LastFailure(); !strings.Contains(f.Message, "unavailable") {
			t.Fatalf("failure %q", f.Message)
		}
		if cur, _ := m.Current(); cur != first || len(e.leafRows(t)) != 1 {
			t.Fatal("a failed renewal changed the current leaf or stored a row")
		}

		fake.SetDown(false)
		retry2 := retry1 + 9*time.Hour + 11*time.Minute + 15*time.Second
		e.at(retry2 - time.Second)
		m.Step(ctx)
		if len(e.leafRows(t)) != 1 {
			t.Fatal("renewed before the retry time")
		}
		e.at(retry2)
		m.Step(ctx)
		if cur, _ := m.Current(); cur == first || len(e.leafRows(t)) != 2 {
			t.Fatalf("not recovered: current %q, %d rows", cur, len(e.leafRows(t)))
		}
		if _, ok := m.LastFailure(); ok {
			t.Fatal("the failure was not cleared by the recovery")
		}
	})

	t.Run("down during a forced renewal changes nothing", func(t *testing.T) {
		e, fake := keyServiceEnv(t)
		m := e.newManager(t)
		before := e.snap(t)
		cur, _ := m.Current()
		fake.SetDown(true)
		_, err := rotate(ctx, m, "k1")
		var be *bus.Error
		if !errors.As(err, &be) || be.Code != bus.CodeUnavailable || !be.Retryable {
			t.Fatalf("err = %v, want a retryable unavailable", err)
		}
		e.wantSnap(t, before)
		if now, _ := m.Current(); now != cur {
			t.Fatal("the failed rotation changed the current leaf")
		}
		fake.SetDown(false)
		if _, err := rotate(ctx, m, "k1"); err != nil {
			t.Fatalf("the same key after the service returned: %v", err)
		}
	})

	t.Run("a repointed alias never signs a used leaf", func(t *testing.T) {
		e, fake := keyServiceEnv(t)
		m := e.newManager(t)
		first, _ := m.Current()
		// A newer certificate of the same key, whose row pins the reference of the
		// alias's second version: the key behind that reference is not the
		// certificate's key.
		pub1 := mustNext(t, fake).Public
		later := craft(t, e.f, pub1, func(c *x509.Certificate) { c.NotBefore = e.clk.now().Add(-time.Minute) })
		e.putIntermediate(t, later, fake.Repoint().Ref)
		before := e.snap(t)

		_, err := rotate(ctx, m, "k1")
		var be *bus.Error
		if !errors.As(err, &be) || be.Code != bus.CodeUnavailable || be.Retryable {
			t.Fatalf("rotate err = %v, want a not retryable unavailable", err)
		}
		if !strings.Contains(err.Error(), "the configured key is not the certificate's key") {
			t.Fatalf("rotate err = %v", err)
		}
		e.wantSnap(t, before)

		e.at(84 * time.Hour)
		m.Step(ctx)
		if f, ok := m.LastFailure(); !ok || !strings.Contains(f.Message, "the configured key is not the certificate's key") {
			t.Fatalf("LastFailure = %+v, %v", f, ok)
		}
		if cur, _ := m.Current(); cur != first || len(e.leafRows(t)) != 1 {
			t.Fatal("a leaf signed with the wrong key was stored or became current")
		}
		if !e.logged("the configured key is not the certificate's key") {
			t.Fatalf("not logged:\n%s", e.logs.String())
		}
	})
}

// TestKeyChange is section 4.4 in the file form: a second key for the same
// installation name, signed with sameInstallation and installed, runs beside the
// first; each process accepts the other's bearers until the old key is revoked
// with the root tool and the root CRL installed.
func TestKeyChange(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	e.admin(t, "root")
	now := e.clk.now()

	// The second key: a file, a request for the same name, the root tool's
	// sameInstallation flag.
	keyFile := filepath.Join(e.f.Dir, "second.key")
	if err := keyprovider.CreateKeyFile(keyFile, fileacl.OwnerOnly); err != nil {
		t.Fatal(err)
	}
	der, err := pki.NewRequest(parsePEMKey(t, keyFile), e.f.Installation)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := rootca.Sign(e.f.Dir, csr, 365, false, now.Add(-time.Hour)); err == nil {
		t.Fatal("a second key for a taken name was signed without sameInstallation")
	}
	second, err := rootca.Sign(e.f.Dir, csr, 365, true, now.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c2 := e.coreOver(t, e.st)
	tr2 := e.tr
	tr2.Core = c2
	tr2.Provider = keyprovider.FileProvider{Path: keyFile, Read: os.ReadFile}
	if changed, err := tr2.InstallIntermediate(ctx, second); err != nil || !changed {
		t.Fatalf("install of the second key: %v, %v", changed, err)
	}
	if n := len(e.rows(t, store.TrustIntermediate)); n != 2 {
		t.Fatalf("%d intermediates stored, want 2", n)
	}

	oldM := e.newManager(t)
	newM, err := signingkeys.New(ctx, signingkeys.Options{Trust: tr2, LeafValidity: week})
	if err != nil {
		t.Fatal(err)
	}
	oldTP, _ := oldM.Current()
	newTP, _ := newM.Current()
	if oldTP == newTP || len(e.leafRows(t)) != 2 {
		t.Fatalf("leaves %q and %q, %d rows", oldTP, newTP, len(e.leafRows(t)))
	}
	oldIss, newIss := e.issuer(t, oldM), e.issuer(t, newM)
	mint := func(iss *token.Issuer) string {
		raw, _, err := iss.Mint(ctx, token.MintInput{Identity: "alice", Kind: token.KindAgent})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	fromOld, fromNew := mint(oldIss), mint(newIss)
	accepted(t, newIss, fromOld, e.clk.now())
	accepted(t, oldIss, fromNew, e.clk.now())

	// A forced renewal on the new key: the old key's leaf is not covered, so it is
	// reported (logged) and neither revoked nor listed.
	res, err := rotate(ctx, newM, "k1")
	if err != nil {
		t.Fatal(err)
	}
	if thumbs(res.Revoked)[oldTP] || !thumbs(res.Revoked)[newTP] {
		t.Fatalf("revoked %v: the old key's leaf must stay, the new key's former leaf must go", res.Revoked)
	}
	if !e.logged(oldTP) || !e.logged("not covered") {
		t.Fatalf("the old key's leaf was not reported as not covered:\n%s", e.logs.String())
	}
	accepted(t, newIss, fromOld, e.clk.now())

	// Revoke the old key with the root tool and install the root CRL: its leaves
	// are cut off, the new key's stay.
	crlDER, _, err := rootca.Revoke(e.f.Dir, e.f.Intermediate, now)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := pki.ParseCRL(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	if changed, err := tr2.InstallRootCRL(ctx, crl); err != nil || !changed {
		t.Fatalf("InstallRootCRL: %v, %v", changed, err)
	}
	// A process reloads at its next periodic reload.
	e.clk.advance(token.ReloadInterval + time.Second)
	unknownKey(t, newIss, fromOld, e.clk.now())
	newCur, _ := newM.Current()
	if newCur == "" {
		t.Fatal("the new key's manager lost its leaf")
	}
	accepted(t, newIss, mint(newIss), e.clk.now())
	oldM.Step(ctx)
	_ = refused(t, oldIss, fromOld, e.clk.now())
}
