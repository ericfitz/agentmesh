package signingkeys_test

import (
	"context"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
	"github.com/ericfitz/agentmesh/internal/trusttest"
)

func TestLoadVerifiesRows(t *testing.T) {
	type bad struct {
		kind, thumb string
	}
	garbage := []byte("garbage")
	cases := []struct {
		name  string
		setup func(t *testing.T, e *env) bad
	}{
		{"intermediate-of-another-root", func(t *testing.T, e *env) bad {
			c := trusttest.New(t, e.clk.now()).Intermediate
			e.putIntermediate(t, c, "")
			return bad{store.TrustIntermediate, pki.Thumbprint(c.Raw)}
		}},
		{"intermediate-of-another-installation", func(t *testing.T, e *env) bad {
			c := e.f.Sibling(t, "other-installation").Intermediate
			e.putIntermediate(t, c, "")
			return bad{store.TrustIntermediate, pki.Thumbprint(c.Raw)}
		}},
		{"intermediate-without-the-usage", func(t *testing.T, e *env) bad {
			c := craft(t, e.f, newP256(t).Public(), func(c *x509.Certificate) { c.UnknownExtKeyUsage = nil })
			e.putIntermediate(t, c, "")
			return bad{store.TrustIntermediate, pki.Thumbprint(c.Raw)}
		}},
		{"thumbprint-column-is-not-the-ders", func(t *testing.T, e *env) bad {
			e.putRow(t, store.TrustCertificate{Kind: store.TrustIntermediate, Thumbprint: "wrong-thumbprint", DER: e.f.Intermediate.Raw})
			return bad{store.TrustIntermediate, "wrong-thumbprint"}
		}},
		{"garbage-intermediate", func(t *testing.T, e *env) bad {
			e.putRow(t, store.TrustCertificate{Kind: store.TrustIntermediate, Thumbprint: pki.Thumbprint(garbage), DER: garbage})
			return bad{store.TrustIntermediate, pki.Thumbprint(garbage)}
		}},
		{"garbage-leaf", func(t *testing.T, e *env) bad {
			e.f.Install(t, e.c)
			e.putRow(t, store.TrustCertificate{Kind: store.TrustLeaf, Thumbprint: pki.Thumbprint(garbage), DER: garbage, IssuerKey: keyID(e.f.Intermediate)})
			return bad{store.TrustLeaf, pki.Thumbprint(garbage)}
		}},
		{"garbage-root-crl", func(t *testing.T, e *env) bad {
			e.tx(t, func(ctx context.Context, tx store.Tx) error {
				return tx.PutCRL(ctx, store.TrustCRL{Kind: store.TrustRootCRL, Thumbprint: pki.Thumbprint(garbage), DER: garbage, Number: 5, CreatedAt: e.nowMs()})
			})
			return bad{store.TrustRootCRL, pki.Thumbprint(garbage)}
		}},
		{"garbage-leaf-crl", func(t *testing.T, e *env) bad {
			e.f.Install(t, e.c)
			e.tx(t, func(ctx context.Context, tx store.Tx) error {
				return tx.PutCRL(ctx, store.TrustCRL{Kind: store.TrustLeafCRL, Thumbprint: pki.Thumbprint(garbage), DER: garbage, IssuerKey: keyID(e.f.Intermediate), Number: 5, CreatedAt: e.nowMs()})
			})
			return bad{store.TrustLeafCRL, pki.Thumbprint(garbage)}
		}},
		{"self-signed-leaf", func(t *testing.T, e *env) bad {
			e.f.Install(t, e.c)
			k := newP256(t)
			ski, _ := pki.SubjectKeyID(k.Public())
			tmpl := &x509.Certificate{
				SerialNumber:          randSerial(t),
				Subject:               pkix.Name{CommonName: "agentmesh leaf"},
				NotBefore:             e.clk.now().Add(-time.Minute),
				NotAfter:              e.clk.now().Add(time.Hour),
				KeyUsage:              x509.KeyUsageDigitalSignature,
				UnknownExtKeyUsage:    []asn1.ObjectIdentifier{pki.ExtKeyUsageAgentmesh},
				BasicConstraintsValid: true,
				SubjectKeyId:          ski,
				AuthorityKeyId:        e.f.Intermediate.SubjectKeyId,
			}
			der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, k.Public(), k)
			if err != nil {
				t.Fatal(err)
			}
			c, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			e.putLeaf(t, c, keyID(e.f.Intermediate))
			return bad{store.TrustLeaf, pki.Thumbprint(c.Raw)}
		}},
		{"leaf-under-an-ignored-intermediate", func(t *testing.T, e *env) bad {
			e.f.Install(t, e.c)
			sib := e.f.Sibling(t, "other-installation")
			e.putIntermediate(t, sib.Intermediate, "")
			leaf := leafUnder(t, sib.Intermediate, interKey(t, sib), e.clk.now(), time.Hour)
			e.putLeaf(t, leaf, keyID(sib.Intermediate))
			return bad{store.TrustLeaf, pki.Thumbprint(leaf.Raw)}
		}},
		{"leaf-one-second-over-the-ceiling", func(t *testing.T, e *env) bad {
			e.f.Install(t, e.c)
			leaf := overlongLeaf(t, e.f, e.clk.now(), pki.MaxLeafLifetime+time.Second)
			e.putLeaf(t, leaf, keyID(e.f.Intermediate))
			return bad{store.TrustLeaf, pki.Thumbprint(leaf.Raw)}
		}},
		{"leaf-crl-signed-by-another-key", func(t *testing.T, e *env) bad {
			e.f.Install(t, e.c)
			der := crlBy(t, e.f.Intermediate, newP256(t), 10, e.clk.now(), big.NewInt(7))
			e.putCRL(t, store.TrustLeafCRL, keyID(e.f.Intermediate), der)
			return bad{store.TrustLeafCRL, pki.Thumbprint(der)}
		}},
		{"root-crl-signed-by-another-root", func(t *testing.T, e *env) bad {
			other := trusttest.New(t, e.clk.now())
			crl := other.RevokeIntermediate(t, e.clk.now())
			e.putCRL(t, store.TrustRootCRL, "", crl.Raw)
			return bad{store.TrustRootCRL, pki.Thumbprint(crl.Raw)}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newEnv(t)
			b := c.setup(t, e)
			m := e.load(t)
			for _, x := range m.Intermediates {
				if pki.Thumbprint(x.Raw) == b.thumb {
					t.Fatal("the row is in Intermediates")
				}
			}
			for _, l := range m.Leaves {
				if pki.Thumbprint(l.Verified.Leaf.Raw) == b.thumb {
					t.Fatal("the row is in Leaves")
				}
			}
			switch b.kind {
			case store.TrustRootCRL:
				if m.RootCRL != nil {
					t.Fatal("RootCRL is set")
				}
			case store.TrustLeafCRL:
				if len(m.LeafCRLs) != 0 {
					t.Fatalf("LeafCRLs = %d", len(m.LeafCRLs))
				}
			}
			if !e.logged(b.thumb) {
				t.Fatalf("the log does not name %s:\n%s", b.thumb, e.logs.String())
			}
			if !e.logged(b.kind) {
				t.Fatalf("the log does not name the kind %s:\n%s", b.kind, e.logs.String())
			}
			e.load(t)
			if n := countOf(e.logs.String(), b.thumb); n != 1 {
				t.Fatalf("the thumbprint is logged %d times over two loads, want once", n)
			}
		})
	}
}

func countOf(s, sub string) int {
	n := 0
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			n++
		}
	}
	return n
}

func TestLoadKeepsExpired(t *testing.T) {
	start := time.UnixMilli(startMs)
	clk := &clock{t: start}
	f := trusttest.New(t, start.Add(-100*24*time.Hour))
	e := newEnvWith(t, clk, f)
	f.Install(t, e.c)

	t.Run("expired-intermediate", func(t *testing.T) {
		old := craft(t, f, interKey(t, f).Public(), func(c *x509.Certificate) {
			c.NotBefore = start.Add(-100 * 24 * time.Hour)
			c.NotAfter = start.Add(-50 * 24 * time.Hour)
		})
		e.putIntermediate(t, old, "")
		m := e.load(t)
		if !hasIntermediate(m, old) {
			t.Fatal("an expired intermediate was dropped")
		}
		if e.logged(pki.Thumbprint(old.Raw)) {
			t.Fatal("an expired intermediate was logged as ignored")
		}
	})
	t.Run("expired-leaf", func(t *testing.T) {
		leaf := leafFor(t, f, f.Now, time.Hour) // issued 100 days ago, valid for an hour
		e.putLeaf(t, leaf, keyID(f.Intermediate))
		m := e.load(t)
		if !hasLeaf(m, leaf) {
			t.Fatal("an expired leaf was dropped")
		}
		for _, l := range m.Leaves {
			if l.Verified.NotAfter.After(start) {
				t.Fatalf("leaf period ends %s, want the past", l.Verified.NotAfter)
			}
		}
	})
}

func TestLoadRevocationByKey(t *testing.T) {
	e := newEnv(t)
	e.f.Install(t, e.c)
	now := e.clk.now()
	second := e.f.Renew(t, now, 365)
	if _, err := e.tr.InstallIntermediate(context.Background(), second); err != nil {
		t.Fatal(err)
	}
	l1 := leafFor(t, e.f, now, time.Hour)
	l2 := leafFor(t, e.f, now, 2*time.Hour)
	e.putLeaf(t, l1, keyID(e.f.Intermediate))
	e.putLeaf(t, l2, keyID(e.f.Intermediate))
	// The root CRL lists only the first certificate; the key is revoked with it.
	der := crlBy(t, e.f.Root, rootKey(t, e.f), pki.NextNumber(now, 0), now, e.f.Intermediate.SerialNumber)
	crl, err := pki.ParseCRL(der)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.tr.InstallRootCRL(context.Background(), crl); err != nil {
		t.Fatal(err)
	}
	m := e.load(t)
	if len(m.Leaves) != 2 {
		t.Fatalf("leaves = %d, want 2", len(m.Leaves))
	}
	for _, l := range m.Leaves {
		if !l.Revoked {
			t.Fatalf("leaf %d is not revoked", l.ID)
		}
	}
	if !m.RevokedKeys[keyID(e.f.Intermediate)] {
		t.Fatal("the key is not in RevokedKeys")
	}
	if m.RootCRL == nil {
		t.Fatal("RootCRL is nil")
	}
}

func TestLoadUnion(t *testing.T) {
	e := newEnv(t)
	e.f.Install(t, e.c)
	now := e.clk.now()
	key := interKey(t, e.f)
	leaf := leafFor(t, e.f, now, time.Hour)
	e.putLeaf(t, leaf, keyID(e.f.Intermediate))
	e.putCRL(t, store.TrustLeafCRL, keyID(e.f.Intermediate), crlBy(t, e.f.Intermediate, key, 1000, now, leaf.SerialNumber))
	m := e.load(t)
	if len(m.Leaves) != 1 || !m.Leaves[0].Revoked {
		t.Fatalf("first load: %+v", m.Leaves)
	}
	// A higher number replaces the row and lists nothing.
	e.putCRL(t, store.TrustLeafCRL, keyID(e.f.Intermediate), crlBy(t, e.f.Intermediate, key, 2000, now))
	m = e.load(t)
	if len(m.Leaves) != 1 || !m.Leaves[0].Revoked {
		t.Fatalf("the revocation was forgotten: %+v", m.Leaves)
	}
	if len(m.Rollback) != 0 {
		t.Fatalf("rollback = %d, want 0", len(m.Rollback))
	}
}

func TestLoadRollback(t *testing.T) {
	a := newEnv(t)
	b := a.second(t)
	now := a.clk.now()
	key := interKey(t, a.f)
	leaf := leafFor(t, a.f, now, time.Hour)
	issuer := keyID(a.f.Intermediate)
	for _, e := range []*env{a, b} {
		e.f.Install(t, e.c)
		e.putLeaf(t, leaf, issuer)
	}
	newer := crlBy(t, a.f.Intermediate, key, 2000, now, leaf.SerialNumber)
	a.putCRL(t, store.TrustLeafCRL, issuer, newer)
	b.putCRL(t, store.TrustLeafCRL, issuer, crlBy(t, a.f.Intermediate, key, 1000, now))

	if m := a.load(t); !m.Leaves[0].Revoked || len(m.Rollback) != 0 {
		t.Fatalf("first load: %+v rollback %d", m.Leaves, len(m.Rollback))
	}
	m := b.load(t)
	if !m.Leaves[0].Revoked {
		t.Fatal("the entry stopped being revoked after the rollback")
	}
	if len(m.Rollback) != 1 || m.Rollback[0].Number != 2000 || m.Rollback[0].Kind != store.TrustLeafCRL ||
		m.Rollback[0].IssuerKey != issuer || string(m.Rollback[0].DER) != string(newer) {
		t.Fatalf("Rollback = %+v", m.Rollback)
	}
	if !b.logged("rollback") {
		t.Fatalf("the log does not say rollback:\n%s", b.logs.String())
	}
}

func TestLoadCachesVerification(t *testing.T) {
	e := newEnv(t)
	e.f.Install(t, e.c)
	for i := 0; i < 3; i++ {
		e.putLeaf(t, leafFor(t, e.f, e.clk.now(), time.Hour), keyID(e.f.Intermediate))
	}
	calls := 0
	signingkeys.SetChainCheckHook(func() { calls++ })
	t.Cleanup(func() { signingkeys.SetChainCheckHook(nil) })
	m := e.load(t)
	if len(m.Leaves) != 3 || calls != 3 {
		t.Fatalf("first load: %d leaves, %d chain checks, want 3 and 3", len(m.Leaves), calls)
	}
	e.load(t)
	if calls != 3 {
		t.Fatalf("second load made %d more chain checks, want none", calls-3)
	}
	e.putLeaf(t, leafFor(t, e.f, e.clk.now(), time.Hour), keyID(e.f.Intermediate))
	e.load(t)
	if calls != 4 {
		t.Fatalf("a new leaf cost %d chain checks, want 1", calls-3)
	}
}

func TestLoadNumberAndStoreFailure(t *testing.T) {
	e := newEnv(t)
	e.f.Install(t, e.c)
	m := e.load(t)
	if m.Number == 0 || m.Number != e.trustNumber(t) {
		t.Fatalf("Number = %d, stored %d", m.Number, e.trustNumber(t))
	}
	if len(m.KeyRefs) != 1 {
		t.Fatalf("KeyRefs = %v", m.KeyRefs)
	}
	if err := e.st.Close(); err != nil {
		t.Fatal(err)
	}
	_, err := e.tr.Load(context.Background(), e.mem)
	if err == nil {
		t.Fatal("Load over a closed store succeeded")
	}
	// A closed Store is the Store's retryable "unavailable", never an internal error.
	if got := bus.CodeOf(err); got != bus.CodeUnavailable {
		t.Fatalf("code = %q (%v), want %q", got, err, bus.CodeUnavailable)
	}
}

// A leaf CRL whose row is stored but ignored (its issuer key is now revoked) is
// not a rollback.
func TestLoadRevokedIssuerIsNotRollback(t *testing.T) {
	e := newEnv(t)
	e.f.Install(t, e.c)
	now := e.clk.now()
	leaf := leafFor(t, e.f, now, time.Hour)
	e.putLeaf(t, leaf, keyID(e.f.Intermediate))
	e.putCRL(t, store.TrustLeafCRL, keyID(e.f.Intermediate), crlBy(t, e.f.Intermediate, interKey(t, e.f), 1000, now, leaf.SerialNumber))
	if m := e.load(t); len(m.Rollback) != 0 {
		t.Fatalf("first load: rollback %d", len(m.Rollback))
	}
	if _, err := e.tr.InstallRootCRL(context.Background(), e.f.RevokeIntermediate(t, now)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		m := e.load(t)
		if len(m.Rollback) != 0 {
			t.Fatalf("load %d after the revocation: Rollback = %+v", i, m.Rollback)
		}
		if len(m.Leaves) != 1 || !m.Leaves[0].Revoked {
			t.Fatalf("leaf: %+v", m.Leaves)
		}
	}
}

// A CRL this process holds whose stored row is gone is reported, for the root
// CRL and for a leaf CRL.
func TestLoadMissingRowIsRollback(t *testing.T) {
	setup := func(t *testing.T) (a *env, leaf *x509.Certificate, rootDER, leafDER []byte) {
		a = newEnv(t)
		a.f.Install(t, a.c)
		now := a.clk.now()
		leaf = leafFor(t, a.f, now, time.Hour)
		a.putLeaf(t, leaf, keyID(a.f.Intermediate))
		rootDER = crlBy(t, a.f.Root, rootKey(t, a.f), 3000, now, big.NewInt(99))
		leafDER = crlBy(t, a.f.Intermediate, interKey(t, a.f), 2000, now, leaf.SerialNumber)
		a.putCRL(t, store.TrustRootCRL, "", rootDER)
		a.putCRL(t, store.TrustLeafCRL, keyID(a.f.Intermediate), leafDER)
		if m := a.load(t); len(m.Rollback) != 0 || m.RootCRL == nil || len(m.LeafCRLs) != 1 {
			t.Fatalf("first load: %+v", m.Rollback)
		}
		return
	}
	t.Run("both", func(t *testing.T) {
		a, leaf, rootDER, leafDER := setup(t)
		b := a.second(t)
		b.f.Install(t, b.c)
		b.putLeaf(t, leaf, keyID(b.f.Intermediate))
		m := b.load(t)
		if len(m.Rollback) != 2 {
			t.Fatalf("Rollback = %+v", m.Rollback)
		}
		// Sorted by kind: the leaf CRL, then the root CRL.
		lc, rc := m.Rollback[0], m.Rollback[1]
		if lc.Kind != store.TrustLeafCRL || lc.Number != 2000 || string(lc.DER) != string(leafDER) || lc.IssuerKey != keyID(b.f.Intermediate) {
			t.Fatalf("leaf rollback = %+v", lc)
		}
		if rc.Kind != store.TrustRootCRL || rc.Number != 3000 || string(rc.DER) != string(rootDER) {
			t.Fatalf("root rollback = %+v", rc)
		}
		if m.RootCRL == nil || pki.CRLNumber(m.RootCRL) != 3000 || m.LeafCRLs[keyID(b.f.Intermediate)] == nil {
			t.Fatalf("held CRLs are not carried: root %v leaf %v", m.RootCRL, m.LeafCRLs)
		}
		if len(m.Leaves) != 1 || !m.Leaves[0].Revoked {
			t.Fatalf("leaf: %+v", m.Leaves)
		}
		if !b.logged("no longer stored") {
			t.Fatalf("the log does not say \"no longer stored\":\n%s", b.logs.String())
		}
	})
	t.Run("leaf-guard-no-kept-intermediate", func(t *testing.T) {
		a, _, _, _ := setup(t)
		b := a.second(t) // no intermediate stored
		m := b.load(t)
		if len(m.LeafCRLs) != 0 {
			t.Fatalf("a leaf CRL of an issuer with no kept intermediate was reported: %v", m.LeafCRLs)
		}
		if len(m.Rollback) != 1 || m.Rollback[0].Kind != store.TrustRootCRL {
			t.Fatalf("Rollback = %+v, want the root CRL alone", m.Rollback)
		}
	})
}

// failingStore fails the calls the trust rules make with a retryable error.
type failingStore struct {
	store.Store
	tryLock, tx, read bool
}

func (f failingStore) fail() error { return fmt.Errorf("injected: %w", store.ErrRetryable) }

func (f failingStore) TryLock(ctx context.Context, name, owner string, now, until int64) (bool, error) {
	if f.tryLock {
		return false, f.fail()
	}
	return f.Store.TryLock(ctx, name, owner, now, until)
}

func (f failingStore) Tx(ctx context.Context, fn func(context.Context, store.Tx) error) error {
	if f.tx {
		return f.fail()
	}
	return f.Store.Tx(ctx, fn)
}

func (f failingStore) Read(ctx context.Context, fn func(context.Context, store.Tx) error) error {
	if f.read {
		return f.fail()
	}
	return f.Store.Read(ctx, fn)
}

func TestRetryableStoreErrorIsUnavailable(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	for name, fs := range map[string]failingStore{
		"lock":        {Store: e.st, tryLock: true},
		"transaction": {Store: e.st, tx: true},
		"read":        {Store: e.st, read: true},
	} {
		t.Run(name, func(t *testing.T) {
			c, err := core.New(fs, core.Defaults(), core.Options{Now: e.clk.now})
			if err != nil {
				t.Fatal(err)
			}
			tr := e.f.Trust(c)
			if name == "read" {
				_, err = tr.Load(ctx, &signingkeys.Memory{})
			} else {
				_, err = tr.InstallIntermediate(ctx, e.f.Intermediate)
				if err == nil {
					t.Fatal("no error")
				}
				if _, err2 := tr.InstallRootCRL(ctx, e.f.RevokeIntermediate(t, e.clk.now())); err2 == nil {
					t.Fatal("root CRL: no error")
				} else {
					wantUnavailable(t, err2)
				}
			}
			wantUnavailable(t, err)
		})
	}
}
