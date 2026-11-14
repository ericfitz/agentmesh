package signingkeys_test

import (
	"context"
	"crypto/x509"
	"errors"
	"math/big"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/identities"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
)

// admin registers name as an administrator of e's store.
func (e *env) admin(t *testing.T, name string) {
	t.Helper()
	svc := identities.Service{Core: e.c}
	if err := svc.RegisterLocal(context.Background(), name); err != nil {
		t.Fatal(err)
	}
	if err := svc.MakeAdmin(context.Background(), name, true); err != nil {
		t.Fatal(err)
	}
}

// managerOn starts a manager over c (another process on e's store and clock).
func (e *env) managerOn(t *testing.T, c *core.Core) *signingkeys.Manager {
	t.Helper()
	m, err := signingkeys.New(context.Background(), signingkeys.Options{Trust: e.f.Trust(c), LeafValidity: week})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// leafCRL is the stored leaf CRL of the fixture's intermediate key.
func (e *env) leafCRL(t *testing.T) (store.TrustCRL, *x509.RevocationList, bool) {
	t.Helper()
	var rows []store.TrustCRL
	if err := e.st.Read(context.Background(), func(ctx context.Context, tx store.Tx) error {
		var err error
		rows, err = tx.CRLs(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.Kind == store.TrustLeafCRL && r.IssuerKey == keyID(e.f.Intermediate) {
			crl, err := pki.ParseCRL(r.DER)
			if err != nil {
				t.Fatal(err)
			}
			return r, crl, true
		}
	}
	return store.TrustCRL{}, nil, false
}

// crlSet is the serial numbers (hex) a CRL lists.
func crlSet(crl *x509.RevocationList) map[string]bool {
	out := map[string]bool{}
	if crl == nil {
		return out
	}
	for _, en := range crl.RevokedCertificateEntries {
		out[pki.SerialText(en.SerialNumber)] = true
	}
	return out
}

func (e *env) leafCerts(t *testing.T) []*x509.Certificate {
	t.Helper()
	var out []*x509.Certificate
	for _, r := range e.leafRows(t) {
		c, err := x509.ParseCertificate(r.DER)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, c)
	}
	return out
}

func thumbs(rs []bus.RevokedLeaf) map[string]bool {
	out := map[string]bool{}
	for _, r := range rs {
		out[r.Thumbprint] = true
	}
	return out
}

// otherKeyLeaf installs an intermediate of a second key and a leaf under it
// (a leaf the configured key does not cover), and returns the leaf.
func (e *env) otherKeyLeaf(t *testing.T) *x509.Certificate {
	t.Helper()
	k2 := newP256(t)
	inter2 := craft(t, e.f, &k2.PublicKey, nil)
	e.putIntermediate(t, inter2, "")
	leaf := leafUnder(t, inter2, k2, e.clk.now(), week)
	e.putLeaf(t, leaf, keyID(inter2))
	return leaf
}

func TestRevokeAll(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	e.newManager(t)
	e.managerOn(t, e.coreOver(t, e.st))
	foreign := e.otherKeyLeaf(t)
	certs := e.leafCerts(t)
	if len(certs) != 3 {
		t.Fatalf("%d leaf rows, want 3", len(certs))
	}
	before := e.trustNumber(t)

	res, err := e.tr.Revoke(ctx, e.mem, signingkeys.RevokeInput{All: true})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Changed || len(res.Revoked) != 2 {
		t.Fatalf("Changed=%v Revoked=%v, want the two leaves of the configured key", res.Changed, res.Revoked)
	}
	for _, c := range certs {
		if pki.Thumbprint(c.Raw) == pki.Thumbprint(foreign.Raw) {
			continue
		}
		if !thumbs(res.Revoked)[pki.Thumbprint(c.Raw)] {
			t.Fatalf("leaf %s not reported revoked", pki.Thumbprint(c.Raw))
		}
	}
	for _, r := range res.Revoked {
		if r.HumanMessages != 0 {
			t.Fatalf("HumanMessages = %d", r.HumanMessages)
		}
	}
	if len(res.NotCovered) != 1 || res.NotCovered[0] != pki.Thumbprint(foreign.Raw) {
		t.Fatalf("NotCovered = %v, want the foreign leaf", res.NotCovered)
	}
	row, crl, ok := e.leafCRL(t)
	if !ok {
		t.Fatal("no leaf CRL stored")
	}
	set := crlSet(crl)
	if len(set) != 2 || set[pki.SerialText(foreign.SerialNumber)] {
		t.Fatalf("CRL entries %v: want the two leaves of the key only", set)
	}
	if row.Number != pki.NextNumber(e.clk.now(), 0) {
		t.Fatalf("CRL number %d", row.Number)
	}
	if want := pki.NextNumber(e.clk.now(), before); res.TrustNumber != want || e.trustNumber(t) != want {
		t.Fatalf("trust number %d / stored %d, want %d", res.TrustNumber, e.trustNumber(t), want)
	}
	if len(e.leafRows(t)) != 3 {
		t.Fatal("the host form issued a leaf")
	}
}

func TestRevokeByCert(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	e.newManager(t)
	withRow := e.leafCerts(t)[0]
	noRow := leafFor(t, e.f, e.clk.now(), week)

	res, err := e.tr.Revoke(ctx, e.mem, signingkeys.RevokeInput{Cert: withRow})
	if err != nil || !res.Changed || len(res.Revoked) != 1 || res.Revoked[0].Thumbprint != pki.Thumbprint(withRow.Raw) || res.Revoked[0].HumanMessages != 0 {
		t.Fatalf("with a row: %+v, %v", res, err)
	}
	res, err = e.tr.Revoke(ctx, e.mem, signingkeys.RevokeInput{Cert: noRow})
	if err != nil || !res.Changed || len(res.Revoked) != 1 || res.Revoked[0].Thumbprint != pki.Thumbprint(noRow.Raw) || res.Revoked[0].HumanMessages != 0 {
		t.Fatalf("without a row: %+v, %v", res, err)
	}
	_, crl, _ := e.leafCRL(t)
	set := crlSet(crl)
	if len(set) != 2 || !set[pki.SerialText(withRow.SerialNumber)] || !set[pki.SerialText(noRow.SerialNumber)] {
		t.Fatalf("CRL entries %v", set)
	}

	// A certificate another key signed is refused, and nothing is written.
	n := e.trustNumber(t)
	foreign := e.otherKeyLeaf(t)
	_, err = e.tr.Revoke(ctx, e.mem, signingkeys.RevokeInput{Cert: foreign})
	wantCheck(t, err, "not signed by the configured intermediate key")
	if e.trustNumber(t) != n {
		t.Fatal("a refused revocation bumped the trust number")
	}
}

func TestRevokeBySerial(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	e.newManager(t)
	own := e.leafCerts(t)[0]

	res, err := e.tr.Revoke(ctx, e.mem, signingkeys.RevokeInput{Serial: own.SerialNumber})
	if err != nil || !res.Changed || len(res.Revoked) != 1 || res.Revoked[0].Thumbprint != pki.Thumbprint(own.Raw) {
		t.Fatalf("a serial number of a stored leaf: %+v, %v", res, err)
	}
	unknown := big.NewInt(424242)
	res, err = e.tr.Revoke(ctx, e.mem, signingkeys.RevokeInput{Serial: unknown})
	if err != nil || !res.Changed || len(res.Revoked) != 0 {
		t.Fatalf("a serial number no row has: %+v, %v", res, err)
	}
	_, crl, _ := e.leafCRL(t)
	set := crlSet(crl)
	if len(set) != 2 || !set[pki.SerialText(own.SerialNumber)] || !set[pki.SerialText(unknown)] {
		t.Fatalf("CRL entries %v: serial numbers are listed as given", set)
	}
}

func TestRevokeAlreadyListed(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	e.newManager(t)
	if _, err := e.tr.Revoke(ctx, e.mem, signingkeys.RevokeInput{All: true}); err != nil {
		t.Fatal(err)
	}
	n := e.trustNumber(t)
	row1, _, _ := e.leafCRL(t)
	e.clk.advance(time.Minute)

	for name, in := range map[string]signingkeys.RevokeInput{
		"all":    {All: true},
		"cert":   {Cert: e.leafCerts(t)[0]},
		"serial": {Serial: e.leafCerts(t)[0].SerialNumber},
	} {
		res, err := e.tr.Revoke(ctx, e.mem, in)
		if err != nil || res.Changed || len(res.Revoked) != 0 {
			t.Fatalf("%s: %+v, %v", name, res, err)
		}
		if res.TrustNumber != n || e.trustNumber(t) != n {
			t.Fatalf("%s: trust number %d / %d, want %d", name, res.TrustNumber, e.trustNumber(t), n)
		}
		if row2, _, _ := e.leafCRL(t); row2.Thumbprint != row1.Thumbprint {
			t.Fatalf("%s: the CRL was rewritten", name)
		}
	}
}

func TestRevokeInputs(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	e.newManager(t)
	cert := e.leafCerts(t)[0]
	n := e.trustNumber(t)
	for name, in := range map[string]signingkeys.RevokeInput{
		"none":              {},
		"all and serial":    {All: true, Serial: big.NewInt(5)},
		"all and cert":      {All: true, Cert: cert},
		"cert and serial":   {Cert: cert, Serial: big.NewInt(5)},
		"zero serial":       {Serial: big.NewInt(0)},
		"negative serial":   {Serial: big.NewInt(-7)},
		"all three":         {All: true, Cert: cert, Serial: big.NewInt(5)},
		"cert without data": {Cert: &x509.Certificate{}},
	} {
		_, err := e.tr.Revoke(ctx, e.mem, in)
		if !errors.Is(err, signingkeys.ErrCheck) {
			t.Fatalf("%s: err = %v, want ErrCheck", name, err)
		}
	}
	if _, _, ok := e.leafCRL(t); ok || e.trustNumber(t) != n {
		t.Fatal("a refused input wrote something")
	}
}

func TestRevokedLeafIsReplaced(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	m := e.newManager(t)
	old, _ := m.Current()
	if _, err := e.tr.Revoke(ctx, e.mem, signingkeys.RevokeInput{All: true}); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	wantWake(t, m, true)
	if tp, _ := m.Current(); tp != "" {
		t.Fatalf("Current = %q for a revoked leaf", tp)
	}
	m.Step(ctx)
	tp, _ := m.Current()
	if tp == "" || tp == old {
		t.Fatalf("Current = %q, want a new leaf", tp)
	}
}

func TestListSigningKeys(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	e.admin(t, "root")
	m1 := e.newManager(t)
	m2 := e.managerOn(t, e.coreOver(t, e.st))
	m3 := e.managerOn(t, e.coreOver(t, e.st))
	first, _ := m1.Current()
	other, _ := m2.Current()
	gone, _ := m3.Current()
	e.clk.advance(84 * time.Hour)
	m1.Step(ctx)
	cur, _ := m1.Current()
	if cur == first {
		t.Fatal("setup: no renewal")
	}
	var goneCert *x509.Certificate
	for _, c := range e.leafCerts(t) {
		if pki.Thumbprint(c.Raw) == gone {
			goneCert = c
		}
	}
	if _, err := e.tr.Revoke(ctx, e.mem, signingkeys.RevokeInput{Cert: goneCert}); err != nil {
		t.Fatal(err)
	}
	// An expired leaf is not listed.
	e.putLeaf(t, leafFor(t, e.f, time.UnixMilli(startMs), 2*time.Hour), keyID(e.f.Intermediate))

	l, err := m1.ListSigningKeys(ctx, "root")
	if err != nil {
		t.Fatal(err)
	}
	var got [][2]string
	for _, k := range l.Keys {
		got = append(got, [2]string{k.Thumbprint, k.State})
	}
	want := [][2]string{{cur, bus.SigningKeyCurrent}, {first, bus.SigningKeyPrevious}, {other, bus.SigningKeyOther}, {gone, bus.SigningKeyRevoked}}
	if len(got) != len(want) {
		t.Fatalf("keys %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("keys %v, want %v", got, want)
		}
	}
	if l.TrustNumber != e.trustNumber(t) {
		t.Fatalf("trust number %d, want %d", l.TrustNumber, e.trustNumber(t))
	}
	for _, k := range l.Keys {
		if k.IssuerThumbprint != pki.Thumbprint(e.f.Intermediate.Raw) || k.Serial == "" || k.NotAfter <= k.NotBefore {
			t.Fatalf("key fields: %+v", k)
		}
	}

	// The host form knows no current or previous leaf.
	hl, err := e.tr.List(ctx, e.mem)
	if err != nil {
		t.Fatal(err)
	}
	states := map[string]string{}
	for _, k := range hl.Keys {
		states[k.Thumbprint] = k.State
	}
	if len(states) != 4 || states[gone] != bus.SigningKeyRevoked || states[cur] != bus.SigningKeyOther || states[first] != bus.SigningKeyOther {
		t.Fatalf("host list states %v", states)
	}
	if hl.TrustNumber != l.TrustNumber {
		t.Fatalf("host list trust number %d", hl.TrustNumber)
	}

	// A non-administrator is refused.
	if err := (identities.Service{Core: e.c}).RegisterLocal(ctx, "bob"); err != nil {
		t.Fatal(err)
	}
	if _, err := m1.ListSigningKeys(ctx, "bob"); bus.CodeOf(err) != bus.CodeForbidden {
		t.Fatalf("a non-administrator: %v", err)
	}
	if _, err := m1.ListSigningKeys(ctx, ""); err == nil {
		t.Fatal("no identity was accepted")
	}
}

func TestRemoveExpiredLeaves(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	start := time.UnixMilli(startMs)
	a := leafFor(t, e.f, start, 2*time.Hour)               // not after: start+2h
	b := leafFor(t, e.f, start, 2*time.Hour+2*time.Minute) // not after: start+2h2m
	e.putLeaf(t, a, keyID(e.f.Intermediate))
	e.putLeaf(t, b, keyID(e.f.Intermediate))
	e.putCRL(t, store.TrustLeafCRL, keyID(e.f.Intermediate), crlBy(t, e.f.Intermediate, interKey(t, e.f), 5, start, a.SerialNumber))
	e.at(2*time.Hour + 61*time.Minute) // a is 61 minutes past its end, b 59

	n, err := e.tr.RemoveExpiredLeaves(ctx)
	if err != nil || n != 1 {
		t.Fatalf("removed %d, %v; want 1", n, err)
	}
	rows := e.leafRows(t)
	if len(rows) != 1 || rows[0].Thumbprint != pki.Thumbprint(b.Raw) {
		t.Fatalf("rows left: %d", len(rows))
	}
	if len(e.rows(t, store.TrustIntermediate)) != 1 {
		t.Fatal("an intermediate row went")
	}
	if _, crl, ok := e.leafCRL(t); !ok || !crlSet(crl)[pki.SerialText(a.SerialNumber)] {
		t.Fatal("the removed leaf's serial number left the CRL")
	}
	if n, err := e.tr.RemoveExpiredLeaves(ctx); err != nil || n != 0 {
		t.Fatalf("second call removed %d, %v", n, err)
	}
}

func TestRemoveExpiredLeavesBatch(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	start := time.UnixMilli(startMs)
	e.tx(t, func(ctx context.Context, tx store.Tx) error {
		for i := 0; i < 501; i++ {
			c := leafFor(t, e.f, start, 2*time.Hour)
			if _, err := tx.PutTrustCertificate(ctx, store.TrustCertificate{
				Kind: store.TrustLeaf, Thumbprint: pki.Thumbprint(c.Raw), DER: c.Raw,
				IssuerKey: keyID(e.f.Intermediate), NotAfter: c.NotAfter.UnixMilli(), CreatedAt: startMs,
			}); err != nil {
				return err
			}
		}
		return nil
	})
	e.at(5 * time.Hour)
	if n, err := e.tr.RemoveExpiredLeaves(ctx); err != nil || n != 500 {
		t.Fatalf("first call removed %d, %v; want 500", n, err)
	}
	if n, err := e.tr.RemoveExpiredLeaves(ctx); err != nil || n != 1 {
		t.Fatalf("second call removed %d, %v; want 1", n, err)
	}
}
