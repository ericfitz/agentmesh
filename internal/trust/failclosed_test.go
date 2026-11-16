package trust

import (
	"errors"
	"math/big"
	"os"
	"reflect"
	"testing"
)

func asIncomplete(t testing.TB, err error, dir string) {
	t.Helper()
	var inc *incompleteError
	if !errors.As(err, &inc) || !contains(err.Error(), dir) {
		t.Fatalf("got %v, want an incomplete-pin error naming %s", err, dir)
	}
}

// A first contact killed between the two writes (state.json only) is not a
// pin the next plain contact may overwrite.
func TestFirstContactHalfPinFailsClosed(t *testing.T) {
	c, other := newCA(t, "root-a"), newCA(t, "root-b")
	s := newStore(t)
	if err := s.withLock(true, func() error {
		return s.saveState(&state{Installation: "inst", Server: srv, RootThumb: thumb(c)})
	}); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, s.Dir)
	for _, ca := range []testCA{c, other} {
		_, err := s.Accept(discover(ca, "inst", 1), expect(srv), false)
		asIncomplete(t, err, s.Dir)
	}
	_, _, err := s.Pinned()
	asIncomplete(t, err, s.Dir)
	asIncomplete(t, s.Check(expect(srv)), s.Dir)
	if _, err := s.Apply(Bundle{TrustNumber: 1}); err == nil {
		t.Fatal("Apply on an incomplete pin succeeded")
	}
	if !reflect.DeepEqual(before, snapshot(t, s.Dir)) {
		t.Fatal("files changed")
	}
	// Recovery: -accept-new-root.
	acc, err := s.Accept(discover(other, "inst", 1), expect(srv), true)
	if err != nil || acc.New.Thumbprint != thumb(other) {
		t.Fatalf("%+v %v", acc, err)
	}
	if p, ok, err := s.Pinned(); err != nil || !ok || p.Thumbprint != thumb(other) {
		t.Fatalf("%+v %v %v", p, ok, err)
	}
	// root.pem alone is just as incomplete.
	s2 := newStore(t)
	if err := os.MkdirAll(s2.Dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s2.path(rootFile), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = s2.Accept(discover(c, "inst", 1), expect(srv), false)
	asIncomplete(t, err, s2.Dir)
}

// A replacement killed after state.json (the new thumbprint) and before
// root.pem.
func TestReplacementKilledBetweenWrites(t *testing.T) {
	a, b := newCA(t, "root-a"), newCA(t, "root-b")
	s := pinned(t, a, "inst")
	in := a.validInter(t, "inst")
	if _, err := s.Apply(Bundle{TrustNumber: 2, Intermediates: [][]byte{in.cert.Raw}, RootCRL: a.rootCRL(t, 1)}); err != nil {
		t.Fatal(err)
	}
	if err := s.withLock(false, func() error {
		return s.saveState(&state{Installation: "inst", Server: srv, RootThumb: thumb(b)})
	}); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, s.Dir)
	for _, ca := range []testCA{a, b} {
		_, err := s.Accept(discover(ca, "inst", 1), expect(srv), false)
		asIncomplete(t, err, s.Dir)
	}
	if !reflect.DeepEqual(before, snapshot(t, s.Dir)) {
		t.Fatal("files changed")
	}
	if _, err := s.Accept(discover(b, "inst", 1), expect(srv), true); err != nil {
		t.Fatal(err)
	}
	if got := names(snapshot(t, s.Dir)); !reflect.DeepEqual(got, []string{"root.pem", "state.json"}) {
		t.Fatalf("files = %v", got)
	}
	if cs, _ := s.Intermediates(); len(cs) != 0 {
		t.Fatal("old chain kept")
	}
}

// A replacement killed after both pin files and before the derived files are
// removed: the leftovers of the old root are never adopted.
func TestReplacementLeftoversIgnored(t *testing.T) {
	a, b := newCA(t, "root-a"), newCA(t, "root-b")
	s := pinned(t, a, "inst")
	ina := a.validInter(t, "inst")
	if _, err := s.Apply(Bundle{TrustNumber: 2, Intermediates: [][]byte{ina.cert.Raw}, RootCRL: a.rootCRL(t, 1000000, big.NewInt(9))}); err != nil {
		t.Fatal(err)
	}
	if err := s.writePin(Pin{Root: b.root, Thumbprint: thumb(b), Installation: "inst", Server: srv}); err != nil {
		t.Fatal(err)
	}
	if cs, err := s.Intermediates(); err != nil || len(cs) != 0 {
		t.Fatalf("%d %v", len(cs), err)
	}
	if r, _ := s.Revocations(); len(r.Root) != 0 {
		t.Fatalf("%+v", r)
	}
	inb := b.validInter(t, "inst")
	rep, err := s.Apply(Bundle{TrustNumber: 3, Intermediates: [][]byte{inb.cert.Raw}, RootCRL: b.rootCRL(t, 5)})
	if err != nil || len(rep.Refused) != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	cs, _ := s.Intermediates()
	if len(cs) != 1 || !cs[0].Equal(inb.cert) {
		t.Fatalf("held %d", len(cs))
	}
	if r, _ := s.Revocations(); hasSerial(r.Root, 9) {
		t.Fatal("old revocation adopted")
	}
}

// The pin gone with leftovers behind (the reviewer's scenario).
func TestFirstContactClearsLeftovers(t *testing.T) {
	a, b := newCA(t, "root-a"), newCA(t, "root-b")
	s := pinned(t, a, "inst")
	ina := a.validInter(t, "inst")
	if _, err := s.Apply(Bundle{TrustNumber: 2, Intermediates: [][]byte{ina.cert.Raw}, RootCRL: a.rootCRL(t, 1000000, big.NewInt(9))}); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.path(stateFile)); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(s.path(rootFile)); err != nil {
		t.Fatal(err)
	}
	if acc, err := s.Accept(discover(b, "inst", 1), expect(srv), false); err != nil || !acc.First {
		t.Fatalf("%+v %v", acc, err)
	}
	if got := names(snapshot(t, s.Dir)); !reflect.DeepEqual(got, []string{"root.pem", "state.json"}) {
		t.Fatalf("files = %v", got)
	}
	rep, err := s.Apply(Bundle{TrustNumber: 3, RootCRL: b.rootCRL(t, 5)})
	if err != nil || len(rep.Refused) != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	if cs, _ := s.Intermediates(); len(cs) != 0 {
		t.Fatal("old intermediate held")
	}
}
