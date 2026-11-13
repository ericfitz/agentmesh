package trust

import (
	"errors"
	"reflect"
	"sync"
	"testing"
)

func errorsAs(err error, target **MismatchError) bool { return errors.As(err, target) }

func TestFirstContactPins(t *testing.T) {
	c := newCA(t, "root-a")
	s := newStore(t)
	if _, ok, err := s.Pinned(); err != nil || ok {
		t.Fatalf("before: ok=%v err=%v", ok, err)
	}
	a, err := s.Accept(discover(c, "inst-a", 1), expect(srv), false)
	if err != nil || !a.First || a.Replaced {
		t.Fatalf("Accept = %+v, %v", a, err)
	}
	p, ok, err := s.Pinned()
	if err != nil || !ok {
		t.Fatalf("Pinned: ok=%v err=%v", ok, err)
	}
	if p.Installation != "inst-a" || p.Server != srv || p.Thumbprint != a.New.Thumbprint || !p.Root.Equal(c.root) {
		t.Fatalf("pin = %+v", p)
	}
	again, err := s.Accept(discover(c, "inst-a", 2), expect(srv), false)
	if err != nil || again.First || again.Replaced {
		t.Fatalf("second Accept = %+v, %v", again, err)
	}
}

func TestDifferentRootRefused(t *testing.T) {
	a, b := newCA(t, "root-a"), newCA(t, "root-b")
	s := pinned(t, a, "inst")
	inter := a.validInter(t, "inst")
	if _, err := s.Apply(Bundle{TrustNumber: 4, Intermediates: [][]byte{inter.cert.Raw}, RootCRL: a.rootCRL(t, 3)}); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, s.Dir)
	_, err := s.Accept(discover(b, "inst", 9), expect(srv), false)
	me := asMismatch(t, err, "root")
	if me.Held == "" || me.Got == "" || me.Held == me.Got {
		t.Fatalf("thumbprints: %+v", me)
	}
	if !reflect.DeepEqual(before, snapshot(t, s.Dir)) {
		t.Fatal("files changed")
	}
}

func TestDifferentInstallationRefused(t *testing.T) {
	c := newCA(t, "root-a")
	s := pinned(t, c, "inst-a")
	before := snapshot(t, s.Dir)
	_, err := s.Accept(discover(c, "inst-b", 1), expect(srv), false)
	me := asMismatch(t, err, "installation")
	if me.Held != "inst-a" || me.Got != "inst-b" {
		t.Fatalf("%+v", me)
	}
	if !reflect.DeepEqual(before, snapshot(t, s.Dir)) {
		t.Fatal("files changed")
	}
}

func TestExpectedRoot(t *testing.T) {
	a, b := newCA(t, "root-a"), newCA(t, "root-b")
	ta, tb := thumb(a), thumb(b)
	s := newStore(t)
	e := Expect{Server: srv, RootThumbprint: ta}
	// Another root: refused, directory stays empty.
	_, err := s.Accept(discover(b, "inst", 1), e, false)
	me := asMismatch(t, err, "expected root")
	if me.Held != ta || me.Got != tb {
		t.Fatalf("%+v", me)
	}
	if len(snapshot(t, s.Dir)) != 0 {
		t.Fatal("directory not empty")
	}
	// A match pins.
	if acc, err := s.Accept(discover(a, "inst", 1), e, false); err != nil || !acc.First {
		t.Fatalf("%+v %v", acc, err)
	}
	// acceptNew toward a root that does not match is refused.
	before := snapshot(t, s.Dir)
	_, err = s.Accept(discover(b, "inst", 1), e, true)
	asMismatch(t, err, "expected root")
	if !reflect.DeepEqual(before, snapshot(t, s.Dir)) {
		t.Fatal("files changed")
	}
	// A held pin that differs fails Check.
	err = s.Check(Expect{Server: srv, RootThumbprint: tb})
	asMismatch(t, err, "expected root")
	if err := s.Check(e); err != nil {
		t.Fatal(err)
	}
}

func TestExpectedInstallation(t *testing.T) {
	c := newCA(t, "root-a")
	s := newStore(t)
	e := Expect{Server: srv, Installation: "inst-a"}
	_, err := s.Accept(discover(c, "inst-b", 1), e, false)
	me := asMismatch(t, err, "expected installation")
	if me.Held != "inst-a" || me.Got != "inst-b" {
		t.Fatalf("%+v", me)
	}
	if len(snapshot(t, s.Dir)) != 0 {
		t.Fatal("directory not empty")
	}
	if acc, err := s.Accept(discover(c, "inst-a", 1), e, false); err != nil || !acc.First {
		t.Fatalf("%+v %v", acc, err)
	}
	before := snapshot(t, s.Dir)
	_, err = s.Accept(discover(c, "inst-b", 1), e, true)
	asMismatch(t, err, "expected installation")
	if !reflect.DeepEqual(before, snapshot(t, s.Dir)) {
		t.Fatal("files changed")
	}
	asMismatch(t, s.Check(Expect{Server: srv, Installation: "inst-b"}), "expected installation")
	if err := s.Check(e); err != nil {
		t.Fatal(err)
	}
}

func TestExpectIndependent(t *testing.T) {
	c := newCA(t, "root-a")
	s1, s2 := newStore(t), newStore(t)
	if _, err := s1.Accept(discover(c, "inst-a", 1), Expect{Server: srv, RootThumbprint: thumb(c)}, false); err != nil {
		t.Fatalf("root alone: %v", err)
	}
	if _, err := s2.Accept(discover(c, "inst-a", 1), Expect{Server: srv, Installation: "inst-a"}, false); err != nil {
		t.Fatalf("installation alone: %v", err)
	}
}

func TestServerChanged(t *testing.T) {
	c := newCA(t, "root-a")
	s := pinned(t, c, "inst")
	me := asMismatch(t, s.Check(expect("https://other.example.test")), "server")
	if me.Held != srv || me.Got != "https://other.example.test" {
		t.Fatalf("%+v", me)
	}
	if err := s.Check(expect(srv)); err != nil {
		t.Fatal(err)
	}
}

func TestAcceptNewRoot(t *testing.T) {
	a, b := newCA(t, "root-a"), newCA(t, "root-b")
	s := pinned(t, a, "inst-a")
	inter := a.validInter(t, "inst-a")
	if _, err := s.Apply(Bundle{TrustNumber: 2, Intermediates: [][]byte{inter.cert.Raw}, RootCRL: a.rootCRL(t, 1), LeafCRLs: [][]byte{inter.crl(t, 1)}}); err != nil {
		t.Fatal(err)
	}
	acc, err := s.Accept(discover(b, "inst-b", 1), expect(srv), true)
	if err != nil || !acc.Replaced || acc.First || acc.Old.Installation != "inst-a" || acc.New.Installation != "inst-b" || acc.Old.Thumbprint == acc.New.Thumbprint {
		t.Fatalf("%+v %v", acc, err)
	}
	got := names(snapshot(t, s.Dir))
	if !reflect.DeepEqual(got, []string{"root.pem", "state.json"}) {
		t.Fatalf("files = %v", got)
	}
	if _, ok, _ := s.TrustNumber(); ok {
		t.Fatal("trust number survived")
	}
	if r, err := s.Revocations(); err != nil || len(r.Root) != 0 || len(r.Leaves) != 0 {
		t.Fatalf("%+v %v", r, err)
	}
	before := snapshot(t, s.Dir)
	again, err := s.Accept(discover(b, "inst-b", 1), expect(srv), true)
	if err != nil || again.Replaced || again.First {
		t.Fatalf("second run %+v %v", again, err)
	}
	if !reflect.DeepEqual(before, snapshot(t, s.Dir)) {
		t.Fatal("second run changed files")
	}
}

func TestTwoFirstContacts(t *testing.T) {
	c := newCA(t, "root-a")
	s := newStore(t)
	var wg sync.WaitGroup
	res := make([]Accepted, 2)
	errs := make([]error, 2)
	for i := range res {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res[i], errs[i] = s.Accept(discover(c, "inst", 1), expect(srv), false)
		}()
	}
	wg.Wait()
	if errs[0] != nil || errs[1] != nil {
		t.Fatalf("%v %v", errs[0], errs[1])
	}
	if res[0].First == res[1].First {
		t.Fatalf("First: %v and %v, want exactly one", res[0].First, res[1].First)
	}

	a, b := newCA(t, "root-a"), newCA(t, "root-b")
	s = newStore(t)
	roots := []testCA{a, b}
	for i := range res {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res[i], errs[i] = s.Accept(discover(roots[i], "inst", 1), expect(srv), false)
		}()
	}
	wg.Wait()
	if (errs[0] == nil) == (errs[1] == nil) {
		t.Fatalf("exactly one must fail: %v %v", errs[0], errs[1])
	}
	for _, err := range errs {
		if err != nil {
			asMismatch(t, err, "root")
		}
	}
}

func TestStoreUnwritable(t *testing.T) {
	c := newCA(t, "root-a")
	dir := t.TempDir()
	s := Store{Dir: Dir(dir, "p")}
	// A regular file where the directory should be.
	if err := mkParentFile(s.Dir); err != nil {
		t.Fatal(err)
	}
	_, err := s.Accept(discover(c, "inst", 1), expect(srv), false)
	if err == nil {
		t.Fatal("Accept succeeded")
	}
	if !contains(err.Error(), s.Dir) {
		t.Fatalf("error does not name %s: %v", s.Dir, err)
	}
	if _, ok, err := s.Pinned(); err != nil || ok {
		t.Fatalf("Pinned: ok=%v err=%v", ok, err)
	}
	// A directory that cannot be created below a file.
	s2 := Store{Dir: s.Dir + "/sub"}
	if _, err := s2.Accept(discover(c, "inst", 1), expect(srv), false); err == nil || !contains(err.Error(), s2.Dir) {
		t.Fatalf("below a file: %v", err)
	}
	if _, ok, err := s2.Pinned(); err != nil || ok {
		t.Fatalf("Pinned below a file: ok=%v err=%v", ok, err)
	}
}
