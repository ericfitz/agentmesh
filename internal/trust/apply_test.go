package trust

import (
	"math/big"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/pki"
)

func hasSerial(list []string, n int64) bool {
	for _, s := range list {
		if s == pki.SerialText(big.NewInt(n)) {
			return true
		}
	}
	return false
}

func TestApplyKeepsIntermediates(t *testing.T) {
	c := newCA(t, "root-a")
	s := pinned(t, c, "inst")
	good := c.validInter(t, "inst")
	other := c.validInter(t, "other-inst")
	now := time.Now()
	expired := c.inter(t, "inst", now.Add(-48*time.Hour), now.Add(-24*time.Hour))
	if _, err := s.Apply(Bundle{TrustNumber: 1, Intermediates: [][]byte{good.cert.Raw, other.cert.Raw, expired.cert.Raw, []byte("junk")}}); err != nil {
		t.Fatal(err)
	}
	got, err := s.Intermediates()
	if err != nil {
		t.Fatal(err)
	}
	has := func(c *testInter) bool {
		for _, x := range got {
			if x.Equal(c.cert) {
				return true
			}
		}
		return false
	}
	if len(got) != 2 || !has(&good) || !has(&expired) || has(&other) {
		t.Fatalf("kept %d, good=%v expired=%v other=%v", len(got), has(&good), has(&expired), has(&other))
	}
	// A held one absent from the next bundle stays.
	next := c.validInter(t, "inst")
	if _, err := s.Apply(Bundle{TrustNumber: 2, Intermediates: [][]byte{next.cert.Raw}}); err != nil {
		t.Fatal(err)
	}
	got, _ = s.Intermediates()
	if len(got) != 3 {
		t.Fatalf("kept %d, want 3", len(got))
	}
}

func TestApplyNeedsPin(t *testing.T) {
	s := newStore(t)
	if _, err := s.Apply(Bundle{}); err == nil {
		t.Fatal("Apply without a pin succeeded")
	}
	if len(snapshot(t, s.Dir)) != 0 {
		t.Fatal("created files")
	}
}

func TestApplyCRLNumbers(t *testing.T) {
	c := newCA(t, "root-a")
	s := pinned(t, c, "inst")
	in := c.validInter(t, "inst")
	apply := func(n int64) Report {
		rep, err := s.Apply(Bundle{TrustNumber: n, Intermediates: [][]byte{in.cert.Raw}, RootCRL: c.rootCRL(t, n), LeafCRLs: [][]byte{in.crl(t, n)}})
		if err != nil {
			t.Fatal(err)
		}
		return rep
	}
	if rep := apply(5); len(rep.Refused) != 0 {
		t.Fatalf("%+v", rep)
	}
	if rep := apply(5); len(rep.Refused) != 0 {
		t.Fatalf("equal refused: %+v", rep)
	}
	if rep := apply(7); len(rep.Refused) != 0 {
		t.Fatalf("higher refused: %+v", rep)
	}
	before := snapshot(t, s.Dir)
	rep := apply(3)
	want := []RefusedCRL{{Held: 7, Got: 3}, {IssuerKey: in.keyID(), Held: 7, Got: 3}}
	if !reflect.DeepEqual(rep.Refused, want) {
		t.Fatalf("Refused = %+v, want %+v", rep.Refused, want)
	}
	after := snapshot(t, s.Dir)
	for _, f := range []string{"root.crl", "leaf-" + in.keyID() + ".crl", "revoked.json", "intermediates.pem"} {
		if before[f] != after[f] {
			t.Fatalf("%s changed", f)
		}
	}
}

func TestApplyUnion(t *testing.T) {
	c := newCA(t, "root-a")
	s := pinned(t, c, "inst")
	in := c.validInter(t, "inst")
	b := func(n int64, root, leaf int64) Bundle {
		return Bundle{TrustNumber: n, Intermediates: [][]byte{in.cert.Raw}, RootCRL: c.rootCRL(t, n, big.NewInt(root)), LeafCRLs: [][]byte{in.crl(t, n, big.NewInt(leaf))}}
	}
	if _, err := s.Apply(b(1, 101, 201)); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Apply(b(2, 102, 202)); err != nil {
		t.Fatal(err)
	}
	r, err := s.Revocations()
	if err != nil {
		t.Fatal(err)
	}
	if !hasSerial(r.Root, 101) || !hasSerial(r.Root, 102) || !hasSerial(r.Leaves[in.keyID()], 201) || !hasSerial(r.Leaves[in.keyID()], 202) {
		t.Fatalf("%+v", r)
	}
}

func TestApplyLeafCRLOfRevokedKey(t *testing.T) {
	c := newCA(t, "root-a")
	s := pinned(t, c, "inst")
	in := c.validInter(t, "inst")
	// The root CRL of the same bundle revokes the intermediate.
	rep, err := s.Apply(Bundle{TrustNumber: 1, Intermediates: [][]byte{in.cert.Raw}, RootCRL: c.rootCRL(t, 1, in.cert.SerialNumber), LeafCRLs: [][]byte{in.crl(t, 1, big.NewInt(77))}})
	if err != nil || len(rep.Refused) != 0 {
		t.Fatalf("%+v %v", rep, err)
	}
	r, _ := s.Revocations()
	if len(r.Leaves[in.keyID()]) != 0 {
		t.Fatalf("leaf CRL of a revoked key accepted: %+v", r)
	}
	if _, ok := snapshot(t, s.Dir)["leaf-"+in.keyID()+".crl"]; ok {
		t.Fatal("leaf CRL file written")
	}
	// A leaf CRL signed by no kept intermediate is not accepted either.
	stranger := c.validInter(t, "inst")
	if _, err := s.Apply(Bundle{TrustNumber: 2, LeafCRLs: [][]byte{stranger.crl(t, 1, big.NewInt(5))}}); err != nil {
		t.Fatal(err)
	}
	if r, _ := s.Revocations(); len(r.Leaves[stranger.keyID()]) != 0 {
		t.Fatal("stranger's CRL accepted")
	}
}

func TestApplyRecordsTrustNumber(t *testing.T) {
	c := newCA(t, "root-a")
	s := pinned(t, c, "inst")
	if _, ok, _ := s.TrustNumber(); ok {
		t.Fatal("number before any bundle")
	}
	for _, n := range []int64{9, 4} {
		if _, err := s.Apply(Bundle{TrustNumber: n}); err != nil {
			t.Fatal(err)
		}
		if got, ok, err := s.TrustNumber(); err != nil || !ok || got != n {
			t.Fatalf("n=%d got %d ok=%v err=%v", n, got, ok, err)
		}
	}
	// Also when a CRL was refused.
	if _, err := s.Apply(Bundle{TrustNumber: 20, RootCRL: c.rootCRL(t, 8)}); err != nil {
		t.Fatal(err)
	}
	rep, err := s.Apply(Bundle{TrustNumber: 6, RootCRL: c.rootCRL(t, 2)})
	if err != nil || len(rep.Refused) != 1 {
		t.Fatalf("%+v %v", rep, err)
	}
	if got, _, _ := s.TrustNumber(); got != 6 {
		t.Fatalf("trust number %d, want 6", got)
	}
}

func TestApplyTwice(t *testing.T) {
	c := newCA(t, "root-a")
	s := pinned(t, c, "inst")
	in := c.validInter(t, "inst")
	b := Bundle{TrustNumber: 3, Intermediates: [][]byte{in.cert.Raw}, RootCRL: c.rootCRL(t, 3, big.NewInt(1)), LeafCRLs: [][]byte{in.crl(t, 3, big.NewInt(2))}}
	if _, err := s.Apply(b); err != nil {
		t.Fatal(err)
	}
	before := snapshot(t, s.Dir)
	if _, err := s.Apply(b); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, snapshot(t, s.Dir)) {
		t.Fatal("second Apply changed files")
	}
}

func TestTwoWriters(t *testing.T) {
	c := newCA(t, "root-a")
	s := pinned(t, c, "inst")
	in := c.validInter(t, "inst")
	mk := func(n int64, root, leaf int64) Bundle {
		return Bundle{TrustNumber: n, Intermediates: [][]byte{in.cert.Raw}, RootCRL: c.rootCRL(t, n, big.NewInt(root)), LeafCRLs: [][]byte{in.crl(t, n, big.NewInt(leaf))}}
	}
	bs := []Bundle{mk(5, 11, 21), mk(8, 12, 22)}
	// Whichever applies first, the higher numbers win. The lower bundle adds
	// its serial numbers only when it ran first (a refused CRL adds nothing,
	// Ruling 34), so the union is checked for that outcome: bundle 5 is
	// applied alone first in the odd rounds.
	for round := 0; round < 20; round++ {
		s = pinned(t, c, "inst")
		var wg sync.WaitGroup
		refused := make([]int, len(bs))
		if round%2 == 1 {
			if _, err := s.Apply(bs[0]); err != nil {
				t.Fatal(err)
			}
			refused[0] = 0
		}
		for i := range bs {
			if round%2 == 1 && i == 0 {
				continue
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				rep, err := s.Apply(bs[i])
				if err != nil {
					t.Error(err)
				}
				refused[i] = len(rep.Refused)
			}()
		}
		wg.Wait()
		if n, _, err := s.heldCRLNumber(rootCRLFile, c.root); err != nil || n != 8 {
			t.Fatalf("round %d: root CRL number %d %v", round, n, err)
		}
		if n, _, _ := s.heldCRLNumber(leafCRLName(in.keyID()), in.cert); n != 8 {
			t.Fatalf("round %d: leaf CRL number %d", round, n)
		}
		r, _ := s.Revocations()
		if !hasSerial(r.Root, 12) || !hasSerial(r.Leaves[in.keyID()], 22) {
			t.Fatalf("round %d: winner's serials missing: %+v", round, r)
		}
		if refused[0] == 0 && (!hasSerial(r.Root, 11) || !hasSerial(r.Leaves[in.keyID()], 21)) {
			t.Fatalf("round %d: union lost: %+v", round, r)
		}
		if refused[0] != 0 && (hasSerial(r.Root, 11) || hasSerial(r.Leaves[in.keyID()], 21)) {
			t.Fatalf("round %d: refused CRL's serials kept: %+v", round, r)
		}
	}
}

func TestCrashBetweenFiles(t *testing.T) {
	c := newCA(t, "root-a")
	s := pinned(t, c, "inst") // the pin and nothing else
	if got := names(snapshot(t, s.Dir)); !reflect.DeepEqual(got, []string{"root.pem", "state.json"}) {
		t.Fatalf("files = %v", got)
	}
	in := c.validInter(t, "inst")
	if _, err := s.Apply(Bundle{TrustNumber: 2, Intermediates: [][]byte{in.cert.Raw}, RootCRL: c.rootCRL(t, 1)}); err != nil {
		t.Fatal(err)
	}
	if got := names(snapshot(t, s.Dir)); len(got) != 5 {
		t.Fatalf("files = %v", got)
	}
}

func TestConcurrentReadWrite(t *testing.T) {
	c := newCA(t, "root-a")
	s := pinned(t, c, "inst")
	in := c.validInter(t, "inst")
	const n = 200
	bundles := make([]Bundle, n)
	for i := range bundles {
		k := int64(i + 1)
		bundles[i] = Bundle{TrustNumber: k, Intermediates: [][]byte{in.cert.Raw}, RootCRL: c.rootCRL(t, k, big.NewInt(k)), LeafCRLs: [][]byte{in.crl(t, k, big.NewInt(k))}}
	}
	done := make(chan struct{})
	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		defer close(done)
		for _, b := range bundles {
			if _, err := s.Apply(b); err != nil {
				t.Errorf("Apply: %v", err)
				return
			}
		}
	}()
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-done:
				return
			default:
			}
			if _, _, err := s.TrustNumber(); err != nil {
				t.Errorf("TrustNumber: %v", err)
				return
			}
			if _, err := s.Intermediates(); err != nil {
				t.Errorf("Intermediates: %v", err)
				return
			}
			if _, err := s.Revocations(); err != nil {
				t.Errorf("Revocations: %v", err)
				return
			}
		}
	}()
	wg.Wait()
	if got, _, _ := s.TrustNumber(); got != n {
		t.Fatalf("trust number %d", got)
	}
}

// A leaf CRL held from before an intermediate's renewal still counts: the new
// certificate has the same key and another validity period, and the number rule
// is per issuer key (spec 4.10 step 4; issue #44, M4).
func TestApplyLeafCRLNumberAcrossRenewal(t *testing.T) {
	c := newCA(t, "root-a")
	s := pinned(t, c, "inst")
	k := newKey(t)
	der, err := pki.NewRequest(k, "inst")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	issue := func(nb, na time.Time) testInter {
		cert, err := pki.IssueIntermediate(c.root, c.rootKey, csr, nb, na)
		if err != nil {
			t.Fatal(err)
		}
		return testInter{cert, k}
	}
	old := issue(now.Add(-3*time.Hour), now.Add(-time.Hour))
	renewed := issue(now.Add(-30*time.Minute), now.Add(time.Hour))
	leafCRL := func(in testInter, number int64, at time.Time) []byte {
		d, err := pki.CreateCRL(in.cert, in.key, number, at, nil)
		if err != nil {
			t.Fatal(err)
		}
		return d
	}
	if _, err := s.Apply(Bundle{TrustNumber: 2, Intermediates: [][]byte{old.cert.Raw}, LeafCRLs: [][]byte{leafCRL(old, 100, now.Add(-2*time.Hour))}}); err != nil {
		t.Fatal(err)
	}
	rep, err := s.Apply(Bundle{TrustNumber: 3, Intermediates: [][]byte{old.cert.Raw, renewed.cert.Raw}, LeafCRLs: [][]byte{leafCRL(renewed, 50, now)}})
	if err != nil {
		t.Fatal(err)
	}
	want := []RefusedCRL{{IssuerKey: old.keyID(), Held: 100, Got: 50}}
	if !reflect.DeepEqual(rep.Refused, want) {
		t.Fatalf("Refused = %+v, want %+v", rep.Refused, want)
	}
}
