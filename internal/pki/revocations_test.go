package pki

import (
	"crypto/x509"
	"encoding/json"
	"math/big"
	"reflect"
	"testing"
)

func TestRevocationByKey(t *testing.T) {
	key := newP256(t)
	a := buildChain(t, chainOpts{interKey: key})
	b := buildChain(t, chainOpts{interKey: key}) // a renewal: same key, new certificate
	if KeyID(a.inter.SubjectKeyId) != KeyID(b.inter.SubjectKeyId) {
		t.Fatal("fixture: the renewal must keep the key")
	}
	der, err := CreateCRL(a.root, a.rootKey, 1, fixtureBase, []*big.Int{a.inter.SerialNumber})
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ParseCRL(der)
	if err != nil {
		t.Fatal(err)
	}
	var r Revocations
	r.AddRoot(crl)
	inters := []*x509.Certificate{a.inter, b.inter}
	keys := r.RevokedKeys(inters)
	if !keys[KeyID(a.inter.SubjectKeyId)] || len(keys) != 1 {
		t.Fatalf("RevokedKeys = %v", keys)
	}
	if !r.LeafRevoked(b.leaf, inters) {
		t.Error("a leaf chaining through the renewal is not revoked")
	}

	// A serial number matching no held certificate revokes nothing.
	der, err = CreateCRL(a.root, a.rootKey, 2, fixtureBase, []*big.Int{big.NewInt(99)})
	if err != nil {
		t.Fatal(err)
	}
	crl, err = ParseCRL(der)
	if err != nil {
		t.Fatal(err)
	}
	var r2 Revocations
	r2.AddRoot(crl)
	if got := r2.RevokedKeys(inters); len(got) != 0 {
		t.Errorf("RevokedKeys = %v", got)
	}
	if r2.LeafRevoked(b.leaf, inters) {
		t.Error("leaf revoked by an unmatched serial number")
	}
}

func TestLeafRevokedBySerial(t *testing.T) {
	f := buildChain(t, chainOpts{})
	var r Revocations
	if r.LeafRevoked(f.leaf, []*x509.Certificate{f.inter}) {
		t.Fatal("empty revocations revoke")
	}
	der, err := CreateCRL(f.inter, f.interKey, 1, fixtureBase, []*big.Int{f.leaf.SerialNumber})
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ParseCRL(der)
	if err != nil {
		t.Fatal(err)
	}
	r.AddLeaves(KeyID(f.inter.SubjectKeyId), crl)
	if !r.LeafRevoked(f.leaf, []*x509.Certificate{f.inter}) {
		t.Error("leaf serial number kept but not revoked")
	}
	other := buildChain(t, chainOpts{})
	if r.LeafRevoked(other.leaf, []*x509.Certificate{other.inter}) {
		t.Error("another issuer's leaf revoked")
	}
}

func TestUnion(t *testing.T) {
	f := buildChain(t, chainOpts{})
	mk := func(n int64, ids ...int64) *x509.RevocationList {
		var ss []*big.Int
		for _, i := range ids {
			ss = append(ss, big.NewInt(i))
		}
		der, err := CreateCRL(f.inter, f.interKey, n, fixtureBase, ss)
		if err != nil {
			t.Fatal(err)
		}
		c, err := ParseCRL(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	var r Revocations
	r.AddLeaves("k", mk(1, 2, 1, 2))
	r.AddLeaves("k", mk(2, 3))
	got := r.LeafSerials("k")
	if len(got) != 3 || got[0].Int64() != 1 || got[1].Int64() != 2 || got[2].Int64() != 3 {
		t.Fatalf("LeafSerials = %v", got)
	}
	if len(r.LeafSerials("none")) != 0 {
		t.Error("serials for an unknown key")
	}

	var a, b Revocations
	a.AddLeaves("k", mk(1, 1, 255))
	a.AddLeaves("j", mk(1, 5))
	a.AddRoot(mk(1, 10))
	b.AddLeaves("k", mk(1, 2, 255))
	b.AddLeaves("m", mk(1, 9))
	b.AddRoot(mk(1, 10, 11))
	a.Merge(b)
	want := Revocations{
		Root: []string{"a", "b"},
		Leaves: map[string][]string{
			"j": {"5"}, "k": {"1", "2", "ff"}, "m": {"9"},
		},
	}
	if !reflect.DeepEqual(a, want) {
		t.Errorf("Merge = %+v, want %+v", a, want)
	}

	raw, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	var back Revocations
	if err := json.Unmarshal(raw, &back); err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(back, a) {
		t.Errorf("round trip = %+v", back)
	}
}

// A leaf whose authority key identifier is absent or wrong, signed by a revoked
// key, is still revoked: the issuer is the intermediate that verifies the
// signature, not what the leaf claims.
func TestLeafRevokedIgnoresForgedAKI(t *testing.T) {
	mods := map[string]func(*x509.Certificate){
		"absent":   func(c *x509.Certificate) { c.SubjectKeyId = nil },
		"mismatch": func(c *x509.Certificate) { c.SubjectKeyId = []byte{9, 9, 9} },
	}
	for name, mod := range mods {
		t.Run(name, func(t *testing.T) {
			f := buildChain(t, chainOpts{leafParentMod: mod})
			if got := KeyID(f.leaf.AuthorityKeyId); got == KeyID(f.inter.SubjectKeyId) {
				t.Fatalf("fixture: AKI %q was not forged", got)
			}
			der, err := CreateCRL(f.root, f.rootKey, 1, fixtureBase, []*big.Int{f.inter.SerialNumber})
			if err != nil {
				t.Fatal(err)
			}
			crl, err := ParseCRL(der)
			if err != nil {
				t.Fatal(err)
			}
			var r Revocations
			if r.LeafRevoked(f.leaf, []*x509.Certificate{f.inter}) {
				t.Fatal("revoked with nothing revoked")
			}
			r.AddRoot(crl)
			if !r.LeafRevoked(f.leaf, []*x509.Certificate{f.inter}) {
				t.Error("forged-AKI leaf under a revoked key is not revoked")
			}
		})
	}
	// A leaf serial kept for the key is found whatever the leaf's AKI says.
	f := buildChain(t, chainOpts{leafParentMod: mods["mismatch"]})
	var r Revocations
	r.Leaves = map[string][]string{KeyID(f.inter.SubjectKeyId): {SerialText(f.leaf.SerialNumber)}}
	if !r.LeafRevoked(f.leaf, []*x509.Certificate{f.inter}) {
		t.Error("kept leaf serial not found for a forged-AKI leaf")
	}
}

func TestLeafRevokedFailsClosed(t *testing.T) {
	f := buildChain(t, chainOpts{})
	other := buildChain(t, chainOpts{})
	var r Revocations
	if !r.LeafRevoked(f.leaf, []*x509.Certificate{other.inter}) {
		t.Error("a leaf no listed intermediate verifies is not revoked")
	}
	if !r.LeafRevoked(f.leaf, nil) {
		t.Error("a leaf with no intermediates is not revoked")
	}
}

// Certificates of one key are checked once, and a key that did not sign the
// leaf is not listed (issue #44, Important 3).
func TestLeafIssuerKeysOncePerKey(t *testing.T) {
	key := newP256(t)
	a := buildChain(t, chainOpts{interKey: key})
	b := buildChain(t, chainOpts{interKey: key}) // a renewal
	other := buildChain(t, chainOpts{})
	got := LeafIssuerKeys(b.leaf, []*x509.Certificate{other.inter, a.inter, b.inter})
	want := []string{KeyID(a.inter.SubjectKeyId)}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("LeafIssuerKeys = %v, want %v", got, want)
	}
	var r Revocations
	if r.LeafRevokedBy(b.leaf.SerialNumber, got, []*x509.Certificate{a.inter, b.inter}) {
		t.Error("revoked with nothing listed")
	}
	if !r.LeafRevokedBy(b.leaf.SerialNumber, nil, nil) {
		t.Error("a leaf no key verifies is not revoked")
	}
}
