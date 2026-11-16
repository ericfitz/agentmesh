package pki

import (
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"testing"
	"time"
)

func TestNextNumber(t *testing.T) {
	cases := []struct {
		nowMS    int64
		previous int64
		want     int64
	}{
		{1000, 5, 1000},
		{1000, 1000, 1001},
		{1000, 2000, 2001},
		{1000, 1 << 31, 1<<31 + 1},
		{1 << 40, 5, 1 << 40},
	}
	for _, c := range cases {
		got := NextNumber(time.UnixMilli(c.nowMS), c.previous)
		if got != c.want {
			t.Errorf("NextNumber(%d, %d) = %d, want %d", c.nowMS, c.previous, got, c.want)
		}
	}
}

func TestCreateAndCheckCRL(t *testing.T) {
	f := buildChain(t, chainOpts{})
	now := fixtureBase
	serials := []*big.Int{big.NewInt(7), big.NewInt(255)}
	der, err := CreateCRL(f.inter, f.interKey, 42, now, serials)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := ParseCRL(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCRL(crl, f.inter); err != nil {
		t.Fatalf("CheckCRL: %v", err)
	}
	if CRLNumber(crl) != 42 {
		t.Errorf("number = %d", CRLNumber(crl))
	}
	if len(crl.RevokedCertificateEntries) != 2 ||
		crl.RevokedCertificateEntries[0].SerialNumber.Cmp(big.NewInt(7)) != 0 ||
		crl.RevokedCertificateEntries[1].SerialNumber.Cmp(big.NewInt(255)) != 0 {
		t.Errorf("entries = %v", crl.RevokedCertificateEntries)
	}
	if !crl.ThisUpdate.Equal(now) || !crl.NextUpdate.Equal(f.inter.NotAfter) {
		t.Errorf("this %v next %v", crl.ThisUpdate, crl.NextUpdate)
	}
	for _, e := range crl.RevokedCertificateEntries {
		if !e.RevocationTime.Equal(now) {
			t.Errorf("revocation time %v", e.RevocationTime)
		}
	}

	other := buildChain(t, chainOpts{})
	if err := CheckCRL(crl, other.inter); err == nil {
		t.Error("CheckCRL accepted a CRL signed by another intermediate")
	}

	// The issuer expired before "this update".
	late := f.inter.NotAfter.Add(time.Hour)
	der2, err := CreateCRL(f.inter, f.interKey, 43, late, nil)
	if err != nil {
		t.Fatal(err)
	}
	crl2, err := ParseCRL(der2)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCRL(crl2, f.inter); err == nil {
		t.Error("CheckCRL accepted an issuer expired at this update")
	}
	// ... and not yet valid.
	early := f.inter.NotBefore.Add(-time.Hour)
	der3, err := CreateCRL(f.inter, f.interKey, 44, early, nil)
	if err != nil {
		t.Fatal(err)
	}
	crl3, err := ParseCRL(der3)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCRL(crl3, f.inter); err == nil {
		t.Error("CheckCRL accepted an issuer not yet valid at this update")
	}

	// The root signs a CRL too.
	rder, err := CreateCRL(f.root, f.rootKey, 1, now, []*big.Int{f.inter.SerialNumber})
	if err != nil {
		t.Fatal(err)
	}
	rcrl, err := ParseCRL(rder)
	if err != nil {
		t.Fatal(err)
	}
	if err := CheckCRL(rcrl, f.root); err != nil {
		t.Fatalf("root CRL: %v", err)
	}
	if err := CheckCRL(rcrl, f.inter); err == nil {
		t.Error("root CRL checked against the intermediate")
	}
}

func TestParseCRLRefusesNoNumber(t *testing.T) {
	f := buildChain(t, chainOpts{})
	der := crlWithoutNumber(t, f)
	if _, err := ParseCRL(der); err == nil {
		t.Error("ParseCRL accepted a CRL without a number")
	}
	if _, err := ParseCRL([]byte("junk")); err == nil {
		t.Error("ParseCRL accepted junk")
	}
}

// crlWithoutNumber hand-encodes and signs an empty CRL with no CRL number
// extension (Go's own encoder insists on one).
func crlWithoutNumber(t *testing.T, f chainFixture) []byte {
	t.Helper()
	sigAlg := pkix.AlgorithmIdentifier{Algorithm: asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}}
	tbs := struct {
		Version    int
		Signature  pkix.AlgorithmIdentifier
		Issuer     asn1.RawValue
		ThisUpdate time.Time `asn1:"utc"`
		NextUpdate time.Time `asn1:"utc"`
	}{1, sigAlg, asn1.RawValue{FullBytes: f.inter.RawSubject}, fixtureBase, f.inter.NotAfter}
	tbsDER, err := asn1.Marshal(tbs)
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(tbsDER)
	sig, err := ecdsa.SignASN1(rand.Reader, f.interKey, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	der, err := asn1.Marshal(struct {
		TBS    asn1.RawValue
		SigAlg pkix.AlgorithmIdentifier
		Sig    asn1.BitString
	}{asn1.RawValue{FullBytes: tbsDER}, sigAlg, asn1.BitString{Bytes: sig, BitLength: len(sig) * 8}})
	if err != nil {
		t.Fatal(err)
	}
	return der
}
