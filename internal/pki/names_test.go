package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestThumbprint(t *testing.T) {
	if got, want := Thumbprint([]byte("abc")), "ungWv48Bz-pBQUDeXa4iI7ADYaOWF3qctBD_YfIAFa0"; got != want {
		t.Errorf("Thumbprint = %q, want %q", got, want)
	}
}

func TestValidInstallationName(t *testing.T) {
	for _, ok := range []string{"a", "prod-1", "eu.west-2", "0lab", strings.Repeat("a", 64)} {
		if err := ValidInstallationName(ok); err != nil {
			t.Errorf("%q refused: %v", ok, err)
		}
	}
	for _, bad := range []string{"", strings.Repeat("a", 65), "Prod", "-a", ".a", "a_b", "a b", "é"} {
		if err := ValidInstallationName(bad); err == nil {
			t.Errorf("%q accepted", bad)
		}
	}
}

func TestSerialAndKeyText(t *testing.T) {
	if got := SerialText(big.NewInt(0xabc)); got != "abc" {
		t.Errorf("SerialText = %q", got)
	}
	if got := KeyID([]byte{0x00, 0xAB, 0x0f}); got != "00ab0f" {
		t.Errorf("KeyID = %q", got)
	}
}

func TestSubjectKeyID(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ski, err := SubjectKeyID(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	der, err := x509.MarshalPKIXPublicKey(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(der)
	if len(ski) != 20 || string(ski) != string(sum[:20]) {
		t.Errorf("SubjectKeyID = %x, want %x", ski, sum[:20])
	}
	if _, err := SubjectKeyID("not a key"); err == nil {
		t.Error("unsupported key accepted")
	}

	f := newFixture(t)
	csr := f.request(t, key, "prod")
	a, err := IssueIntermediate(f.root, f.rootKey, csr, f.now, f.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	b, err := IssueIntermediate(f.root, f.rootKey, csr, f.now, f.now.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if string(a.SubjectKeyId) != string(b.SubjectKeyId) || string(a.SubjectKeyId) != string(ski) {
		t.Error("one CSR key gave different subject key identifiers")
	}
	if a.SerialNumber.Cmp(b.SerialNumber) == 0 {
		t.Error("two intermediates share a serial number")
	}
}
