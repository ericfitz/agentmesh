package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"
)

type fixture struct {
	now     time.Time
	root    *x509.Certificate
	rootKey *ecdsa.PrivateKey
	inter   *x509.Certificate
	interK  *ecdsa.PrivateKey
}

func p256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{now: time.Now().UTC().Truncate(time.Second)}
	f.rootKey = p256(t)
	var err error
	f.root, err = NewRoot(f.rootKey, "test root", f.now.Add(-time.Hour), f.now.Add(10*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	f.interK = p256(t)
	f.inter, err = IssueIntermediate(f.root, f.rootKey, f.request(t, f.interK, "prod"), f.now.Add(-time.Hour), f.now.Add(5*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func (f *fixture) request(t *testing.T, key *ecdsa.PrivateKey, name string) *x509.CertificateRequest {
	t.Helper()
	der, err := NewRequest(key, name)
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return csr
}

func (f *fixture) leaf(t *testing.T, now time.Time, validity time.Duration) *x509.Certificate {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := IssueLeaf(f.inter, f.interK, pub, now, validity)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func noNames(t *testing.T, c *x509.Certificate) {
	t.Helper()
	if len(c.DNSNames)+len(c.IPAddresses)+len(c.EmailAddresses)+len(c.URIs) != 0 {
		t.Errorf("%s carries a name", c.Subject)
	}
	for _, u := range c.ExtKeyUsage {
		t.Errorf("%s carries the standard usage %d", c.Subject, u)
	}
}

func TestRootProfile(t *testing.T) {
	f := newFixture(t)
	c := f.root
	if !c.IsCA || !c.BasicConstraintsValid {
		t.Error("root is not a CA")
	}
	if c.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("key usage = %b", c.KeyUsage)
	}
	if want, _ := SubjectKeyID(f.rootKey.Public()); string(c.SubjectKeyId) != string(want) {
		t.Error("subject key identifier is not SubjectKeyID of the key")
	}
	if len(c.ExtKeyUsage)+len(c.UnknownExtKeyUsage) != 0 {
		t.Error("root has an extended key usage")
	}
	if c.Subject.CommonName != "test root" {
		t.Errorf("CN = %q", c.Subject.CommonName)
	}
	noNames(t, c)
	if err := c.CheckSignatureFrom(c); err != nil {
		t.Errorf("not self-signed: %v", err)
	}
}

func TestIntermediateProfile(t *testing.T) {
	f := newFixture(t)
	c := f.inter
	if !c.IsCA || !c.BasicConstraintsValid || c.MaxPathLen != 0 || !c.MaxPathLenZero {
		t.Errorf("basic constraints: CA %v, path length %d zero %v", c.IsCA, c.MaxPathLen, c.MaxPathLenZero)
	}
	if c.KeyUsage != x509.KeyUsageCertSign|x509.KeyUsageCRLSign {
		t.Errorf("key usage = %b", c.KeyUsage)
	}
	for _, e := range c.Extensions {
		if (e.Id.Equal([]int{2, 5, 29, 19}) || e.Id.Equal([]int{2, 5, 29, 15})) && !e.Critical {
			t.Errorf("extension %v is not critical", e.Id)
		}
	}
	if string(c.AuthorityKeyId) != string(f.root.SubjectKeyId) || len(c.SubjectKeyId) != 20 {
		t.Error("key identifiers wrong")
	}
	if !HasAgentmeshUsage(c) {
		t.Error("no agentmesh usage")
	}
	if c.Subject.CommonName != "prod" {
		t.Errorf("CN = %q", c.Subject.CommonName)
	}
	if err := c.CheckSignatureFrom(f.root); err != nil {
		t.Error(err)
	}
	noNames(t, c)

	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, key := range map[string]crypto.Signer{"rsa": rsaKey, "p384": p384} {
		der, err := NewRequest(key, "prod")
		if err != nil {
			t.Fatal(err)
		}
		csr, err := ParseRequest(der)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := IssueIntermediate(f.root, f.rootKey, csr, f.now, f.now.Add(time.Hour)); !errors.Is(err, ErrRequestKey) {
			t.Errorf("%s: err = %v, want ErrRequestKey", name, err)
		}
	}
}

func TestLeafProfile(t *testing.T) {
	f := newFixture(t)
	c := f.leaf(t, f.now, 24*time.Hour)
	if c.IsCA || !c.BasicConstraintsValid {
		t.Error("leaf basic constraints wrong")
	}
	for _, e := range c.Extensions {
		if (e.Id.Equal([]int{2, 5, 29, 19}) || e.Id.Equal([]int{2, 5, 29, 15})) && !e.Critical {
			t.Errorf("extension %v is not critical", e.Id)
		}
	}
	if c.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Errorf("key usage = %b", c.KeyUsage)
	}
	if string(c.AuthorityKeyId) != string(f.inter.SubjectKeyId) || len(c.SubjectKeyId) != 20 {
		t.Error("key identifiers wrong")
	}
	if c.SerialNumber.Sign() <= 0 || c.SerialNumber.BitLen() > 128 {
		t.Errorf("serial %s is not a positive 128-bit number", c.SerialNumber)
	}
	if other := f.leaf(t, f.now, 24*time.Hour); other.SerialNumber.Cmp(c.SerialNumber) == 0 {
		t.Error("two leaves share a serial number")
	}
	if !HasAgentmeshUsage(c) {
		t.Error("no agentmesh usage")
	}
	if !c.NotBefore.Equal(f.now.Add(-LeafBackdate)) || !c.NotAfter.Equal(f.now.Add(24*time.Hour)) {
		t.Errorf("validity %s to %s", c.NotBefore, c.NotAfter)
	}
	if _, ok := c.PublicKey.(ed25519.PublicKey); !ok {
		t.Errorf("key is %T", c.PublicKey)
	}
	if err := c.CheckSignatureFrom(f.inter); err != nil {
		t.Error(err)
	}
	noNames(t, c)
}

func TestLeafNotAfterCut(t *testing.T) {
	f := newFixture(t)
	f.inter.NotAfter = f.now.Add(time.Hour) // the cut reads only the parsed value
	c := f.leaf(t, f.now, 168*time.Hour)
	if !c.NotAfter.Equal(f.inter.NotAfter) {
		t.Errorf("not after %s, want %s", c.NotAfter, f.inter.NotAfter)
	}
}

func TestParseRequest(t *testing.T) {
	key := p256(t)
	der, err := NewRequest(key, "prod")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := ParseRequest(der)
	if err != nil || csr.Subject.CommonName != "prod" {
		t.Fatalf("good request: %v, %v", csr, err)
	}

	bad := append([]byte(nil), der...)
	bad[len(bad)-1] ^= 0xff
	if _, err := ParseRequest(bad); err == nil || !strings.Contains(err.Error(), "signature") {
		t.Errorf("flipped signature: %v", err)
	}
	for name, cn := range map[string]string{"empty": "", "Prod": "Prod"} {
		d, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
		if err != nil {
			t.Fatal(err)
		}
		_, err = ParseRequest(d)
		if err == nil {
			t.Fatalf("%s accepted", name)
		}
		t.Logf("%s: %v", name, err)
	}
	if _, err := ParseRequest([]byte("junk")); err == nil {
		t.Error("junk accepted")
	}
	if _, err := NewRequest(key, "Prod"); err == nil {
		t.Error("NewRequest accepted an invalid name")
	}
}

func TestCheckRoot(t *testing.T) {
	f := newFixture(t)
	if err := CheckRoot(f.root); err != nil {
		t.Errorf("NewRoot root: %v", err)
	}
	selfSign := func(key crypto.Signer, tmpl *x509.Certificate) *x509.Certificate {
		tmpl.SerialNumber = big.NewInt(1)
		tmpl.NotBefore, tmpl.NotAfter = f.now.Add(-48*time.Hour), f.now.Add(-24*time.Hour)
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	ca := func(ku x509.KeyUsage) *x509.Certificate {
		return &x509.Certificate{BasicConstraintsValid: true, IsCA: true, KeyUsage: ku}
	}
	for name, c := range map[string]*x509.Certificate{
		"rsa, expired":     selfSign(rsaKey, ca(x509.KeyUsageCertSign)),
		"no key usage":     selfSign(p256(t), ca(0)),
		"cert sign + more": selfSign(p256(t), ca(x509.KeyUsageCertSign|x509.KeyUsageDigitalSignature)),
	} {
		if err := CheckRoot(c); err != nil {
			t.Errorf("%s refused: %v", name, err)
		}
	}
	for name, c := range map[string]*x509.Certificate{
		"CA false":             selfSign(p256(t), &x509.Certificate{BasicConstraintsValid: true, KeyUsage: x509.KeyUsageDigitalSignature}),
		"no sign bit":          selfSign(p256(t), ca(x509.KeyUsageCRLSign)),
		"no basic constraints": selfSign(p256(t), &x509.Certificate{KeyUsage: x509.KeyUsageCertSign}),
	} {
		if err := CheckRoot(c); err == nil {
			t.Errorf("%s accepted", name)
		}
	}
}

func TestIssueLeafRefusesBadValidity(t *testing.T) {
	f := newFixture(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, v := range map[string]time.Duration{
		"zero":             0,
		"negative":         -time.Hour,
		"one-over-ceiling": MaxLeafLifetime - LeafBackdate + time.Second,
	} {
		if _, err := IssueLeaf(f.inter, f.interK, pub, f.now, v); !errors.Is(err, ErrLeafValidity) {
			t.Errorf("%s: err = %v, want ErrLeafValidity", name, err)
		}
	}
	c, err := IssueLeaf(f.inter, f.interK, pub, f.now, MaxLeafLifetime-LeafBackdate)
	if err != nil {
		t.Fatalf("the ceiling itself is refused: %v", err)
	}
	if _, err := CheckChain([]*x509.Certificate{c, f.inter}, f.root, "prod"); err != nil {
		t.Fatalf("a leaf at the ceiling does not pass the chain check: %v", err)
	}
}

func TestIssueLeafRefusesInvalidIntermediate(t *testing.T) {
	f := newFixture(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	for name, at := range map[string]time.Time{
		"before-not-before": f.inter.NotBefore.Add(-time.Second),
		"after-not-after":   f.inter.NotAfter.Add(time.Second),
	} {
		if _, err := IssueLeaf(f.inter, f.interK, pub, at, time.Hour); !errors.Is(err, ErrIssuerNotValid) {
			t.Errorf("%s: err = %v, want ErrIssuerNotValid", name, err)
		}
	}
}

func TestIssueLeafExactBoundaries(t *testing.T) {
	f := newFixture(t)
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := IssueLeaf(f.inter, f.interK, pub, f.inter.NotBefore, time.Hour); err != nil {
		t.Errorf("now == NotBefore refused: %v", err)
	}
	c, err := IssueLeaf(f.inter, f.interK, pub, f.inter.NotAfter, time.Hour)
	if err != nil {
		t.Fatalf("now == NotAfter refused: %v", err)
	}
	if !c.NotAfter.Equal(f.inter.NotAfter) {
		t.Errorf("not after %s at the boundary, want the intermediate's %s", c.NotAfter, f.inter.NotAfter)
	}
	// The clamp lands exactly on the intermediate's "not after", from below and
	// from exactly equal.
	for name, v := range map[string]time.Duration{"exact": time.Hour, "over": time.Hour + time.Second} {
		c, err := IssueLeaf(f.inter, f.interK, pub, f.inter.NotAfter.Add(-time.Hour), v)
		if err != nil {
			t.Fatal(err)
		}
		if !c.NotAfter.Equal(f.inter.NotAfter) {
			t.Errorf("%s: not after %s, want %s", name, c.NotAfter, f.inter.NotAfter)
		}
	}
}
