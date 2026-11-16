package cmd

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
)

// TestOutsideCAProfileAccepted is section 4.2's outside-CA profile: an
// intermediate an RSA root signed with plain x509.CreateCertificate, carrying
// exactly what the profile lists (CA, path length 0, the certificate and CRL
// signing usages, a subject key identifier, an ECDSA P-256 key, the installation
// name as the common name, the agentmesh extended key usage) and also an
// organization name and a non-critical extended key usage extension, is
// installed by `ca install` and the server starts on it. The same certificate
// without the usage, and with another name, is refused.
func TestOutsideCAProfileAccepted(t *testing.T) {
	e := newCAEnv(t)
	now := time.Now()

	rootKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	rootTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "outside root", Organization: []string{"Example Corp"}},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	rootDER, err := x509.CreateCertificate(rand.Reader, rootTmpl, rootTmpl, &rootKey.PublicKey, rootKey)
	if err != nil {
		t.Fatal(err)
	}
	root, err := x509.ParseCertificate(rootDER)
	if err != nil {
		t.Fatal(err)
	}
	rootFile := writeTemp(t, "outside-root.pem", pki.EncodePEM("CERTIFICATE", rootDER))

	pub := keyOf(t, e.f.KeyFile).Public()
	ski, err := pki.SubjectKeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	profile := func(name string, withUsage bool) *x509.Certificate {
		tmpl := &x509.Certificate{
			SerialNumber:          big.NewInt(time.Now().UnixNano()),
			Subject:               pkix.Name{CommonName: name, Organization: []string{"Example Corp"}},
			NotBefore:             now.Add(-time.Minute),
			NotAfter:              now.Add(24 * time.Hour),
			KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
			BasicConstraintsValid: true,
			IsCA:                  true,
			MaxPathLen:            0,
			MaxPathLenZero:        true,
			SubjectKeyId:          ski,
		}
		if withUsage {
			tmpl.UnknownExtKeyUsage = []asn1.ObjectIdentifier{pki.ExtKeyUsageAgentmesh} // Go writes the extension as not critical
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, root, pub, rootKey)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	settings := []string{
		"root_certificate_file=" + rootFile, "installation_name=" + e.f.Installation, "intermediate_key_file=" + e.f.KeyFile,
	}
	install := func(c *x509.Certificate) (int, string) {
		args := []string{}
		for _, s := range settings {
			args = append(args, "-set", s)
		}
		code, _, errOut := e.run(append(args, "ca", "install", certFile(t, c))...)
		return code, errOut
	}

	good := profile(e.f.Installation, true)
	if good.Subject.Organization[0] != "Example Corp" {
		t.Fatalf("the test certificate has no organization: %v", good.Subject)
	}
	for _, ext := range good.Extensions {
		if ext.Id.Equal(asn1.ObjectIdentifier{2, 5, 29, 37}) && ext.Critical {
			t.Fatal("the extended key usage extension is critical")
		}
	}
	for name, c := range map[string]struct {
		cert *x509.Certificate
		text string
	}{
		"without the usage": {profile(e.f.Installation, false), "lacks the agentmesh extended key usage"},
		"another name":      {profile("another-installation", true), `names installation "another-installation"`},
	} {
		code, errOut := install(c.cert)
		if code != 2 || !strings.Contains(errOut, c.text) {
			t.Errorf("%s: exit %d, stderr %q, want exit 2 naming %q", name, code, errOut, c.text)
		}
	}
	if n := len(e.rows(store.TrustIntermediate)); n != 0 {
		t.Fatalf("a refused certificate left %d rows", n)
	}

	if code, errOut := install(good); code != 0 {
		t.Fatalf("ca install of the outside CA's certificate: exit %d: %s", code, errOut)
	}
	if n := len(e.rows(store.TrustIntermediate)); n != 1 {
		t.Fatalf("%d intermediate rows after the install, want 1", n)
	}

	args := []string{"-listen", "127.0.0.1:0", "-sqlite", e.file, "-set", "issuer=http://agentmesh.local"}
	for _, s := range settings {
		args = append(args, "-set", s)
	}
	srv := launch(t, nil, args...).waitReady()
	defer srv.stop()
	if n := leafRows(t, e.file); n != 1 {
		t.Fatalf("leaf rows = %d, want 1", n)
	}
	_, tok := registerAndMint(t, srv, "pat")
	if code, body := httpDo(t, nil, "GET", srv.base()+"/v1/channels", tok.Token); code != 200 {
		t.Fatalf("a bearer signed under the outside CA's chain: %d %s", code, body)
	}
}
