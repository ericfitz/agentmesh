package cmd

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/keyprovider"
	"github.com/ericfitz/agentmesh/internal/keyprovider/kmsfake"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/pki/rootca"
	"github.com/ericfitz/agentmesh/internal/server/config"
	"github.com/ericfitz/agentmesh/internal/store"
	"github.com/ericfitz/agentmesh/internal/trusttest"
)

// caEnv is an admin environment with a root, an installation name and a
// key file configured through -set.
type caEnv struct {
	*adminEnv
	f *trusttest.Fixture
}

func newCAEnv(t *testing.T) *caEnv {
	t.Helper()
	return &caEnv{adminEnv: newAdminEnv(t), f: trusttest.New(t, time.Time{})}
}

func (e *caEnv) settings(keySetting string) []string {
	return []string{
		"-set", "root_certificate_file=" + e.f.RootFile,
		"-set", "installation_name=" + e.f.Installation,
		"-set", keySetting,
	}
}

// ca runs `ca ARGS` with the key file of the fixture.
func (e *caEnv) ca(args ...string) (int, string, string) {
	e.t.Helper()
	return e.caWith("intermediate_key_file="+e.f.KeyFile, args...)
}

func (e *caEnv) caWith(keySetting string, args ...string) (int, string, string) {
	e.t.Helper()
	all := append(e.settings(keySetting), "ca")
	return e.run(append(all, args...)...)
}

func (e *caEnv) core() (*core.Core, store.Store) {
	e.t.Helper()
	_, st := e.service()
	c, err := core.New(st, core.Defaults(), core.Options{})
	if err != nil {
		e.t.Fatal(err)
	}
	return c, st
}

func (e *caEnv) trustNumber() int64 {
	e.t.Helper()
	_, st := e.service()
	return readStore(e.t, st, func(ctx context.Context, tx store.Tx) (int64, error) { return tx.TrustNumber(ctx) })
}

func (e *caEnv) rows(kind string) []store.TrustCertificate {
	e.t.Helper()
	_, st := e.service()
	return readStore(e.t, st, func(ctx context.Context, tx store.Tx) ([]store.TrustCertificate, error) {
		return tx.TrustCertificates(ctx, kind)
	})
}

func writeTemp(t *testing.T, name string, b []byte) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func certFile(t *testing.T, c *x509.Certificate) string {
	return writeTemp(t, "cert.pem", pki.EncodePEM("CERTIFICATE", c.Raw))
}

func crlFile(t *testing.T, crl *x509.RevocationList) string {
	return writeTemp(t, "crl.pem", pki.EncodePEM("X509 CRL", crl.Raw))
}

func wantExit(t *testing.T, got, want int, errOut string) {
	t.Helper()
	if got != want {
		t.Fatalf("exit %d, want %d; stderr %q", got, want, errOut)
	}
}

func TestCACsr(t *testing.T) {
	e := newCAEnv(t)
	key := filepath.Join(t.TempDir(), "new.key")
	set := "intermediate_key_file=" + key
	before := e.trustNumber()

	code, out1, errOut := e.caWith(set, "csr")
	wantExit(t, code, 0, errOut)
	assertOwnerOnlyKey(t, key)
	csr1, err := pki.ParseRequestPEM([]byte(out1))
	if err != nil {
		t.Fatalf("stdout is not a CSR: %v\n%s", err, out1)
	}
	if csr1.Subject.CommonName != e.f.Installation {
		t.Fatalf("CN %q, want %q", csr1.Subject.CommonName, e.f.Installation)
	}

	code, out2, errOut := e.caWith(set, "csr")
	wantExit(t, code, 0, errOut)
	csr2, err := pki.ParseRequestPEM([]byte(out2))
	if err != nil || !csr2.PublicKey.(*ecdsa.PublicKey).Equal(csr1.PublicKey) {
		t.Fatalf("the second run is not a request for the same key: %v", err)
	}

	outFile := filepath.Join(t.TempDir(), "req.pem")
	code, stdout, errOut := e.caWith(set, "csr", "-out", outFile)
	wantExit(t, code, 0, errOut)
	if stdout != "" {
		t.Fatalf("-out left stdout %q", stdout)
	}
	b, err := os.ReadFile(outFile)
	if err != nil {
		t.Fatal(err)
	}
	if csr3, err := pki.ParseRequestPEM(b); err != nil || !csr3.PublicKey.(*ecdsa.PublicKey).Equal(csr1.PublicKey) {
		t.Fatalf("-out file: %v", err)
	}
	if e.trustNumber() != before || len(e.rows(store.TrustIntermediate)) != 0 {
		t.Fatal("csr changed trust_material")
	}
}

func TestCACsrKeyService(t *testing.T) {
	e := newCAEnv(t)
	fake := kmsfake.New("awskms")
	useFake(t, fake)
	k0, err := fake.Next(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	code, out, errOut := e.caWith("intermediate_key_uri=awskms://alias/x", "csr")
	wantExit(t, code, 0, errOut)
	csr, err := pki.ParseRequestPEM([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if !csr.PublicKey.(*ecdsa.PublicKey).Equal(k0.Public) {
		t.Fatal("the request is not under the fake's key")
	}
	k1, _ := fake.Next(context.Background())
	if k1.Ref != k0.Ref {
		t.Fatalf("the fake holds a new key: %s -> %s", k0.Ref, k1.Ref)
	}
}

func TestCAInstall(t *testing.T) {
	now := time.Now()
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	type tc struct {
		name  string
		text  string
		cert  func(e *caEnv) *x509.Certificate
		setup func(t *testing.T, e *caEnv)
	}
	own := func(e *caEnv) crypto.PublicKey { return keyOf(t, e.f.KeyFile).Public() }
	cases := []tc{
		{name: "other-root", text: "does not chain to the pinned root",
			cert: func(e *caEnv) *x509.Certificate { return trusttest.New(t, now).Intermediate }},
		{name: "path-length", text: "is not a CA with path length 0",
			cert: func(e *caEnv) *x509.Certificate {
				return craft(t, e.f, own(e), func(c *x509.Certificate) { c.MaxPathLen = 1; c.MaxPathLenZero = false })
			}},
		{name: "crl-usage", text: "lacks the certificate signing or the CRL signing usage",
			cert: func(e *caEnv) *x509.Certificate {
				return craft(t, e.f, own(e), func(c *x509.Certificate) { c.KeyUsage = x509.KeyUsageCertSign })
			}},
		{name: "no-ski", text: "has no subject key identifier",
			cert: func(e *caEnv) *x509.Certificate {
				return craft(t, e.f, own(e), func(c *x509.Certificate) {
					c.SubjectKeyId = nil
					c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: []byte{0x04, 0x00}})
				})
			}},
		{name: "not-p256", text: "its key is not ECDSA P-256",
			cert: func(e *caEnv) *x509.Certificate { return craft(t, e.f, p384.Public(), nil) }},
		{name: "installation", text: `names installation "other", expected "test-installation"`,
			cert: func(e *caEnv) *x509.Certificate {
				return craft(t, e.f, own(e), func(c *x509.Certificate) { c.Subject.CommonName = "other" })
			}},
		{name: "extended-key-usage", text: "lacks the agentmesh extended key usage",
			cert: func(e *caEnv) *x509.Certificate {
				return craft(t, e.f, own(e), func(c *x509.Certificate) { c.UnknownExtKeyUsage = nil })
			}},
		{name: "not-yet-valid", text: "is not valid now",
			cert: func(e *caEnv) *x509.Certificate { return e.f.Renew(t, now.Add(time.Hour), 30) }},
		{name: "expired", text: "is not valid now",
			cert: func(e *caEnv) *x509.Certificate { return e.f.Renew(t, now.AddDate(-1, 0, 0), 30) }},
		{name: "not-the-configured-key", text: "its public key is not the configured intermediate key",
			cert: func(e *caEnv) *x509.Certificate { return craft(t, e.f, newP256(t).Public(), nil) }},
		{name: "key-revoked", text: "its key is revoked by the stored root CRL",
			setup: func(t *testing.T, e *caEnv) {
				if code, _, errOut := e.ca("install", certFile(t, e.f.Intermediate)); code != 0 {
					t.Fatal(errOut)
				}
				if code, _, errOut := e.ca("install-crl", crlFile(t, e.f.RevokeIntermediate(t, time.Time{}))); code != 0 {
					t.Fatal(errOut)
				}
			},
			cert: func(e *caEnv) *x509.Certificate { return e.f.Renew(t, time.Time{}, 30) }},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newCAEnv(t)
			if c.setup != nil {
				c.setup(t, e)
			}
			before, n := e.trustNumber(), len(e.rows(store.TrustIntermediate))
			code, out, errOut := e.ca("install", certFile(t, c.cert(e)))
			wantExit(t, code, 2, errOut)
			if out != "" || !strings.Contains(errOut, c.text) {
				t.Fatalf("stdout %q, stderr %q; want stderr to contain %q", out, errOut, c.text)
			}
			if e.trustNumber() != before || len(e.rows(store.TrustIntermediate)) != n {
				t.Fatal("a refused install changed the store")
			}
		})
	}

	t.Run("good", func(t *testing.T) {
		e := newCAEnv(t)
		code, out, errOut := e.ca("install", e.f.CertFile)
		wantExit(t, code, 0, errOut)
		want := fmt.Sprintf("installed %s installation %s until %s\n", pki.Thumbprint(e.f.Intermediate.Raw), e.f.Installation, e.f.Intermediate.NotAfter.UTC().Format(time.RFC3339))
		if out != want {
			t.Fatalf("stdout %q, want %q", out, want)
		}
		n := e.trustNumber()
		code, out, errOut = e.ca("install", e.f.CertFile)
		wantExit(t, code, 0, errOut)
		if out != "unchanged "+pki.Thumbprint(e.f.Intermediate.Raw)+"\n" || e.trustNumber() != n {
			t.Fatalf("again: stdout %q, number %d -> %d", out, n, e.trustNumber())
		}
	})

	t.Run("lock-held-is-retryable", func(t *testing.T) {
		e := newCAEnv(t)
		_, st := e.core()
		now := time.Now().UnixMilli()
		if held, err := st.TryLock(context.Background(), signingkeys.LockName, "another-replica", now, now+time.Hour.Milliseconds()); err != nil || !held {
			t.Fatalf("lock: %v %v", held, err)
		}
		code, _, errOut := e.ca("install", e.f.CertFile)
		wantExit(t, code, 1, errOut)
		if !strings.Contains(errOut, "try again") {
			t.Fatalf("stderr %q does not say to retry", errOut)
		}
	})
}

func TestCAInstallCRL(t *testing.T) {
	e := newCAEnv(t)
	sib1, sib2 := e.f.Sibling(t, "other-one"), e.f.Sibling(t, "other-two")
	now := time.Now()
	crl1 := sibRevoke(t, e.f, sib1, now)
	crl2 := sibRevoke(t, e.f, sib2, now.Add(time.Second)) // lists both siblings
	if pki.CRLNumber(crl2) <= pki.CRLNumber(crl1) {
		t.Fatalf("test CRL numbers %d, %d are not increasing", pki.CRLNumber(crl1), pki.CRLNumber(crl2))
	}
	code, out, errOut := e.ca("install-crl", crlFile(t, crl2))
	wantExit(t, code, 0, errOut)
	if want := fmt.Sprintf("installed root-crl %d\n", pki.CRLNumber(crl2)); out != want {
		t.Fatalf("stdout %q, want %q", out, want)
	}
	n := e.trustNumber()
	code, out, errOut = e.ca("install-crl", crlFile(t, crl2))
	wantExit(t, code, 0, errOut)
	if want := fmt.Sprintf("unchanged root-crl %d\n", pki.CRLNumber(crl2)); out != want || e.trustNumber() != n {
		t.Fatalf("again: stdout %q", out)
	}
	code, _, errOut = e.ca("install-crl", crlFile(t, crl1))
	wantExit(t, code, 2, errOut)
	if !strings.Contains(errOut, "is not above the stored") || e.trustNumber() != n {
		t.Fatalf("lower number: stderr %q", errOut)
	}
}

func TestCAStatus(t *testing.T) {
	e := newCAEnv(t)
	sib := e.f.Sibling(t, "other-installation")
	if code, _, errOut := e.ca("install", e.f.CertFile); code != 0 {
		t.Fatal(errOut)
	}
	crl := sibRevoke(t, e.f, sib, time.Now())
	if code, _, errOut := e.ca("install-crl", crlFile(t, crl)); code != 0 {
		t.Fatal(errOut)
	}
	_, st := e.core()
	// A leaf and its issuer's CRL, stored as rows.
	key := keyOf(t, e.f.KeyFile)
	inter := e.f.Intermediate
	leaf := leafUnder(t, inter, key, time.Now(), time.Hour)
	issuer := pki.KeyID(inter.SubjectKeyId)
	leafCRL, err := pki.CreateCRL(inter, key, 7, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := st.Tx(context.Background(), func(ctx context.Context, tx store.Tx) error {
		if _, err := tx.PutTrustCertificate(ctx, store.TrustCertificate{Kind: store.TrustLeaf, Thumbprint: pki.Thumbprint(leaf.Raw), DER: leaf.Raw, IssuerKey: issuer, NotAfter: leaf.NotAfter.UnixMilli(), CreatedAt: time.Now().UnixMilli()}); err != nil {
			return err
		}
		return tx.PutCRL(ctx, store.TrustCRL{Kind: store.TrustLeafCRL, Thumbprint: pki.Thumbprint(leafCRL), DER: leafCRL, IssuerKey: issuer, Number: 7, CreatedAt: time.Now().UnixMilli()})
	}); err != nil {
		t.Fatal(err)
	}

	code, out, errOut := e.ca("status")
	wantExit(t, code, 0, errOut)
	rfc := func(tm time.Time) string { return tm.UTC().Format(time.RFC3339) }
	want := []string{
		fmt.Sprintf("root %s until %s", pki.Thumbprint(e.f.Root.Raw), rfc(e.f.Root.NotAfter)),
		"installation " + e.f.Installation,
		fmt.Sprintf("intermediate %s %s %s key=configured revoked=no", pki.Thumbprint(inter.Raw), rfc(inter.NotBefore), rfc(inter.NotAfter)),
		fmt.Sprintf("root-crl %d", pki.CRLNumber(crl)),
		fmt.Sprintf("leaf-crl %s 7", issuer),
		fmt.Sprintf("trust-number %d", e.trustNumber()),
		fmt.Sprintf("leaf %s serial %s until %s", pki.Thumbprint(leaf.Raw), leaf.SerialNumber.Text(16), rfc(leaf.NotAfter)),
	}
	if got := strings.Split(strings.TrimSuffix(out, "\n"), "\n"); strings.Join(got, "\n") != strings.Join(want, "\n") {
		t.Fatalf("status:\n%s\nwant:\n%s", out, strings.Join(want, "\n"))
	}

	t.Run("another-key", func(t *testing.T) {
		// A second intermediate of another key (the sibling's, renamed by a
		// sibling with this installation's name) reads key=other.
		otherKey := filepath.Join(t.TempDir(), "other.key")
		if err := keyprovider.CreateKeyFile(otherKey, func(string) error { return nil }); err != nil {
			t.Fatal(err)
		}
		otherCert := craft(t, e.f, keyOf(t, otherKey).Public(), nil)
		c, _ := e.core()
		tr := signingkeys.Trust{Core: c, Root: e.f.Root, Installation: e.f.Installation,
			Provider: keyprovider.FileProvider{Path: otherKey, Read: os.ReadFile}}
		if _, err := tr.InstallIntermediate(context.Background(), otherCert); err != nil {
			t.Fatal(err)
		}
		_, out, errOut := e.ca("status")
		if !strings.Contains(out, pki.Thumbprint(otherCert.Raw)+" ") || strings.Count(out, "key=other") != 1 || strings.Count(out, "key=configured") != 1 {
			t.Fatalf("status %q (stderr %q)", out, errOut)
		}
	})

	t.Run("revoked", func(t *testing.T) {
		e2 := newCAEnv(t)
		if code, _, errOut := e2.ca("install", e2.f.CertFile); code != 0 {
			t.Fatal(errOut)
		}
		if code, _, errOut := e2.ca("install-crl", crlFile(t, e2.f.RevokeIntermediate(t, time.Time{}))); code != 0 {
			t.Fatal(errOut)
		}
		_, out, _ := e2.ca("status")
		if !strings.Contains(out, "key=configured revoked=yes") {
			t.Fatalf("status %q", out)
		}
	})

	t.Run("empty-store", func(t *testing.T) {
		e3 := newCAEnv(t)
		code, out, errOut := e3.ca("status")
		wantExit(t, code, 0, errOut)
		if !regexp.MustCompile(`(?m)^root-crl none$`).MatchString(out) || strings.Contains(out, "intermediate ") {
			t.Fatalf("status %q", out)
		}
	})

	t.Run("missing-key-file", func(t *testing.T) {
		missing := filepath.Join(t.TempDir(), "gone.key")
		code, _, errOut := e.caWith("intermediate_key_file="+missing, "status")
		wantExit(t, code, 2, errOut)
		if !strings.Contains(errOut, missing) {
			t.Fatalf("stderr %q does not name the key file", errOut)
		}
		// With no stored intermediate the key file is not read.
		e3 := newCAEnv(t)
		code, _, errOut = e3.caWith("intermediate_key_file="+missing, "status")
		wantExit(t, code, 0, errOut)
	})
}

func TestCAStatusKeyService(t *testing.T) {
	e := newCAEnv(t)
	aws, gcp := kmsfake.New("awskms"), kmsfake.New("gcpkms")
	useFake(t, aws)
	setBackend(t, "gcpkms", func(string) (keyprovider.Provider, error) { return gcp, nil })
	c, _ := e.core()
	for _, fk := range []*kmsfake.Fake{aws, gcp} {
		k, err := fk.Next(context.Background())
		if err != nil {
			t.Fatal(err)
		}
		tr := signingkeys.Trust{Core: c, Root: e.f.Root, Installation: e.f.Installation, Provider: fk}
		if _, err := tr.InstallIntermediate(context.Background(), craft(t, e.f, k.Public, nil)); err != nil {
			t.Fatal(err)
		}
	}
	calls := aws.Calls() + gcp.Calls()
	code, out, errOut := e.caWith("intermediate_key_uri=awskms://alias/x", "status")
	wantExit(t, code, 0, errOut)
	if strings.Count(out, "key=configured") != 1 || strings.Count(out, "key=other") != 1 {
		t.Fatalf("status %q", out)
	}
	if got := aws.Calls() + gcp.Calls(); got != calls {
		t.Fatalf("status called the key service: %d -> %d", calls, got)
	}
}

func TestCARequiresTrustSettings(t *testing.T) {
	e := newCAEnv(t)
	for _, verb := range []string{"csr", "install", "install-crl", "status"} {
		args := []string{verb}
		if verb == "install" || verb == "install-crl" {
			args = append(args, e.f.CertFile)
		}
		t.Run(verb+"/no-installation-name", func(t *testing.T) {
			code, _, errOut := e.run(append([]string{"-set", "root_certificate_file=" + e.f.RootFile, "-set", "intermediate_key_file=" + e.f.KeyFile, "ca"}, args...)...)
			wantExit(t, code, 2, errOut)
			if !strings.Contains(errOut, "installation_name") {
				t.Fatalf("stderr %q", errOut)
			}
		})
		t.Run(verb+"/no-key-setting", func(t *testing.T) {
			code, _, errOut := e.run(append([]string{"-set", "root_certificate_file=" + e.f.RootFile, "-set", "installation_name=x", "ca"}, args...)...)
			wantExit(t, code, 2, errOut)
			if !strings.Contains(errOut, "intermediate_key_file") || !strings.Contains(errOut, "intermediate_key_uri") {
				t.Fatalf("stderr %q", errOut)
			}
		})
		t.Run(verb+"/no-root", func(t *testing.T) {
			code, _, errOut := e.run(append([]string{"-set", "installation_name=x", "-set", "intermediate_key_file=" + e.f.KeyFile, "ca"}, args...)...)
			wantExit(t, code, 2, errOut)
			if !strings.Contains(errOut, "root_certificate_file") {
				t.Fatalf("stderr %q", errOut)
			}
		})
	}
}

func TestCAUsage(t *testing.T) {
	e := newCAEnv(t)
	for _, args := range [][]string{{}, {"bogus"}, {"install"}, {"install", "a", "b"}, {"status", "x"}, {"csr", "-nope"}} {
		code, _, errOut := e.run(append([]string{"ca"}, args...)...)
		wantExit(t, code, 2, errOut)
	}
}

func TestCAInputs(t *testing.T) {
	e := newCAEnv(t)
	pemBytes := pki.EncodePEM("CERTIFICATE", e.f.Intermediate.Raw)
	crlf := []byte(strings.ReplaceAll(string(pemBytes), "\n", "\r\n"))
	cases := []struct {
		name string
		file []byte
		code int
	}{
		{"der", e.f.Intermediate.Raw, 2},
		{"two-certificates", append(append([]byte{}, pemBytes...), pemBytes...), 2},
		{"empty", nil, 2},
		{"crl-in-place-of-certificate", pki.EncodePEM("X509 CRL", e.f.Intermediate.Raw), 2},
		{"crlf", crlf, 0},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, _, errOut := e.ca("install", writeTemp(t, "in.pem", c.file))
			wantExit(t, code, c.code, errOut)
		})
	}
	if code, _, errOut := e.ca("install", filepath.Join(t.TempDir(), "absent.pem")); code != 2 {
		t.Fatalf("a missing file: exit %d, stderr %q", code, errOut)
	}
	if code, _, errOut := e.ca("install-crl", writeTemp(t, "crl.pem", pemBytes)); code != 2 {
		t.Fatalf("a certificate as a CRL: exit %d, stderr %q", code, errOut)
	}
}

func TestOpenRoot(t *testing.T) {
	f := trusttest.New(t, time.Time{})
	cfg := func(path string) (c config.Config) { c.RootCertificateFile = path; return }
	if _, err := openRoot(cfg(f.RootFile)); err != nil {
		t.Fatalf("the good root: %v", err)
	}
	rootPEM := pki.EncodePEM("CERTIFICATE", f.Root.Raw)
	// the intermediate is a CA, so use a leaf as the certificate that is not one
	leaf := leafUnder(t, f.Intermediate, keyOf(t, f.KeyFile), time.Now(), time.Hour)
	notCA := writeTemp(t, "leaf.pem", pki.EncodePEM("CERTIFICATE", leaf.Raw))
	for name, path := range map[string]string{
		"unreadable": filepath.Join(t.TempDir(), "absent.pem"),
		"two":        writeTemp(t, "two.pem", append(append([]byte{}, rootPEM...), rootPEM...)),
		"not-a-ca":   notCA,
		"der":        writeTemp(t, "root.der", f.Root.Raw),
	} {
		_, err := openRoot(cfg(path))
		if err == nil || !strings.Contains(err.Error(), "root_certificate_file") {
			t.Errorf("%s: error %v does not name root_certificate_file", name, err)
		}
	}
	// An outside CA's root of RSA is accepted.
	rsaRoot := rsaRootPEM(t)
	if _, err := openRoot(cfg(writeTemp(t, "rsa.pem", rsaRoot))); err != nil {
		t.Fatalf("RSA root: %v", err)
	}
}

func rsaRootPEM(t *testing.T) []byte {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "outside root"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		BasicConstraintsValid: true, IsCA: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
}

// TestCACsrKeyFileIsOwnerOnly is the wiring of keyprovider.CreateKeyFile with
// fileacl.OwnerOnly: the file ca csr creates ends owner-only on every OS.
func TestCACsrKeyFileIsOwnerOnly(t *testing.T) {
	e := newCAEnv(t)
	key := filepath.Join(t.TempDir(), "wired.key")
	if code, _, errOut := e.caWith("intermediate_key_file="+key, "csr"); code != 0 {
		t.Fatal(errOut)
	}
	assertOwnerOnlyKey(t, key)
	if _, err := readOwnerOnly(key); err != nil {
		t.Fatalf("the key the command made is refused by the reader: %v", err)
	}
}

// helpers ---------------------------------------------------------------

func keyOf(t *testing.T, path string) *ecdsa.PrivateKey {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		t.Fatalf("%s: no PEM block", path)
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return k.(*ecdsa.PrivateKey)
}

func rootKeyOf(t *testing.T, f *trusttest.Fixture) *ecdsa.PrivateKey {
	return keyOf(t, filepath.Join(f.Dir, "root.key"))
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// craft signs an intermediate for pub under f's root with the profile of a
// good one, after mod changed the template.
func craft(t *testing.T, f *trusttest.Fixture, pub crypto.PublicKey, mod func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	ski, err := pki.SubjectKeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	sn, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn.Add(sn, big.NewInt(1)),
		Subject:               pkix.Name{CommonName: f.Installation},
		NotBefore:             f.Now.Add(-time.Hour),
		NotAfter:              f.Now.Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{pki.ExtKeyUsageAgentmesh},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski,
		AuthorityKeyId:        f.Root.SubjectKeyId,
	}
	if mod != nil {
		mod(tmpl)
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.Root, pub, rootKeyOf(t, f))
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func leafUnder(t *testing.T, inter *x509.Certificate, key *ecdsa.PrivateKey, now time.Time, v time.Duration) *x509.Certificate {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	c, err := pki.IssueLeaf(inter, key, pub, now, v)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// sibRevoke returns a root CRL dated at that revokes the sibling's key only.
func sibRevoke(t *testing.T, f, sib *trusttest.Fixture, at time.Time) *x509.RevocationList {
	t.Helper()
	der, _, err := rootca.Revoke(f.Dir, sib.Intermediate, at, trusttest.NoCheck)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := pki.ParseCRL(der)
	if err != nil {
		t.Fatal(err)
	}
	return crl
}

func TestCAStatusNamesIgnoredIntermediates(t *testing.T) {
	e := newCAEnv(t)
	if code, _, errOut := e.ca("install", e.f.CertFile); code != 0 {
		t.Fatal(errOut)
	}
	all := append([]string{"-set", "root_certificate_file=" + e.f.RootFile, "-set", "installation_name=renamed",
		"-set", "intermediate_key_file=" + e.f.KeyFile, "ca"}, "status")
	code, out, errOut := e.run(all...)
	wantExit(t, code, 0, errOut)
	want := fmt.Sprintf("ignored intermediate %s: ", pki.Thumbprint(e.f.Intermediate.Raw))
	if !strings.Contains(out, want) || !strings.Contains(out, `names installation "test-installation", expected "renamed"`) {
		t.Fatalf("status %q lacks %q and its reason", out, want)
	}
	if strings.Contains(out, "intermediate "+pki.Thumbprint(e.f.Intermediate.Raw)+" ") {
		t.Fatalf("an ignored row is listed as verified: %q", out)
	}
}

func TestCAFailuresAreExit1(t *testing.T) {
	t.Run("out-file-unwritable", func(t *testing.T) {
		e := newCAEnv(t)
		bad := filepath.Join(t.TempDir(), "no-such-dir", "req.pem")
		code, _, errOut := e.ca("csr", "-out", bad)
		wantExit(t, code, 1, errOut)
	})
	t.Run("csr-key-service-down", func(t *testing.T) {
		e := newCAEnv(t)
		fake := kmsfake.New("awskms")
		fake.SetDown(true)
		useFake(t, fake)
		code, _, errOut := e.caWith("intermediate_key_uri=awskms://alias/x", "csr")
		wantExit(t, code, 1, errOut)
	})
	t.Run("backend-unreachable", func(t *testing.T) {
		setBackend(t, "awskms", func(string) (keyprovider.Provider, error) {
			return nil, fmt.Errorf("dial: %w", keyprovider.ErrUnavailable)
		})
		for _, verb := range []string{"csr", "status"} {
			e := newCAEnv(t)
			code, _, errOut := e.caWith("intermediate_key_uri=awskms://alias/x", verb)
			wantExit(t, code, 1, errOut)
		}
	})
	t.Run("store-failure", func(t *testing.T) {
		e := newCAEnv(t)
		dir := t.TempDir() // a directory is not a database file
		for _, verb := range []string{"status", "install", "install-crl"} {
			args := append(e.settings("intermediate_key_file="+e.f.KeyFile), "ca", verb)
			if verb != "status" {
				args = append(args, e.f.CertFile)
			}
			code, _, errOut := e.runEnv(nil, append([]string{"-sqlite", dir}, args...)...)
			wantExit(t, code, 1, errOut)
		}
	})
	t.Run("install-crl-lock-held", func(t *testing.T) {
		e := newCAEnv(t)
		sib := e.f.Sibling(t, "other-one")
		_, st := e.core()
		now := time.Now().UnixMilli()
		if held, err := st.TryLock(context.Background(), signingkeys.LockName, "another-replica", now, now+time.Hour.Milliseconds()); err != nil || !held {
			t.Fatalf("lock: %v %v", held, err)
		}
		code, _, errOut := e.ca("install-crl", crlFile(t, sibRevoke(t, e.f, sib, time.Now())))
		wantExit(t, code, 1, errOut)
		if !strings.Contains(errOut, "try again") {
			t.Fatalf("stderr %q does not say to retry", errOut)
		}
	})
}
