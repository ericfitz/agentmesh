package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"encoding/pem"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/pki"
)

func runCA(t *testing.T, args ...string) (code int, out, errs string) {
	t.Helper()
	var o, e bytes.Buffer
	code = RunCA(context.Background(), args, nil, strings.NewReader(""), &o, &e)
	return code, o.String(), e.String()
}

func caNewCSR(t *testing.T, name string) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := pki.NewRequest(key, name)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func caWrite(t *testing.T, dir, file string, b []byte) string {
	t.Helper()
	p := filepath.Join(dir, file)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func caInit(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "root")
	if code, _, errs := runCA(t, "init", "-dir", dir); code != 0 {
		t.Fatalf("init: %d %s", code, errs)
	}
	return dir
}

func TestCAInitSignRevoke(t *testing.T) {
	dir := caInit(t)
	// init's output is checked on a second root so caInit stays quiet.
	d2 := filepath.Join(t.TempDir(), "r2")
	code, out, _ := runCA(t, "init", "-dir", d2, "-name", "my root", "-days", "30")
	if code != 0 || !strings.HasPrefix(out, "root "+filepath.Join(d2, "root.pem")+"\nthumbprint ") {
		t.Fatalf("init = %d %q", code, out)
	}
	csr := caWrite(t, t.TempDir(), "a.csr", pki.EncodePEM("CERTIFICATE REQUEST", caNewCSR(t, "inst-a")))
	code, out, errs := runCA(t, "sign", "-dir", dir, csr)
	if code != 0 || errs != "installation inst-a\n" {
		t.Fatalf("sign = %d %q", code, errs)
	}
	cert, err := pki.ParseCertificatePEM([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	rootPEM, err := os.ReadFile(filepath.Join(dir, "root.pem"))
	if err != nil {
		t.Fatal(err)
	}
	root, err := pki.ParseCertificatePEM(rootPEM)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.CheckIntermediate(cert, root, "inst-a"); err != nil {
		t.Fatal(err)
	}
	certFile := caWrite(t, t.TempDir(), "a.pem", []byte(out))
	code, out, errs = runCA(t, "revoke", "-dir", dir, certFile)
	if code != 0 || errs != "revoked "+pki.Thumbprint(cert.Raw)+"\n" {
		t.Fatalf("revoke = %d %q", code, errs)
	}
	crl, err := pki.ParseCRLPEM([]byte(out))
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.CheckCRL(crl, root); err != nil {
		t.Fatal(err)
	}
	if len(crl.RevokedCertificateEntries) != 1 || crl.RevokedCertificateEntries[0].SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Fatalf("crl entries = %v", crl.RevokedCertificateEntries)
	}
	// A repeat revokes nothing new.
	if code, _, errs = runCA(t, "revoke", "-dir", dir, certFile); code != 0 || errs != "" {
		t.Fatalf("repeat revoke = %d %q", code, errs)
	}
}

func TestCASignRefusals(t *testing.T) {
	dir := caInit(t)
	tmp := t.TempDir()
	first := caWrite(t, tmp, "1.csr", pki.EncodePEM("CERTIFICATE REQUEST", caNewCSR(t, "inst")))
	second := caWrite(t, tmp, "2.csr", pki.EncodePEM("CERTIFICATE REQUEST", caNewCSR(t, "inst")))
	if code, _, errs := runCA(t, "sign", "-dir", dir, first); code != 0 {
		t.Fatalf("first: %d %s", code, errs)
	}
	code, _, errs := runCA(t, "sign", "-dir", dir, second)
	if code != 2 || !strings.Contains(errs, "-same-installation") {
		t.Fatalf("second key = %d %q", code, errs)
	}
	if code, _, errs = runCA(t, "sign", "-dir", dir, "-same-installation", second); code != 0 {
		t.Fatalf("with flag = %d %q", code, errs)
	}
	rk, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	der, err := pki.NewRequest(rk, "rsa-inst")
	if err != nil {
		t.Fatal(err)
	}
	rsaCSR := caWrite(t, tmp, "rsa.csr", pki.EncodePEM("CERTIFICATE REQUEST", der))
	code, _, errs = runCA(t, "sign", "-dir", dir, rsaCSR)
	if code != 2 || !strings.Contains(errs, "rsa") {
		t.Fatalf("rsa = %d %q", code, errs)
	}
}

func TestCAInputs(t *testing.T) {
	dir := caInit(t)
	tmp := t.TempDir()
	der := caNewCSR(t, "inst-crlf")
	crlf := strings.ReplaceAll(string(pki.EncodePEM("CERTIFICATE REQUEST", der)), "\n", "\r\n")
	if code, _, errs := runCA(t, "sign", "-dir", dir, caWrite(t, tmp, "crlf.csr", []byte(crlf))); code != 0 {
		t.Fatalf("crlf = %d %q", code, errs)
	}
	good := pki.EncodePEM("CERTIFICATE REQUEST", caNewCSR(t, "inst-x"))
	bad := append([]byte(nil), caNewCSR(t, "inst-bad")...)
	bad[len(bad)-1] ^= 0xff
	cases := map[string]struct {
		content []byte
		want    string
	}{
		"der":      {caNewCSR(t, "inst-der"), "no PEM block"},
		"two":      {append(append([]byte(nil), good...), good...), "2 PEM blocks"},
		"trailing": {append(append([]byte(nil), good...), []byte("junk\n")...), "trailing text"},
		"badsig":   {pki.EncodePEM("CERTIFICATE REQUEST", bad), "signature"},
		"wrongtyp": {pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), "CERTIFICATE"},
		"empty":    {nil, "no PEM block"},
	}
	for name, c := range cases {
		p := caWrite(t, tmp, name+".csr", c.content)
		code, out, errs := runCA(t, "sign", "-dir", dir, p)
		if code != 2 || out != "" || !strings.Contains(errs, c.want) || !strings.Contains(errs, p) {
			t.Errorf("%s: code %d out %q err %q, want exit 2 naming %q and the file", name, code, out, errs, c.want)
		}
	}
	// revoke reads certificates the same way.
	p := caWrite(t, tmp, "r.pem", []byte("not a certificate\n"))
	if code, _, errs := runCA(t, "revoke", "-dir", dir, p); code != 2 || !strings.Contains(errs, "no PEM block") {
		t.Errorf("revoke garbage = %d %q", code, errs)
	}
	if code, _, errs := runCA(t, "sign", "-dir", dir, filepath.Join(tmp, "missing.csr")); code != 2 || !strings.Contains(errs, "missing.csr") {
		t.Errorf("missing file = %d %q", code, errs)
	}
}

func TestCAUsage(t *testing.T) {
	dir := caInit(t)
	f := caWrite(t, t.TempDir(), "x", nil)
	for _, args := range [][]string{
		nil, {"bogus"}, {"init"}, {"sign", f}, {"revoke", f},
		{"sign", "-dir", dir}, {"revoke", "-dir", dir}, {"sign", "-dir", dir, f, "extra"},
		{"init", "-dir", dir, "-profile", "p"}, {"init", "-dir", dir, "-identity", "i"},
		{"init", "-dir", dir, "-days", "x"},
	} {
		code, out, errs := runCA(t, args...)
		if code != 2 || out != "" || !strings.Contains(errs, "usage: agentmesh ca") {
			t.Errorf("%v: code %d out %q err %q", args, code, out, errs)
		}
	}
	// A directory with no root is a refusal that says so.
	empty := t.TempDir()
	for _, args := range [][]string{{"sign", "-dir", empty, f}, {"revoke", "-dir", empty, f}} {
		code, _, errs := runCA(t, args...)
		if code != 2 || !strings.Contains(errs, empty+" holds no root") {
			t.Errorf("%v: code %d err %q", args, code, errs)
		}
	}
}

func TestCAInitTwice(t *testing.T) {
	dir := caInit(t)
	code, out, errs := runCA(t, "init", "-dir", dir)
	if code != 2 || out != "" || !strings.Contains(errs, "never overwrites") {
		t.Fatalf("second init = %d %q %q", code, out, errs)
	}
}

type failWriter struct{}

func (failWriter) Write([]byte) (int, error) { return 0, errors.New("broken pipe") }

// A standard output write failure is exit 1 with the cause and the way to
// print the result again on standard error; the root tool's state stays
// (issue #44).
func TestCAStdoutWriteFailure(t *testing.T) {
	run := func(args ...string) (int, string) {
		var e bytes.Buffer
		code := RunCA(context.Background(), args, nil, strings.NewReader(""), failWriter{}, &e)
		return code, e.String()
	}
	dir := filepath.Join(t.TempDir(), "root")
	if code, errs := run("init", "-dir", dir); code != 1 || !strings.Contains(errs, "broken pipe") || !strings.Contains(errs, "thumbprint") {
		t.Fatalf("init = %d %q", code, errs)
	}
	csr := caWrite(t, t.TempDir(), "a.csr", pki.EncodePEM("CERTIFICATE REQUEST", caNewCSR(t, "inst-a")))
	code, errs := run("sign", "-dir", dir, csr)
	if code != 1 || !strings.Contains(errs, "broken pipe") || !strings.Contains(errs, "state.json") || !strings.Contains(errs, "run the same command again") {
		t.Fatalf("sign = %d %q", code, errs)
	}
	if strings.Contains(errs, "installation inst-a") {
		t.Fatalf("sign reported success: %q", errs)
	}
	st, err := os.ReadFile(filepath.Join(dir, "state.json"))
	if err != nil || !strings.Contains(string(st), "inst-a") {
		t.Fatalf("the issued certificate is not in state.json: %v", err)
	}
	// The recorded key signs again with no flag and prints.
	if code, out, errs := runCA(t, "sign", "-dir", dir, csr); code != 0 || !strings.Contains(out, "BEGIN CERTIFICATE") {
		t.Fatalf("second sign = %d %q", code, errs)
	}
	_, out, _ := runCA(t, "sign", "-dir", dir, csr)
	certFile := caWrite(t, t.TempDir(), "a.pem", []byte(out))
	code, errs = run("revoke", "-dir", dir, certFile)
	if code != 1 || !strings.Contains(errs, "broken pipe") || !strings.Contains(errs, "root.crl") {
		t.Fatalf("revoke = %d %q", code, errs)
	}
	if code, out, _ := runCA(t, "revoke", "-dir", dir, certFile); code != 0 || !strings.Contains(out, "BEGIN X509 CRL") {
		t.Fatalf("revoke again = %d %q", code, out)
	}
}

// help and version that cannot be written are exit 1 (issue #44).
func TestHelpVersionStdoutFailure(t *testing.T) {
	for _, a := range []string{"help", "version", "-h", "--version"} {
		var e bytes.Buffer
		if code := Main(context.Background(), []string{a}, nil, strings.NewReader(""), failWriter{}, &e); code != 1 || !strings.Contains(e.String(), "broken pipe") {
			t.Errorf("%s: code %d, stderr %q", a, code, e.String())
		}
	}
}
