package rootca

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/pki"
)

var t0 = time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)

func newDir(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "root")
	if _, err := Init(dir, "test root", 0, t0); err != nil {
		t.Fatal(err)
	}
	return dir
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func csrFor(t *testing.T, key *ecdsa.PrivateKey, name string) *x509.CertificateRequest {
	t.Helper()
	der, err := pki.NewRequest(key, name)
	if err != nil {
		t.Fatal(err)
	}
	c, err := pki.ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func read(t *testing.T, path string) []byte {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestInit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "root")
	thumb, err := Init(dir, "test root", 100, t0)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range []string{"root.key", "root.pem", "state.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err != nil {
			t.Errorf("%s: %v", f, err)
		}
	}
	root, err := Root(dir)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.CheckRoot(root); err != nil {
		t.Errorf("CheckRoot: %v", err)
	}
	if got := root.NotAfter.Sub(root.NotBefore); got != 100*24*time.Hour {
		t.Errorf("validity %v, want 100 days", got)
	}
	if thumb != pki.Thumbprint(root.Raw) {
		t.Errorf("thumbprint %s, want %s", thumb, pki.Thumbprint(root.Raw))
	}
}

func TestInitDefaultDays(t *testing.T) {
	root, err := Root(newDir(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := root.NotAfter.Sub(root.NotBefore); got != 3650*24*time.Hour {
		t.Errorf("validity %v, want 3650 days", got)
	}
}

func TestInitRefusesExistingRoot(t *testing.T) {
	dir := newDir(t)
	before := read(t, filepath.Join(dir, "root.key"))
	_, err := Init(dir, "again", 0, t0)
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
	if string(read(t, filepath.Join(dir, "root.key"))) != string(before) {
		t.Error("root.key changed")
	}
}

func TestInitAfterDeadRun(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "root.key"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Init(dir, "r", 0, t0)
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "root.key") {
		t.Fatalf("err = %v, want ErrRefused naming root.key", err)
	}
}

func TestInitRejectsNegativeDays(t *testing.T) {
	if _, err := Init(filepath.Join(t.TempDir(), "r"), "r", -1, t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
}

func TestSign(t *testing.T) {
	dir := newDir(t)
	root, _ := Root(dir)
	cert, err := Sign(dir, csrFor(t, newKey(t), "inst-a"), 0, false, t0)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.CheckIntermediate(cert, root, "inst-a"); err != nil {
		t.Errorf("CheckIntermediate: %v", err)
	}
	if got := cert.NotAfter.Sub(cert.NotBefore); got != 365*24*time.Hour {
		t.Errorf("validity %v, want 365 days", got)
	}
	st, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Issued) != 1 || st.Issued[0].Thumbprint != pki.Thumbprint(cert.Raw) || st.Issued[0].Name != "inst-a" {
		t.Errorf("state = %+v", st.Issued)
	}
}

func TestSignRefusals(t *testing.T) {
	dir := newDir(t)
	rsaKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	mk := func(key any) *x509.CertificateRequest {
		der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
			Subject: pkixName("inst-a"),
		}, key)
		if err != nil {
			t.Fatal(err)
		}
		c, err := x509.ParseCertificateRequest(der)
		if err != nil {
			t.Fatal(err)
		}
		return c
	}
	noName := csrFor(t, newKey(t), "inst-a")
	noName.Subject.CommonName = ""
	badName := csrFor(t, newKey(t), "inst-a")
	badName.Subject.CommonName = "Bad Name"
	cases := map[string]*x509.CertificateRequest{
		"empty CN": noName, "bad CN": badName, "RSA": mk(rsaKey), "P-384": mk(p384),
	}
	before := read(t, filepath.Join(dir, "state.json"))
	for name, csr := range cases {
		if _, err := Sign(dir, csr, 0, false, t0); !errors.Is(err, ErrRefused) {
			t.Errorf("%s: err = %v, want ErrRefused", name, err)
		}
	}
	if string(read(t, filepath.Join(dir, "state.json"))) != string(before) {
		t.Error("state.json changed")
	}
}

func TestSignDaysPastRoot(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "r")
	if _, err := Init(dir, "r", 10, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(dir, csrFor(t, newKey(t), "a"), 11, false, t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
}

func TestSignTwice(t *testing.T) {
	dir := newDir(t)
	csr := csrFor(t, newKey(t), "inst-a")
	a, err := Sign(dir, csr, 0, false, t0)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sign(dir, csr, 0, false, t0)
	if err != nil {
		t.Fatal(err)
	}
	if a.SerialNumber.Cmp(b.SerialNumber) == 0 {
		t.Error("same serial number twice")
	}
	if string(a.SubjectKeyId) != string(b.SubjectKeyId) {
		t.Error("subject key identifiers differ")
	}
}

func TestSignNameTaken(t *testing.T) {
	dir := newDir(t)
	k1, k2 := newKey(t), newKey(t)
	if _, err := Sign(dir, csrFor(t, k1, "inst-a"), 0, false, t0); err != nil {
		t.Fatal(err)
	}
	ski, _ := pki.SubjectKeyID(k1.Public())
	statePath := filepath.Join(dir, "state.json")
	before := read(t, statePath)
	_, err := Sign(dir, csrFor(t, k2, "inst-a"), 0, false, t0)
	if !errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), "-same-installation") || !strings.Contains(err.Error(), pki.KeyID(ski)) {
		t.Fatalf("err = %v", err)
	}
	if string(read(t, statePath)) != string(before) {
		t.Error("state.json changed")
	}
	if _, err := Sign(dir, csrFor(t, k2, "inst-a"), 0, true, t0); err != nil {
		t.Errorf("with the flag: %v", err)
	}
	// The flag changes nothing for a new name or the recorded key.
	if _, err := Sign(dir, csrFor(t, newKey(t), "inst-b"), 0, true, t0); err != nil {
		t.Errorf("flag, new name: %v", err)
	}
	if _, err := Sign(dir, csrFor(t, k1, "inst-a"), 0, true, t0); err != nil {
		t.Errorf("flag, recorded key: %v", err)
	}
	// Both keys are recorded now: either renews without the flag.
	if _, err := Sign(dir, csrFor(t, k1, "inst-a"), 0, false, t0); err != nil {
		t.Errorf("renewal of the first key: %v", err)
	}
}

func TestSignNameStaysTakenWhenRevokedOrExpired(t *testing.T) {
	dir := newDir(t)
	k1 := newKey(t)
	cert, err := Sign(dir, csrFor(t, k1, "inst-a"), 1, false, t0)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := Revoke(dir, cert, t0); err != nil {
		t.Fatal(err)
	}
	later := t0.Add(400 * 24 * time.Hour)
	if _, err := Sign(dir, csrFor(t, newKey(t), "inst-a"), 0, false, later); !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
}

func TestRevoke(t *testing.T) {
	dir := newDir(t)
	root, _ := Root(dir)
	kK, kL := newKey(t), newKey(t)
	k1, _ := Sign(dir, csrFor(t, kK, "inst-a"), 0, false, t0)
	k2, _ := Sign(dir, csrFor(t, kK, "inst-a"), 0, false, t0)
	l1, _ := Sign(dir, csrFor(t, kL, "inst-b"), 0, false, t0)
	now := t0.Add(time.Hour)
	der, revoked, err := Revoke(dir, k1, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 2 || revoked[0] != pki.Thumbprint(k1.Raw) || revoked[1] != pki.Thumbprint(k2.Raw) {
		t.Errorf("revoked = %v", revoked)
	}
	crl, err := pki.ParseCRL(der)
	if err != nil {
		t.Fatal(err)
	}
	if err := pki.CheckCRL(crl, root); err != nil {
		t.Errorf("CheckCRL: %v", err)
	}
	got := map[string]bool{}
	for _, e := range crl.RevokedCertificateEntries {
		got[pki.SerialText(e.SerialNumber)] = true
	}
	if len(got) != 2 || !got[pki.SerialText(k1.SerialNumber)] || !got[pki.SerialText(k2.SerialNumber)] || got[pki.SerialText(l1.SerialNumber)] {
		t.Errorf("CRL serials = %v", got)
	}
	if want := pki.NextNumber(now, 0); pki.CRLNumber(crl) != want {
		t.Errorf("number %d, want %d", pki.CRLNumber(crl), want)
	}
	onDisk, err := pki.ParseCRLPEM(read(t, filepath.Join(dir, "root.crl")))
	if err != nil || string(onDisk.Raw) != string(der) {
		t.Errorf("root.crl differs from the returned CRL (%v)", err)
	}
}

func TestRevokeTwice(t *testing.T) {
	dir := newDir(t)
	cert, _ := Sign(dir, csrFor(t, newKey(t), "inst-a"), 0, false, t0)
	first, _, err := Revoke(dir, cert, t0)
	if err != nil {
		t.Fatal(err)
	}
	second, revoked, err := Revoke(dir, cert, t0.Add(time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	if len(revoked) != 0 || string(first) != string(second) {
		t.Errorf("revoked = %v, same bytes = %v", revoked, string(first) == string(second))
	}
}

func TestRevokeCompletesAfterFailedRun(t *testing.T) {
	dir := newDir(t)
	cert, _ := Sign(dir, csrFor(t, newKey(t), "inst-a"), 0, false, t0)
	first, _, err := Revoke(dir, cert, t0)
	if err != nil {
		t.Fatal(err)
	}
	crl, _ := pki.ParseCRL(first)
	// A run died after state.json and before root.crl.
	if err := os.Remove(filepath.Join(dir, "root.crl")); err != nil {
		t.Fatal(err)
	}
	der, revoked, err := Revoke(dir, cert, t0.Add(time.Hour))
	if err != nil || len(revoked) != 0 {
		t.Fatalf("revoked = %v, err = %v", revoked, err)
	}
	again, err := pki.ParseCRL(der)
	if err != nil || pki.CRLNumber(again) != pki.CRLNumber(crl) {
		t.Errorf("number changed: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "root.crl")); err != nil {
		t.Errorf("root.crl not rewritten: %v", err)
	}
}

func TestRevokeClockBack(t *testing.T) {
	dir := newDir(t)
	a, _ := Sign(dir, csrFor(t, newKey(t), "inst-a"), 0, false, t0)
	b, _ := Sign(dir, csrFor(t, newKey(t), "inst-b"), 0, false, t0)
	d1, _, err := Revoke(dir, a, t0)
	if err != nil {
		t.Fatal(err)
	}
	d2, _, err := Revoke(dir, b, t0.Add(-time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	c1, _ := pki.ParseCRL(d1)
	c2, _ := pki.ParseCRL(d2)
	if pki.CRLNumber(c2) != pki.CRLNumber(c1)+1 {
		t.Errorf("numbers %d then %d", pki.CRLNumber(c1), pki.CRLNumber(c2))
	}
}

func TestRevokeUnknown(t *testing.T) {
	dir := newDir(t)
	other := filepath.Join(t.TempDir(), "other")
	if _, err := Init(other, "other", 0, t0); err != nil {
		t.Fatal(err)
	}
	stranger, err := Sign(other, csrFor(t, newKey(t), "inst-a"), 0, false, t0)
	if err != nil {
		t.Fatal(err)
	}
	before := read(t, filepath.Join(dir, "state.json"))
	if _, _, err := Revoke(dir, stranger, t0); !errors.Is(err, ErrRefused) {
		t.Fatalf("err = %v, want ErrRefused", err)
	}
	if string(read(t, filepath.Join(dir, "state.json"))) != string(before) {
		t.Error("state.json changed")
	}
}

func TestLock(t *testing.T) {
	dir := newDir(t)
	old := lockWait
	lockWait = 50 * time.Millisecond
	defer func() { lockWait = old }()
	lock := filepath.Join(dir, "lock")
	if err := os.WriteFile(lock, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Sign(dir, csrFor(t, newKey(t), "inst-a"), 0, false, t0)
	if err == nil || errors.Is(err, ErrRefused) || !strings.Contains(err.Error(), lock) {
		t.Fatalf("err = %v, want a failure naming %s", err, lock)
	}
	if err := os.Remove(lock); err != nil {
		t.Fatal(err)
	}
	if _, err := Sign(dir, csrFor(t, newKey(t), "inst-a"), 0, false, t0); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Errorf("lock left behind: %v", err)
	}
}

func TestConcurrentSign(t *testing.T) {
	dir := newDir(t)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for i := range 8 {
		csr := csrFor(t, newKey(t), fmt.Sprintf("inst-%d", i))
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := Sign(dir, csr, 0, false, t0)
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Error(err)
		}
	}
	st, err := loadState(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(st.Issued) != 8 {
		t.Errorf("recorded %d certificates, want 8", len(st.Issued))
	}
}

func pkixName(cn string) pkix.Name { return pkix.Name{CommonName: cn} }
