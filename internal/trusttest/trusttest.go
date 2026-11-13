// Package trusttest is test support for the certificate hierarchy (ADR 0019):
// a root, an intermediate key file and the signed intermediate, each made
// through internal/pki/rootca so a test holds no committed key or certificate.
// It is never linked into a binary (the m4 rule) and does not import
// internal/server/cmd.
package trusttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/fileacl"
	"github.com/ericfitz/agentmesh/internal/keyprovider"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/pki/rootca"
)

const (
	rootDays         = 3650
	intermediateDays = 365
)

// Fixture is one root and one installation's intermediate.
type Fixture struct {
	Dir          string    // t.TempDir(): the root tool's directory and the files below
	RootFile     string    // root.pem
	KeyFile      string    // the intermediate key, PKCS#8 PEM, mode 0600
	CertFile     string    // the intermediate certificate, PEM
	Installation string    // "test-installation"
	Now          time.Time // the time New was given, or the time it read
	Root         *x509.Certificate
	Intermediate *x509.Certificate

	csr *x509.CertificateRequest // for the key in KeyFile
}

// New makes a root, an intermediate key file and the signed intermediate. now
// is the clock of the test (a fake clock's start); the zero time means
// time.Now(). Root and intermediate are valid from one hour before now
// (rootca.Init and rootca.Sign are called with that time) for 3650 and 365
// days.
func New(t testing.TB, now time.Time) *Fixture {
	t.Helper()
	if now.IsZero() {
		now = time.Now()
	}
	dir := t.TempDir()
	if _, err := rootca.Init(dir, "test root", rootDays, now.Add(-time.Hour)); err != nil {
		t.Fatalf("trusttest: root init: %v", err)
	}
	root, err := rootca.Root(dir)
	if err != nil {
		t.Fatalf("trusttest: %v", err)
	}
	f := &Fixture{Dir: dir, RootFile: filepath.Join(dir, "root.pem"), Now: now, Root: root}
	f.issue(t, "intermediate", "test-installation")
	return f
}

// Sibling is another installation under the same root: its own key, key file
// and name.
func (f *Fixture) Sibling(t testing.TB, installation string) *Fixture {
	t.Helper()
	s := &Fixture{Dir: f.Dir, RootFile: f.RootFile, Now: f.Now, Root: f.Root}
	s.issue(t, installation, installation)
	return s
}

// issue makes the key file base.key, a request for installation, and the
// certificate base.pem.
func (f *Fixture) issue(t testing.TB, base, installation string) {
	t.Helper()
	f.Installation = installation
	f.KeyFile = filepath.Join(f.Dir, base+".key")
	f.CertFile = filepath.Join(f.Dir, base+".pem")
	if err := keyprovider.CreateKeyFile(f.KeyFile, fileacl.OwnerOnly); err != nil {
		t.Fatalf("trusttest: key file: %v", err)
	}
	b, err := os.ReadFile(f.KeyFile)
	if err != nil {
		t.Fatalf("trusttest: %v", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("trusttest: %s holds no PEM block", f.KeyFile)
	}
	priv, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("trusttest: %v", err)
	}
	key, ok := priv.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("trusttest: the key is %T, want ECDSA", priv)
	}
	der, err := pki.NewRequest(key, installation)
	if err != nil {
		t.Fatalf("trusttest: %v", err)
	}
	if f.csr, err = pki.ParseRequest(der); err != nil {
		t.Fatalf("trusttest: %v", err)
	}
	f.Intermediate = f.sign(t, f.Now.Add(-time.Hour), intermediateDays)
	if err := os.WriteFile(f.CertFile, pki.EncodePEM("CERTIFICATE", f.Intermediate.Raw), 0o600); err != nil {
		t.Fatalf("trusttest: %v", err)
	}
}

func (f *Fixture) sign(t testing.TB, at time.Time, days int) *x509.Certificate {
	t.Helper()
	cert, err := rootca.Sign(f.Dir, f.csr, days, false, at)
	if err != nil {
		t.Fatalf("trusttest: sign: %v", err)
	}
	return cert
}

// Trust is the rules over c for this installation: the root, the name and a
// FileProvider that reads the key file with os.ReadFile.
func (f *Fixture) Trust(c *core.Core) signingkeys.Trust {
	return signingkeys.Trust{
		Core:         c,
		Root:         f.Root,
		Installation: f.Installation,
		Provider:     keyprovider.FileProvider{Path: f.KeyFile, Read: os.ReadFile},
	}
}

// Install stores the fixture's intermediate through Trust(c).InstallIntermediate;
// it is fatal on an error.
func (f *Fixture) Install(t testing.TB, c *core.Core) {
	t.Helper()
	if _, err := f.Trust(c).InstallIntermediate(context.Background(), f.Intermediate); err != nil {
		t.Fatalf("trusttest: install: %v", err)
	}
}

// Renew issues another certificate for the same key, valid from at for days.
// A zero at means f.Now.
func (f *Fixture) Renew(t testing.TB, at time.Time, days int) *x509.Certificate {
	t.Helper()
	if at.IsZero() {
		at = f.Now
	}
	return f.sign(t, at, days)
}

// RevokeIntermediate returns the root CRL, dated at, that revokes the key. A
// zero at means f.Now.
func (f *Fixture) RevokeIntermediate(t testing.TB, at time.Time) *x509.RevocationList {
	t.Helper()
	if at.IsZero() {
		at = f.Now
	}
	der, _, err := rootca.Revoke(f.Dir, f.Intermediate, at)
	if err != nil {
		t.Fatalf("trusttest: revoke: %v", err)
	}
	crl, err := pki.ParseCRL(der)
	if err != nil {
		t.Fatalf("trusttest: %v", err)
	}
	return crl
}
