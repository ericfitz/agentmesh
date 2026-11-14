// Package trusttest is test support for the certificate hierarchy (ADR 0019):
// a root, an intermediate key file and the signed intermediate, each made
// through internal/pki/rootca so a test holds no committed key or certificate.
// It is never linked into a binary (the m4 rule) and does not import
// internal/server/cmd.
package trusttest

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
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
	"github.com/ericfitz/agentmesh/internal/store"
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

// Manager starts a leaf manager over c: it installs the fixture's intermediate
// when c's Store holds none, then calls signingkeys.New with a leaf validity of
// 168 hours. It is fatal on an error.
func (f *Fixture) Manager(t testing.TB, c *core.Core) *signingkeys.Manager {
	t.Helper()
	ctx := context.Background()
	var rows []store.TrustCertificate
	if err := c.Store.Read(ctx, func(ctx context.Context, tx store.Tx) error {
		var err error
		rows, err = tx.TrustCertificates(ctx, store.TrustIntermediate)
		return err
	}); err != nil {
		t.Fatalf("trusttest: %v", err)
	}
	if len(rows) == 0 {
		f.Install(t, c)
	}
	m, err := signingkeys.New(ctx, signingkeys.Options{Trust: f.Trust(c), LeafValidity: 168 * time.Hour})
	if err != nil {
		t.Fatalf("trusttest: manager: %v", err)
	}
	return m
}

// Leaf issues a leaf with the fixture's intermediate key at now for validity and
// inserts its row, as another replica would; tests sign bearers with the key it
// returns. It is fatal on an error.
func (f *Fixture) Leaf(t testing.TB, c *core.Core, now time.Time, validity time.Duration) (ed25519.PrivateKey, *x509.Certificate) {
	t.Helper()
	b, err := os.ReadFile(f.KeyFile)
	if err != nil {
		t.Fatalf("trusttest: %v", err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		t.Fatalf("trusttest: %s holds no PEM block", f.KeyFile)
	}
	k, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Fatalf("trusttest: %v", err)
	}
	inter, ok := k.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("trusttest: the key is %T, want ECDSA", k)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("trusttest: %v", err)
	}
	leaf, err := pki.IssueLeaf(f.Intermediate, inter, pub, now, validity)
	if err != nil {
		t.Fatalf("trusttest: leaf: %v", err)
	}
	err = c.Store.Tx(context.Background(), func(ctx context.Context, tx store.Tx) error {
		_, err := tx.PutTrustCertificate(ctx, store.TrustCertificate{
			Kind: store.TrustLeaf, Thumbprint: pki.Thumbprint(leaf.Raw), DER: leaf.Raw,
			IssuerKey: pki.KeyID(f.Intermediate.SubjectKeyId), NotAfter: leaf.NotAfter.UnixMilli(), CreatedAt: c.NowMs(),
		})
		return err
	})
	if err != nil {
		t.Fatalf("trusttest: leaf row: %v", err)
	}
	return priv, leaf
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

// Sets is the three settings as arguments: "-set", "root_certificate_file=...",
// "-set", "intermediate_key_file=...", "-set", "installation_name=...".
func (f *Fixture) Sets() []string {
	return []string{
		"-set", "root_certificate_file=" + f.RootFile,
		"-set", "intermediate_key_file=" + f.KeyFile,
		"-set", "installation_name=" + f.Installation,
	}
}
