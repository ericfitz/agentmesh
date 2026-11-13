package signingkeys_test

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/pem"
	"errors"
	"log/slog"
	"math/big"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
	"github.com/ericfitz/agentmesh/internal/store/sqlite"
	"github.com/ericfitz/agentmesh/internal/trusttest"
)

const startMs = 1_700_000_000_000

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.t
}

func (c *clock) advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.t = c.t.Add(d)
}

// logBuf captures a core's log.
type logBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *logBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *logBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// env is a Store in a temporary directory, a core on a fake clock, the
// fixture's Trust over it and the memory of one process.
type env struct {
	clk  *clock
	path string
	st   store.Store
	c    *core.Core
	logs *logBuf
	f    *trusttest.Fixture
	tr   signingkeys.Trust
	mem  *signingkeys.Memory
}

func openAt(t *testing.T, path string) store.Store {
	t.Helper()
	s, err := sqlite.Open(context.Background(), path, sqlite.Options{})
	if err != nil {
		t.Fatalf("sqlite.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func newEnv(t *testing.T) *env {
	t.Helper()
	clk := &clock{t: time.UnixMilli(startMs)}
	return newEnvWith(t, clk, trusttest.New(t, clk.now()))
}

func newEnvWith(t *testing.T, clk *clock, f *trusttest.Fixture) *env {
	t.Helper()
	path := filepath.Join(t.TempDir(), "agentmesh.db")
	st := openAt(t, path)
	logs := &logBuf{}
	c, err := core.New(st, core.Defaults(), core.Options{Now: clk.now, Logger: slog.New(slog.NewTextHandler(logs, nil))})
	if err != nil {
		t.Fatal(err)
	}
	return &env{clk: clk, path: path, st: st, c: c, logs: logs, f: f, tr: f.Trust(c), mem: &signingkeys.Memory{}}
}

// second is another Store and core on the same clock and fixture, with its own
// memory shared with e's: what a process sees after its database was rolled back.
func (e *env) second(t *testing.T) *env {
	t.Helper()
	o := newEnvWith(t, e.clk, e.f)
	o.mem = e.mem
	return o
}

func (e *env) nowMs() int64 { return e.clk.now().UnixMilli() }

func (e *env) tx(t *testing.T, fn func(ctx context.Context, tx store.Tx) error) {
	t.Helper()
	if err := e.st.Tx(context.Background(), fn); err != nil {
		t.Fatal(err)
	}
}

func (e *env) load(t *testing.T) signingkeys.Material {
	t.Helper()
	m, err := e.tr.Load(context.Background(), e.mem)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	return m
}

func (e *env) trustNumber(t *testing.T) int64 {
	t.Helper()
	var n int64
	if err := e.st.Read(context.Background(), func(ctx context.Context, tx store.Tx) error {
		var err error
		n, err = tx.TrustNumber(ctx)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return n
}

func (e *env) rows(t *testing.T, kind string) []store.TrustCertificate {
	t.Helper()
	var rows []store.TrustCertificate
	if err := e.st.Read(context.Background(), func(ctx context.Context, tx store.Tx) error {
		var err error
		rows, err = tx.TrustCertificates(ctx, kind)
		return err
	}); err != nil {
		t.Fatal(err)
	}
	return rows
}

func (e *env) putIntermediate(t *testing.T, cert *x509.Certificate, keyRef string) {
	t.Helper()
	e.tx(t, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.PutTrustCertificate(ctx, store.TrustCertificate{
			Kind: store.TrustIntermediate, Thumbprint: pki.Thumbprint(cert.Raw), DER: cert.Raw,
			NotAfter: cert.NotAfter.UnixMilli(), KeyRef: keyRef, CreatedAt: e.nowMs(),
		})
		return err
	})
}

func (e *env) putRow(t *testing.T, row store.TrustCertificate) {
	t.Helper()
	if row.CreatedAt == 0 {
		row.CreatedAt = e.nowMs()
	}
	if row.NotAfter == 0 {
		row.NotAfter = e.nowMs() + 1000
	}
	e.tx(t, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.PutTrustCertificate(ctx, row)
		return err
	})
}

func (e *env) putLeaf(t *testing.T, cert *x509.Certificate, issuerKey string) {
	t.Helper()
	e.putRow(t, store.TrustCertificate{
		Kind: store.TrustLeaf, Thumbprint: pki.Thumbprint(cert.Raw), DER: cert.Raw,
		IssuerKey: issuerKey, NotAfter: cert.NotAfter.UnixMilli(),
	})
}

func (e *env) putCRL(t *testing.T, kind, issuerKey string, der []byte) {
	t.Helper()
	crl, err := pki.ParseCRL(der)
	if err != nil {
		t.Fatal(err)
	}
	e.tx(t, func(ctx context.Context, tx store.Tx) error {
		return tx.PutCRL(ctx, store.TrustCRL{
			Kind: kind, Thumbprint: pki.Thumbprint(der), DER: der, IssuerKey: issuerKey,
			Number: pki.CRLNumber(crl), CreatedAt: e.nowMs(),
		})
	})
}

func (e *env) logged(sub string) bool { return strings.Contains(e.logs.String(), sub) }

func keyID(c *x509.Certificate) string { return pki.KeyID(c.SubjectKeyId) }

func parsePEMKey(t *testing.T, path string) *ecdsa.PrivateKey {
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

func rootKey(t *testing.T, f *trusttest.Fixture) *ecdsa.PrivateKey {
	return parsePEMKey(t, filepath.Join(f.Dir, "root.key"))
}

func interKey(t *testing.T, f *trusttest.Fixture) *ecdsa.PrivateKey {
	return parsePEMKey(t, f.KeyFile)
}

func newP256(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func randSerial(t *testing.T) *big.Int {
	t.Helper()
	n, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 100))
	if err != nil {
		t.Fatal(err)
	}
	return n.Add(n, big.NewInt(1))
}

// craft signs an intermediate for pub under f's root with the profile of a
// good one (valid from an hour before f.Now for a year, named for f's
// installation), after mod changed the template.
func craft(t *testing.T, f *trusttest.Fixture, pub crypto.PublicKey, mod func(*x509.Certificate)) *x509.Certificate {
	t.Helper()
	ski, err := pki.SubjectKeyID(pub)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber:          randSerial(t),
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
	der, err := x509.CreateCertificate(rand.Reader, tmpl, f.Root, pub, rootKey(t, f))
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// emptySKI makes Go emit a subject key identifier extension with no bytes.
func emptySKI(c *x509.Certificate) {
	c.SubjectKeyId = nil
	c.ExtraExtensions = append(c.ExtraExtensions, pkix.Extension{
		Id: asn1.ObjectIdentifier{2, 5, 29, 14}, Value: []byte{0x04, 0x00},
	})
}

// leafFor issues a leaf under f's intermediate with validity v at now.
func leafFor(t *testing.T, f *trusttest.Fixture, now time.Time, v time.Duration) *x509.Certificate {
	t.Helper()
	return leafUnder(t, f.Intermediate, interKey(t, f), now, v)
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

// crlBy signs a CRL listing serials, by issuer with key.
func crlBy(t *testing.T, issuer *x509.Certificate, key *ecdsa.PrivateKey, number int64, now time.Time, serials ...*big.Int) []byte {
	t.Helper()
	der, err := pki.CreateCRL(issuer, key, number, now, serials)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

func hasIntermediate(m signingkeys.Material, c *x509.Certificate) bool {
	for _, x := range m.Intermediates {
		if pki.Thumbprint(x.Raw) == pki.Thumbprint(c.Raw) {
			return true
		}
	}
	return false
}

func hasLeaf(m signingkeys.Material, c *x509.Certificate) bool {
	for _, l := range m.Leaves {
		if pki.Thumbprint(l.Verified.Leaf.Raw) == pki.Thumbprint(c.Raw) {
			return true
		}
	}
	return false
}

func wantCheck(t *testing.T, err error, sub string) {
	t.Helper()
	if !errors.Is(err, signingkeys.ErrCheck) {
		t.Fatalf("err = %v, want ErrCheck", err)
	}
	if !strings.Contains(err.Error(), sub) {
		t.Fatalf("err = %q, want it to contain %q", err, sub)
	}
}

func wantUnavailable(t *testing.T, err error) {
	t.Helper()
	var be *bus.Error
	if !errors.As(err, &be) || be.Code != bus.CodeUnavailable || !be.Retryable {
		t.Fatalf("err = %v, want a retryable unavailable", err)
	}
}
