package signingkeys_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
	"github.com/ericfitz/agentmesh/internal/store/sqlite"
	"github.com/ericfitz/agentmesh/internal/trusttest"
)

// loadFixture is a worst case for one Trust.Load: three certificates for the
// installation's intermediate key, a root CRL and a leaf CRL of ten entries
// each, and 50 leaf rows, in a SQLite file.
func loadFixture(b *testing.B) signingkeys.Trust {
	b.Helper()
	ctx := context.Background()
	now := time.UnixMilli(startMs)
	f := trusttest.New(b, now)
	st, err := sqlite.Open(ctx, filepath.Join(b.TempDir(), "agentmesh.db"), sqlite.Options{})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { _ = st.Close() })
	c, err := core.New(st, core.Defaults(), core.Options{Now: func() time.Time { return now }})
	if err != nil {
		b.Fatal(err)
	}
	tr := f.Trust(c)
	for _, cert := range []*x509.Certificate{f.Intermediate, f.Renew(b, now, 30), f.Renew(b, now, 60)} {
		if _, err := tr.InstallIntermediate(ctx, cert); err != nil {
			b.Fatal(err)
		}
	}
	// A root CRL that revokes another installation's certificate.
	if _, err := tr.InstallRootCRL(ctx, f.Sibling(b, "other-installation").RevokeIntermediate(b, now)); err != nil {
		b.Fatal(err)
	}
	raw, err := os.ReadFile(f.KeyFile)
	if err != nil {
		b.Fatal(err)
	}
	blk, _ := pem.Decode(raw)
	parsed, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		b.Fatal(err)
	}
	key := parsed.(*ecdsa.PrivateKey)
	var serials []*big.Int
	err = st.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		for i := range 50 {
			pub, _, err := ed25519.GenerateKey(rand.Reader)
			if err != nil {
				return err
			}
			leaf, err := pki.IssueLeaf(f.Intermediate, key, pub, now, 168*time.Hour)
			if err != nil {
				return err
			}
			if i < 10 {
				serials = append(serials, leaf.SerialNumber)
			}
			if _, err := tx.PutTrustCertificate(ctx, store.TrustCertificate{
				Kind: store.TrustLeaf, Thumbprint: pki.Thumbprint(leaf.Raw), DER: leaf.Raw,
				IssuerKey: pki.KeyID(f.Intermediate.SubjectKeyId), NotAfter: leaf.NotAfter.UnixMilli(), CreatedAt: startMs,
			}); err != nil {
				return err
			}
		}
		der, err := pki.CreateCRL(f.Intermediate, key, 1, now, serials)
		if err != nil {
			return err
		}
		crl, err := pki.ParseCRL(der)
		if err != nil {
			return err
		}
		return tx.PutCRL(ctx, store.TrustCRL{
			Kind: store.TrustLeafCRL, Thumbprint: pki.Thumbprint(der), DER: der,
			IssuerKey: pki.KeyID(f.Intermediate.SubjectKeyId), Number: pki.CRLNumber(crl), CreatedAt: startMs,
		})
	})
	if err != nil {
		b.Fatal(err)
	}
	return tr
}

// BenchmarkLoad is what every LoadKeys call pays: a Load with a Memory that
// has already verified the chains.
func BenchmarkLoad(b *testing.B) {
	ctx := context.Background()
	tr := loadFixture(b)
	mem := &signingkeys.Memory{}
	if m, err := tr.Load(ctx, mem); err != nil || len(m.Leaves) != 50 {
		b.Fatalf("leaves = %d, %v", len(m.Leaves), err)
	}
	b.ResetTimer()
	for range b.N {
		if _, err := tr.Load(ctx, mem); err != nil {
			b.Fatal(err)
		}
	}
}

// BenchmarkLoadCold is the first Load of a process: every chain is verified.
func BenchmarkLoadCold(b *testing.B) {
	ctx := context.Background()
	tr := loadFixture(b)
	b.ResetTimer()
	for range b.N {
		if _, err := tr.Load(ctx, &signingkeys.Memory{}); err != nil {
			b.Fatal(err)
		}
	}
}
