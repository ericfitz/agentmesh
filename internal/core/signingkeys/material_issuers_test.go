package signingkeys_test

import (
	"context"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/store"
)

// The per-leaf issuer cache follows the leaf rows: a row that disappears (expiry
// removal) leaves the cache at the next Load (issue #44, Important 3).
func TestLoadIssuerCacheIsBounded(t *testing.T) {
	e := newEnv(t)
	e.f.Install(t, e.c)
	now := e.clk.now()
	e.putLeaf(t, leafFor(t, e.f, now, time.Hour), keyID(e.f.Intermediate))
	e.putLeaf(t, leafFor(t, e.f, now, 2*time.Hour), keyID(e.f.Intermediate))
	m := e.load(t)
	if len(m.Leaves) != 2 || e.mem.IssuerCount() != 2 {
		t.Fatalf("leaves %d, cached %d, want 2 and 2", len(m.Leaves), e.mem.IssuerCount())
	}
	drop := m.Leaves[0].ID
	e.tx(t, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.DeleteTrustCertificates(ctx, []int64{drop})
		return err
	})
	if m = e.load(t); len(m.Leaves) != 1 || e.mem.IssuerCount() != 1 {
		t.Fatalf("leaves %d, cached %d, want 1 and 1", len(m.Leaves), e.mem.IssuerCount())
	}
	e.tx(t, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.DeleteTrustCertificates(ctx, []int64{m.Leaves[0].ID})
		return err
	})
	if m = e.load(t); len(m.Leaves) != 0 || e.mem.IssuerCount() != 0 {
		t.Fatalf("leaves %d, cached %d, want 0 and 0", len(m.Leaves), e.mem.IssuerCount())
	}
}

// A leaf no stored intermediate verifies is ignored and not cached; once its
// intermediate arrives, the same Memory loads it and caches its issuer.
func TestLoadIssuerRetriedWhenIntermediateArrives(t *testing.T) {
	e := newEnv(t)
	leaf := leafFor(t, e.f, e.clk.now(), time.Hour)
	e.putLeaf(t, leaf, keyID(e.f.Intermediate))
	if m := e.load(t); len(m.Leaves) != 0 || e.mem.IssuerCount() != 0 {
		t.Fatalf("with no intermediate: leaves %d, cached %d, want 0 and 0", len(m.Leaves), e.mem.IssuerCount())
	}
	if _, err := e.tr.InstallIntermediate(context.Background(), e.f.Intermediate); err != nil {
		t.Fatal(err)
	}
	m := e.load(t)
	if len(m.Leaves) != 1 || m.Leaves[0].Revoked || e.mem.IssuerCount() != 1 {
		t.Fatalf("after the intermediate: leaves %d, cached %d, want 1 and 1, not revoked", len(m.Leaves), e.mem.IssuerCount())
	}
}
