package maintenance

import (
	"context"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/trusttest"
)

func jobNames(s Service) []string {
	var out []string
	for _, j := range s.Jobs() {
		out = append(out, j.Name)
	}
	return out
}

// TestExpiredLeafRemovalJob: the job runs where the two old signing key jobs
// ran (before the last job) and only when Trust is set; its count is the rows
// removed (ADR 0019 section 4.16).
func TestExpiredLeafRemovalJob(t *testing.T) {
	a, _, clk := twoCores(t)
	for _, n := range jobNames(a) {
		if n == "expired leaf removal" || n == "signing key rotation" || n == "signing key removal" {
			t.Fatalf("job %q present with Trust nil", n)
		}
	}
	fx := trusttest.New(t, time.UnixMilli(startMs))
	fx.Install(t, a.Core)
	tr := fx.Trust(a.Core)
	a.Trust = &tr
	names := jobNames(a)
	l := len(names)
	if names[l-1] != "assertion replay expiry" || names[l-2] != "expired leaf removal" {
		t.Fatalf("tail of jobs = %v", names[l-3:])
	}
	for _, n := range names {
		if n == "signing key rotation" || n == "signing key removal" {
			t.Fatalf("old job %q is back", n)
		}
	}

	ctx := context.Background()
	fx.Leaf(t, a.Core, clk.now(), 2*time.Hour)
	fx.Leaf(t, a.Core, clk.now(), 2*time.Hour)
	if n, err := a.RunJob(ctx, "expired leaf removal"); n != 0 || err != nil {
		t.Fatalf("before expiry: %d, %v", n, err)
	}
	clk.advance(4 * time.Hour)
	if n, err := a.RunJob(ctx, "expired leaf removal"); n != 2 || err != nil {
		t.Fatalf("after expiry: %d, %v; want 2", n, err)
	}
	if n, err := a.RunJob(ctx, "expired leaf removal"); n != 0 || err != nil {
		t.Fatalf("second run: %d, %v", n, err)
	}
}
