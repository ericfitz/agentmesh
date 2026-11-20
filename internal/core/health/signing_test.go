package health

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/pki/rootca"
	"github.com/ericfitz/agentmesh/internal/store"
	"github.com/ericfitz/agentmesh/internal/store/sqlite"
	"github.com/ericfitz/agentmesh/internal/trusttest"
)

type signingEnv struct {
	svc Service
	fx  *trusttest.Fixture
	mgr *signingkeys.Manager
	now *time.Time
	tr  signingkeys.Trust
}

// newSigningEnv is a serving core with a leaf manager as its trust source, over
// a fixture made at the clock's start; root is an administrator, pat is not.
func newSigningEnv(t *testing.T) *signingEnv {
	t.Helper()
	s, err := sqlite.Open(context.Background(), filepath.Join(t.TempDir(), "agentmesh.db"), sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	e := &signingEnv{now: new(time.Time)}
	*e.now = time.UnixMilli(startMs)
	clock := func() time.Time { return *e.now }
	first, err := core.New(s, core.Defaults(), core.Options{Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	e.fx = trusttest.New(t, clock())
	e.mgr = e.fx.Manager(t, first)
	e.tr = e.fx.Trust(first)
	serving, err := core.New(s, core.Defaults(), core.Options{Now: clock, Trust: e.mgr})
	if err != nil {
		t.Fatal(err)
	}
	e.svc = Service{Core: serving}
	err = s.Tx(context.Background(), func(ctx context.Context, tx store.Tx) error {
		for _, n := range []string{"pat", "root"} {
			if err := tx.CreateIdentity(ctx, n, startMs); err != nil {
				return err
			}
		}
		return tx.SetAdmin(ctx, "root", true)
	})
	if err != nil {
		t.Fatal(err)
	}
	return e
}

func (e *signingEnv) health(t *testing.T, identity string) bus.Health {
	t.Helper()
	h, err := e.svc.Health(context.Background(), identity, "9.9.9")
	if err != nil {
		t.Fatalf("Health(%q): %v", identity, err)
	}
	return h
}

func TestHealthSigning(t *testing.T) {
	e := newSigningEnv(t)
	h := e.health(t, "root")
	sg := h.Signing
	if h.Tier != bus.TierAdmin || sg == nil {
		t.Fatalf("admin tier: %+v", h)
	}
	if h.Status != bus.HealthOK {
		t.Errorf("status %q, want ok", h.Status)
	}
	if sg.Installation != e.fx.Installation {
		t.Errorf("installation %q", sg.Installation)
	}
	if in := sg.Intermediate; in == nil || in.Thumbprint != pki.Thumbprint(e.fx.Intermediate.Raw) ||
		in.NotBefore != e.fx.Intermediate.NotBefore.UnixMilli() || in.NotAfter != e.fx.Intermediate.NotAfter.UnixMilli() || in.DaysLeft != 364 {
		t.Errorf("intermediate %+v", in)
	}
	cur, notAfter := e.mgr.Current()
	if l := sg.Leaf; l == nil || l.Thumbprint != cur || l.NotAfter != notAfter.UnixMilli() || l.NotBefore > startMs || l.NotBefore < startMs-time.Hour.Milliseconds() || l.DaysLeft != 7 {
		t.Errorf("leaf %+v, current %s %v", l, cur, notAfter)
	}
	if want := startMs + 84*int64(time.Hour/time.Millisecond); sg.NextRenewalAt != want {
		t.Errorf("next renewal %d, want %d (half the 168 hours)", sg.NextRenewalAt, want)
	}
	if b := e.mgr.Bundle(); sg.TrustNumber != b.TrustNumber || sg.TrustNumber == 0 {
		t.Errorf("trust number %d, bundle %d", sg.TrustNumber, b.TrustNumber)
	}
	if sg.RootCRLNumber != 0 || sg.LeafCRLNumber != 0 || sg.LastFailureAt != 0 || sg.LastFailure != "" || sg.Stopped != "" {
		t.Errorf("unexpected members: %+v", sg)
	}

	// A root CRL (of another certificate) and a rotation (which writes a leaf CRL)
	// give the CRL numbers.
	ctx := context.Background()
	crl := e.otherRootCRL(t)
	if _, err := e.tr.InstallRootCRL(ctx, crl); err != nil {
		t.Fatal(err)
	}
	if _, err := e.mgr.RotateSigningKey(ctx, "root", bus.RotateSigningKeyInput{}); err != nil {
		t.Fatal(err)
	}
	if err := e.mgr.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	sg = e.health(t, "root").Signing
	if sg.RootCRLNumber != pki.CRLNumber(crl) || sg.RootCRLNumber == 0 {
		t.Errorf("root CRL number %d, want %d", sg.RootCRLNumber, pki.CRLNumber(crl))
	}
	if sg.LeafCRLNumber == 0 {
		t.Errorf("leaf CRL number 0 after a rotation: %+v", sg)
	}

	// The identity and probe tiers carry none of it, and local mode none either.
	for _, id := range []string{"pat", ""} {
		if g := e.health(t, id); g.Signing != nil {
			t.Errorf("identity %q: signing %+v", id, g.Signing)
		}
	}
	local := newEnv(t, nil)
	if g := local.health(t, "root"); g.Signing != nil || g.Status != bus.HealthOK {
		t.Errorf("local mode: %+v", g)
	}
}

// otherRootCRL is a root CRL that revokes a certificate of another key, so the
// installation's intermediate stays valid.
func (e *signingEnv) otherRootCRL(t *testing.T) *x509.RevocationList {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der, err := pki.NewRequest(key, "other-installation")
	if err != nil {
		t.Fatal(err)
	}
	csr, err := pki.ParseRequest(der)
	if err != nil {
		t.Fatal(err)
	}
	other, err := rootca.Sign(e.fx.Dir, csr, 30, false, e.now.Add(-time.Hour), trusttest.NoCheck)
	if err != nil {
		t.Fatal(err)
	}
	crlDER, _, err := rootca.Revoke(e.fx.Dir, other, *e.now, trusttest.NoCheck)
	if err != nil {
		t.Fatal(err)
	}
	crl, err := pki.ParseCRL(crlDER)
	if err != nil {
		t.Fatal(err)
	}
	return crl
}

// TestHealthDegradedBySigning: each rule of section 4.14 on the fake clock, and
// the status answer stays a document (never an error).
func TestHealthDegradedBySigning(t *testing.T) {
	ctx := context.Background()
	toIntermediateDays := func(e *signingEnv, days int) {
		// Stand 'days' days and half an hour before the intermediate's "not after"
		// (so the whole days left are 'days'), with a fresh leaf.
		*e.now = e.fx.Intermediate.NotAfter.Add(-time.Duration(days)*24*time.Hour - 30*time.Minute)
		e.mgr.Step(ctx)
	}
	cases := []struct {
		name     string
		arrange  func(t *testing.T, e *signingEnv)
		degraded bool
		check    func(t *testing.T, e *signingEnv, sg bus.HealthSigning)
	}{
		{"fresh", func(*testing.T, *signingEnv) {}, false, nil},
		{"intermediate 31 days left", func(_ *testing.T, e *signingEnv) { toIntermediateDays(e, 31) }, false,
			func(t *testing.T, e *signingEnv, sg bus.HealthSigning) {
				if sg.Intermediate.DaysLeft != 31 || sg.Leaf == nil || sg.Leaf.DaysLeft != 7 {
					t.Errorf("%+v %+v", sg.Intermediate, sg.Leaf)
				}
			}},
		{"intermediate 29 days left", func(_ *testing.T, e *signingEnv) { toIntermediateDays(e, 29) }, true,
			func(t *testing.T, e *signingEnv, sg bus.HealthSigning) {
				if sg.Intermediate.DaysLeft != 29 {
					t.Errorf("days left %d", sg.Intermediate.DaysLeft)
				}
			}},
		{"failed renewal", func(t *testing.T, e *signingEnv) {
			if err := os.Remove(e.fx.KeyFile); err != nil {
				t.Fatal(err)
			}
			*e.now = e.now.Add(100 * time.Hour) // past half of the leaf's 168 hours
			e.mgr.Step(ctx)
		}, true, func(t *testing.T, e *signingEnv, sg bus.HealthSigning) {
			if sg.LastFailureAt != e.nowMs() || sg.LastFailure == "" {
				t.Errorf("failure %d %q", sg.LastFailureAt, sg.LastFailure)
			}
		}},
		{"expired leaf", func(_ *testing.T, e *signingEnv) { *e.now = e.now.Add(8 * 24 * time.Hour) }, true,
			func(t *testing.T, e *signingEnv, sg bus.HealthSigning) {
				if sg.Leaf == nil || sg.Leaf.DaysLeft >= 0 {
					t.Errorf("leaf %+v", sg.Leaf)
				}
			}},
		{"revoked intermediate key", func(t *testing.T, e *signingEnv) {
			if _, err := e.tr.InstallRootCRL(ctx, e.fx.RevokeIntermediate(t, *e.now)); err != nil {
				t.Fatal(err)
			}
			if err := e.mgr.Reload(ctx); err != nil {
				t.Fatal(err)
			}
		}, true, func(t *testing.T, e *signingEnv, sg bus.HealthSigning) {
			if sg.Stopped != "intermediate_revoked" {
				t.Errorf("stopped %q", sg.Stopped)
			}
		}},
		{"expired intermediate", func(_ *testing.T, e *signingEnv) {
			*e.now = e.fx.Intermediate.NotAfter.Add(time.Hour)
			if err := e.mgr.Reload(ctx); err != nil {
				t.Fatal(err)
			}
		}, true, func(t *testing.T, e *signingEnv, sg bus.HealthSigning) {
			if sg.Stopped != "intermediate_expired" || sg.Intermediate == nil || sg.Intermediate.DaysLeft >= 0 {
				t.Errorf("%q %+v", sg.Stopped, sg.Intermediate)
			}
		}},
		{"expired root", func(_ *testing.T, e *signingEnv) {
			*e.now = e.fx.Root.NotAfter.Add(time.Hour)
			if err := e.mgr.Reload(ctx); err != nil {
				t.Fatal(err)
			}
		}, true, func(t *testing.T, e *signingEnv, sg bus.HealthSigning) {
			if sg.Stopped != "root_expired" {
				t.Errorf("stopped %q", sg.Stopped)
			}
		}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			e := newSigningEnv(t)
			c.arrange(t, e)
			for _, id := range []string{"root", "pat", ""} {
				h := e.health(t, id)
				if got := h.Status == bus.HealthDegraded; got != c.degraded {
					t.Errorf("identity %q: status %q, want degraded %v", id, h.Status, c.degraded)
				}
			}
			if c.check != nil {
				c.check(t, e, *e.health(t, "root").Signing)
			}
		})
	}
}

func (e *signingEnv) nowMs() int64 { return e.now.UnixMilli() }
