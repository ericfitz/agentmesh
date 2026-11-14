package signingkeys_test

import (
	"context"
	"database/sql"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/auth/token"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
)

// revokeLeaf puts the leaf on the leaf CRL the way another process does.
func (e *env) revokeLeaf(t *testing.T, number int64, serials ...*big.Int) {
	t.Helper()
	e.putCRL(t, store.TrustLeafCRL, keyID(e.f.Intermediate),
		crlBy(t, e.f.Intermediate, interKey(t, e.f), number, e.clk.now(), serials...))
}

func (e *env) onlyLeaf(t *testing.T) (thumbprint string, serial *big.Int) {
	t.Helper()
	rows := e.leafRows(t)
	if len(rows) != 1 {
		t.Fatalf("%d leaf rows, want 1", len(rows))
	}
	c, err := pki.ParseCertificatePEM(pki.EncodePEM("CERTIFICATE", rows[0].DER))
	if err != nil {
		t.Fatal(err)
	}
	return pki.Thumbprint(rows[0].DER), c.SerialNumber
}

func wantWake(t *testing.T, m *signingkeys.Manager, want bool) {
	t.Helper()
	select {
	case <-m.Wake():
		if !want {
			t.Fatal("Run was woken")
		}
	default:
		if want {
			t.Fatal("Run was not woken")
		}
	}
}

func TestOwnLeafRevoked(t *testing.T) {
	ctx := context.Background()
	e, m, p := renewEnv(t)
	old, serial := e.onlyLeaf(t)
	e.revokeLeaf(t, 5, serial)

	// The very next reload after the issue sees it (no stale-generation skip).
	if err := m.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	wantWake(t, m, true)
	if tp, _ := m.Current(); tp != "" {
		t.Fatalf("Current = %q for a revoked leaf", tp)
	}
	set, err := m.LoadKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if set.Signer != nil || set.Active.KID != "" || hasKey(set, old) {
		t.Fatalf("the revoked leaf is still published or signs: %+v", set.Active)
	}
	if p.calls.Load() != 0 {
		t.Fatal("Reload used the provider: it must never issue")
	}
	if m.Stopped() != "" {
		t.Fatalf("Stopped = %q for a revoked leaf", m.Stopped())
	}

	m.Step(ctx)
	if p.calls.Load() != 1 {
		t.Fatalf("provider calls = %d, want the one issue", p.calls.Load())
	}
	tp, _ := m.Current()
	if tp == "" || tp == old {
		t.Fatalf("Current = %q, want a new leaf", tp)
	}
	if set, err = m.LoadKeys(ctx); err != nil || set.Signer == nil || set.Active.KID != tp || hasKey(set, old) {
		t.Fatalf("set after the issue: %+v, %v", set.Active, err)
	}
}

// A revoked current leaf is treated as an expired one: the first attempt is at
// once, the next a minute later.
func TestOwnLeafRevokedRetries(t *testing.T) {
	ctx := context.Background()
	e, m, p := renewEnv(t)
	_, serial := e.onlyLeaf(t)
	e.revokeLeaf(t, 5, serial)
	p.down.Store(true)
	m.Step(ctx)
	if p.calls.Load() != 1 {
		t.Fatalf("calls = %d, want an attempt at once", p.calls.Load())
	}
	e.clk.advance(59 * time.Second)
	m.Step(ctx)
	if p.calls.Load() != 1 {
		t.Fatal("an attempt before the minute passed")
	}
	e.clk.advance(time.Second)
	p.down.Store(false)
	m.Step(ctx)
	if p.calls.Load() != 2 {
		t.Fatalf("calls = %d, want the retry after a minute", p.calls.Load())
	}
	if tp, _ := m.Current(); tp == "" {
		t.Fatal("no leaf after the retry")
	}
}

func TestIntermediateKeyRevokedStops(t *testing.T) {
	ctx := context.Background()
	e, m, p := renewEnv(t)
	if _, err := e.tr.InstallRootCRL(ctx, e.f.RevokeIntermediate(t, e.clk.now())); err != nil {
		t.Fatal(err)
	}
	m.Step(ctx)
	if got := m.Stopped(); got != "intermediate_revoked" {
		t.Fatalf("Stopped = %q", got)
	}
	set, err := m.LoadKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if set.Signer != nil || len(set.Keys) != 0 {
		t.Fatalf("a revoked key still publishes: %+v", set)
	}
	if tp, _ := m.Current(); tp != "" {
		t.Fatalf("Current = %q", tp)
	}
	e.clk.advance(2 * week)
	m.Step(ctx)
	if p.calls.Load() != 0 || len(e.leafRows(t)) != 1 {
		t.Fatalf("a stopped manager issued: %d provider calls, %d rows", p.calls.Load(), len(e.leafRows(t)))
	}
	if _, ok := m.LastFailure(); ok {
		t.Fatal("a stop is not a failed issue")
	}
	if !e.logged("intermediate_revoked") {
		t.Fatalf("no log line names the stop:\n%s", e.logs.String())
	}
	wantWake(t, m, false)
}

func TestIntermediateExpiryStops(t *testing.T) {
	ctx := context.Background()
	e, m, p := renewEnv(t)
	e.at(365 * 24 * time.Hour)
	m.Step(ctx)
	if got := m.Stopped(); got != "intermediate_expired" {
		t.Fatalf("Stopped = %q", got)
	}
	if p.calls.Load() != 0 || len(e.leafRows(t)) != 1 {
		t.Fatal("a stopped manager issued")
	}
	if set, err := m.LoadKeys(ctx); err != nil || set.Signer != nil {
		t.Fatalf("set = %+v, %v", set, err)
	}

	// A renewed certificate ends the stop with no restart.
	renewed := e.f.Renew(t, e.clk.now().Add(-time.Hour), 400)
	if _, err := e.tr.InstallIntermediate(ctx, renewed); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if got := m.Stopped(); got != "" {
		t.Fatalf("Stopped = %q after the renewal", got)
	}
	wantWake(t, m, true)
	m.Step(ctx)
	if tp, _ := m.Current(); tp == "" {
		t.Fatal("no leaf after the stop ended")
	}
}

func TestIntermediateRenewalPickedUp(t *testing.T) {
	ctx := context.Background()
	e, m, _ := renewEnv(t)
	renewed := e.f.Renew(t, e.clk.now(), 730)
	if _, err := e.tr.InstallIntermediate(ctx, renewed); err != nil {
		t.Fatal(err)
	}
	for _, d := range []time.Duration{time.Minute, 84 * time.Hour, 366 * 24 * time.Hour} {
		e.at(d)
		m.Step(ctx)
		if got := m.Stopped(); got != "" {
			t.Fatalf("Stopped = %q at %s", got, d)
		}
	}
	set, err := m.LoadKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if set.Signer == nil || len(set.Active.Chain) != 2 || string(set.Active.Chain[1]) != string(renewed.Raw) {
		t.Fatalf("the next leaf does not chain through the renewed certificate: %d certificates", len(set.Active.Chain))
	}
}

func TestRootExpiryStops(t *testing.T) {
	ctx := context.Background()
	e, m, p := renewEnv(t)
	iss, err := token.NewIssuer(ctx, "http://localhost:8420", m, time.Hour, e.clk.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := iss.Mint(ctx, token.MintInput{Identity: "alice", Kind: token.KindAgent})
	if err != nil {
		t.Fatal(err)
	}
	e.at(e.f.Root.NotAfter.Sub(e.clk.now()) + time.Second)
	m.Step(ctx)
	if got := m.Stopped(); got != "root_expired" {
		t.Fatalf("Stopped = %q", got)
	}
	set, err := m.LoadKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if set.Signer != nil || len(set.Keys) != 0 {
		t.Fatalf("an expired root still publishes: %+v", set)
	}
	if p.calls.Load() != 0 {
		t.Fatal("a stopped manager used the key")
	}
	iss.Invalidate()
	if _, err := iss.Verify(ctx, raw, e.clk.now()); err == nil {
		t.Fatal("a bearer verified past the root's not-after")
	}
	if !e.logged("root_expired") {
		t.Fatal("no log line names the stop")
	}
}

func rawDB(t *testing.T, e *env) *sql.DB {
	t.Helper()
	db, err := sql.Open("sqlite", e.path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db
}

func (e *env) leafCRLRow(t *testing.T) store.TrustCRL {
	t.Helper()
	var out []store.TrustCRL
	if err := e.st.Read(context.Background(), func(ctx context.Context, tx store.Tx) error {
		rows, err := tx.CRLs(ctx)
		for _, r := range rows {
			if r.Kind == store.TrustLeafCRL {
				out = append(out, r)
			}
		}
		return err
	}); err != nil {
		t.Fatal(err)
	}
	if len(out) != 1 {
		t.Fatalf("%d leaf CRL rows, want 1", len(out))
	}
	return out[0]
}

func TestRollbackWrittenBack(t *testing.T) {
	ctx := context.Background()
	setup := func(t *testing.T) (*env, *signingkeys.Manager, int64) {
		e, m, _ := renewEnv(t)
		e.revokeLeaf(t, 5000, big.NewInt(99))
		if err := m.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		if got := e.leafCRLRow(t).Number; got != 5000 {
			t.Fatalf("stored number %d", got)
		}
		return e, m, e.trustNumber(t)
	}
	older := func(t *testing.T, e *env) {
		der := crlBy(t, e.f.Intermediate, interKey(t, e.f), 3000, e.clk.now())
		if _, err := rawDB(t, e).Exec("UPDATE trust_material SET thumbprint = ?, der = ?, number = 3000 WHERE kind = 'leaf_crl'",
			pki.Thumbprint(der), der); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("older-crl", func(t *testing.T) {
		e, m, before := setup(t)
		older(t, e)
		if err := m.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		if got := e.leafCRLRow(t).Number; got != 5000 {
			t.Fatalf("stored number %d, want the newer CRL written back", got)
		}
		if after := e.trustNumber(t); after <= before {
			t.Fatalf("trust number %d, want above %d", after, before)
		}
		if !e.logged("rollback") {
			t.Fatalf("the log does not say rollback:\n%s", e.logs.String())
		}
		again := e.trustNumber(t)
		if err := m.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		if e.trustNumber(t) != again {
			t.Fatal("a second reload wrote again")
		}
	})
	t.Run("deleted-row", func(t *testing.T) {
		e, m, before := setup(t)
		if _, err := rawDB(t, e).Exec("DELETE FROM trust_material WHERE kind = 'leaf_crl'"); err != nil {
			t.Fatal(err)
		}
		if err := m.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		if got := e.leafCRLRow(t).Number; got != 5000 {
			t.Fatalf("stored number %d, want the held CRL put back", got)
		}
		if e.trustNumber(t) <= before {
			t.Fatal("the trust number did not rise")
		}
	})
	t.Run("lock-busy", func(t *testing.T) {
		e, m, before := setup(t)
		older(t, e)
		held, err := e.st.TryLock(ctx, signingkeys.LockName, "someone-else", e.nowMs(), e.nowMs()+60_000)
		if err != nil || !held {
			t.Fatalf("TryLock = %v, %v", held, err)
		}
		if err := m.Reload(ctx); err != nil {
			t.Fatalf("a busy lock is not an error: %v", err)
		}
		if got := e.leafCRLRow(t).Number; got != 3000 || e.trustNumber(t) != before {
			t.Fatal("wrote back without the lock")
		}
		if !e.logged("write-back") {
			t.Fatalf("no log line for the deferred write-back:\n%s", e.logs.String())
		}
		if err := e.st.Unlock(ctx, signingkeys.LockName, "someone-else"); err != nil {
			t.Fatal(err)
		}
		if err := m.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		if got := e.leafCRLRow(t).Number; got != 5000 {
			t.Fatalf("stored number %d after the lock was free", got)
		}
	})
}

func TestReloadVerifiesOnlyNewRows(t *testing.T) {
	ctx := context.Background()
	e, m, _ := renewEnv(t)
	now := e.clk.now()
	for range 2000 {
		e.f.Leaf(t, e.c, now, 24*time.Hour)
	}
	var calls atomic.Int64
	signingkeys.SetChainCheckHook(func() { calls.Add(1) })
	t.Cleanup(func() { signingkeys.SetChainCheckHook(nil) })
	if err := m.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() < 2000 {
		t.Fatalf("first reload checked %d chains, want at least 2000", calls.Load())
	}
	calls.Store(0)
	start := time.Now()
	if err := m.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	took := time.Since(start)
	t.Logf("second reload of 2001 rows: %s", took)
	if calls.Load() != 0 {
		t.Fatalf("second reload checked %d chains, want 0", calls.Load())
	}
	if took > time.Second {
		t.Fatalf("second reload took %s, want under 1s", took)
	}
	e.f.Leaf(t, e.c, now, 24*time.Hour)
	calls.Store(0)
	if err := m.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 {
		t.Fatalf("a reload with one new row checked %d chains", calls.Load())
	}
}

func TestReloadCallsOnChange(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	var n atomic.Int64
	m, err := signingkeys.New(ctx, signingkeys.Options{Trust: e.tr, LeafValidity: week, OnChange: func() { n.Add(1) }})
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(ctx); err != nil { // the manager's own leaf is new to the first reload
		t.Fatal(err)
	}
	base := n.Load()
	if err := m.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if n.Load() != base {
		t.Fatalf("OnChange ran %d times at an unchanged reload", n.Load()-base)
	}
	e.f.Leaf(t, e.c, e.clk.now(), 24*time.Hour)
	if err := m.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if n.Load() != base+1 {
		t.Fatalf("OnChange ran %d times for a new leaf", n.Load()-base)
	}
	if err := m.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if _, err := e.tr.InstallRootCRL(ctx, e.f.RevokeIntermediate(t, e.clk.now())); err != nil {
		t.Fatal(err)
	}
	if err := m.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	if n.Load() != base+2 {
		t.Fatalf("OnChange ran %d times in all, want %d", n.Load()-base, 2)
	}
}

// Reload fills the manager's wake channel, and Run wakes on it and issues.
func TestRunWakesOnRevocation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	e, m, _ := renewEnv(t)
	done := make(chan struct{})
	go func() { m.Run(ctx, nil); close(done) }()
	defer func() { cancel(); <-done }()
	// Run's first Step ran or will run; wait for it to settle on its timer.
	deadline := time.Now().Add(5 * time.Second)
	for {
		if _, nd := m.Current(); !nd.IsZero() {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("no current leaf")
		}
		time.Sleep(2 * time.Millisecond)
	}
	old, serial := e.onlyLeaf(t)
	e.revokeLeaf(t, 5, serial)
	if err := m.Reload(ctx); err != nil {
		t.Fatal(err)
	}
	for {
		if tp, _ := m.Current(); tp != "" && tp != old {
			return
		}
		if time.Now().After(deadline) {
			t.Fatal("Run was not woken by the revocation")
		}
		time.Sleep(2 * time.Millisecond)
	}
}
