package signingkeys_test

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/ericfitz/agentmesh/internal/auth/token"
	"github.com/ericfitz/agentmesh/internal/core/notify"
	"github.com/ericfitz/agentmesh/internal/core/signingkeys"
	"github.com/ericfitz/agentmesh/internal/keyprovider"
	"github.com/ericfitz/agentmesh/internal/store"
)

// downProvider wraps the file provider: while down is set, Signer fails with
// err; every call is counted.
type downProvider struct {
	keyprovider.Provider
	down  atomic.Bool
	calls atomic.Int32
	err   error
}

func (p *downProvider) Signer(ctx context.Context, k keyprovider.Key) (keyprovider.Signer, error) {
	p.calls.Add(1)
	if p.down.Load() {
		return nil, p.err
	}
	return p.Provider.Signer(ctx, k)
}

// renewEnv is an env with the intermediate installed and a manager whose
// provider can be taken down.
func renewEnv(t *testing.T) (*env, *signingkeys.Manager, *downProvider) {
	t.Helper()
	e := newEnv(t)
	e.f.Install(t, e.c)
	p := &downProvider{Provider: e.tr.Provider, err: fmt.Errorf("kms: %w", keyprovider.ErrUnavailable)}
	tr := e.tr
	tr.Provider = p
	m, err := signingkeys.New(context.Background(), signingkeys.Options{Trust: tr, LeafValidity: week})
	if err != nil {
		t.Fatal(err)
	}
	p.calls.Store(0)
	return e, m, p
}

// at sets the fake clock to d after the start.
func (e *env) at(d time.Duration) {
	e.clk.advance(time.UnixMilli(startMs).Add(d).Sub(e.clk.now()))
}

func TestRenewAtHalf(t *testing.T) {
	ctx := context.Background()
	e, m, p := renewEnv(t)
	first, _ := m.Current()

	e.at(84*time.Hour - time.Minute)
	next := m.Step(ctx)
	if p.calls.Load() != 0 || len(e.leafRows(t)) != 1 {
		t.Fatalf("a Step before W/2 issued (%d provider calls, %d rows)", p.calls.Load(), len(e.leafRows(t)))
	}
	if limit := time.UnixMilli(startMs).Add(84 * time.Hour); next.After(limit) {
		t.Fatalf("next = %v, later than W/2 (%v)", next, limit)
	}

	e.at(84 * time.Hour)
	m.Step(ctx)
	if len(e.leafRows(t)) != 2 {
		t.Fatalf("%d leaf rows after W/2, want 2", len(e.leafRows(t)))
	}
	second, _ := m.Current()
	if second == "" || second == first {
		t.Fatalf("current = %q after the renewal (first %q)", second, first)
	}
	set, err := m.LoadKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if len(set.Keys) != 2 || !hasKey(set, first) || !hasKey(set, second) || set.Active.KID != second {
		t.Fatalf("set keys %v active %q, want both leaves and the new one active", kids(set), set.Active.KID)
	}
	iss, err := token.NewIssuer(ctx, "http://localhost:8420", m, time.Hour, e.clk.now)
	if err != nil {
		t.Fatalf("the published set is not a valid key set: %v", err)
	}
	raw, _, err := iss.Mint(ctx, token.MintInput{Identity: "alice", Kind: token.KindAgent})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := iss.Verify(ctx, raw, e.clk.now()); err != nil {
		t.Fatal(err)
	}

	// A second Step at the same instant repeats nothing.
	m.Step(ctx)
	if len(e.leafRows(t)) != 2 {
		t.Fatalf("a second Step issued: %d rows", len(e.leafRows(t)))
	}
	// The previous leaf stays published until it expires.
	e.at(week + time.Hour)
	set, err = m.LoadKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if hasKey(set, first) || !hasKey(set, second) {
		t.Fatalf("after the first leaf expired: %v", kids(set))
	}
}

func TestRetrySchedule(t *testing.T) {
	ctx := context.Background()
	e, m, p := renewEnv(t)
	start := time.UnixMilli(startMs)
	p.down.Store(true)

	e.at(84 * time.Hour)
	m.Step(ctx)
	if p.calls.Load() != 1 {
		t.Fatalf("%d attempts at W/2, want 1", p.calls.Load())
	}
	retry1 := 84*time.Hour + 10*time.Hour + 30*time.Minute
	e.at(retry1 - time.Second)
	m.Step(ctx)
	if p.calls.Load() != 1 {
		t.Fatalf("an attempt before the retry time (%d)", p.calls.Load())
	}
	e.at(retry1)
	m.Step(ctx)
	if p.calls.Load() != 2 {
		t.Fatalf("%d attempts at the first retry time, want 2", p.calls.Load())
	}
	retry2 := retry1 + 9*time.Hour + 11*time.Minute + 15*time.Second
	e.at(retry2 - time.Second)
	m.Step(ctx)
	if p.calls.Load() != 2 {
		t.Fatalf("an attempt before the second retry time (%d)", p.calls.Load())
	}
	e.at(retry2)
	m.Step(ctx)
	if p.calls.Load() != 3 {
		t.Fatalf("%d attempts at the second retry time, want 3", p.calls.Load())
	}
	f, ok := m.LastFailure()
	if !ok || !f.At.Equal(start.Add(retry2)) || !strings.Contains(f.Message, "unavailable") {
		t.Fatalf("LastFailure = %+v, %v", f, ok)
	}

	// Four minutes left: a minute later.
	e.at(week - 4*time.Minute)
	m.Step(ctx)
	n := p.calls.Load()
	e.at(week - 4*time.Minute + 59*time.Second)
	m.Step(ctx)
	if p.calls.Load() != n {
		t.Fatal("an attempt 59 s after a failure with 4 minutes left")
	}
	e.at(week - 3*time.Minute)
	m.Step(ctx)
	if p.calls.Load() != n+1 {
		t.Fatal("no attempt a minute after a failure with 4 minutes left")
	}
}

func TestExpiredLeafStopsSigning(t *testing.T) {
	ctx := context.Background()
	e, m, p := renewEnv(t)
	p.down.Store(true)
	e.at(84 * time.Hour)
	m.Step(ctx)

	// Another manager (another process) with a leaf that outlives this one.
	e.at(100 * time.Hour)
	other := e.newManager(t)

	for h := 101; h <= 168; h++ {
		e.at(time.Duration(h) * time.Hour)
		m.Step(ctx)
	}
	if tp, _ := m.Current(); tp == "" {
		t.Fatal("the leaf cannot sign before its leeway ran out")
	}
	e.at(week + 2*token.Leeway)
	m.Step(ctx)
	set, err := m.LoadKeys(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if set.Signer != nil || set.Active.KID != "" {
		t.Fatalf("an expired leaf still signs: %+v", set.Active)
	}
	iss, err := token.NewIssuer(ctx, "http://localhost:8420", m, time.Hour, e.clk.now)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := iss.Mint(ctx, token.MintInput{Identity: "alice", Kind: token.KindAgent}); !errors.Is(err, token.ErrSignerUnavailable) {
		t.Fatalf("Mint err = %v, want ErrSignerUnavailable", err)
	}
	oiss, err := token.NewIssuer(ctx, "http://localhost:8420", other, time.Hour, e.clk.now)
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := oiss.Mint(ctx, token.MintInput{Identity: "bob", Kind: token.KindAgent})
	if err != nil {
		t.Fatal(err)
	}
	if sub, err := iss.Verify(ctx, raw, e.clk.now()); err != nil || sub != "bob" {
		t.Fatalf("a bearer from the other manager's valid leaf: %q, %v", sub, err)
	}

	// Expired and failing: the first attempt was at once (the Step above), the next is a minute later.
	n := p.calls.Load()
	m.Step(ctx)
	if p.calls.Load() != n {
		t.Fatal("a second Step at one instant attempted again")
	}
	e.at(week + 2*token.Leeway + 59*time.Second)
	m.Step(ctx)
	if p.calls.Load() != n {
		t.Fatal("an attempt before the minute passed")
	}
	e.at(week + 2*token.Leeway + time.Minute)
	m.Step(ctx)
	if p.calls.Load() != n+1 {
		t.Fatal("no attempt after a minute")
	}
}

func TestRecoveryClearsFailure(t *testing.T) {
	ctx := context.Background()
	e, m, p := renewEnv(t)
	if _, ok := m.LastFailure(); ok {
		t.Fatal("a failure before anything failed")
	}
	p.down.Store(true)
	e.at(84 * time.Hour)
	m.Step(ctx)
	if _, ok := m.LastFailure(); !ok {
		t.Fatal("no failure recorded")
	}
	p.down.Store(false)
	e.at(84*time.Hour + 10*time.Hour + 30*time.Minute)
	m.Step(ctx)
	if f, ok := m.LastFailure(); ok {
		t.Fatalf("failure %+v after a successful issue", f)
	}
	if len(e.leafRows(t)) != 2 {
		t.Fatalf("%d rows, want 2", len(e.leafRows(t)))
	}
}

func TestClockOutsideValidity(t *testing.T) {
	ctx := context.Background()
	t.Run("before not before", func(t *testing.T) {
		e, m, _ := renewEnv(t)
		e.at(10 * time.Hour)
		m.Step(ctx) // nothing due: the first leaf is the current one
		e.at(84 * time.Hour)
		m.Step(ctx) // the renewal; the second leaf's period starts at 84 h
		second, _ := m.Current()
		if len(e.leafRows(t)) != 2 {
			t.Fatalf("%d rows", len(e.leafRows(t)))
		}
		e.at(12 * time.Hour) // before the second leaf's "not before"
		m.Step(ctx)
		third, _ := m.Current()
		if third == second || third == "" || len(e.leafRows(t)) != 3 {
			t.Fatalf("current %q (was %q), %d rows: no leaf issued for the stepped clock", third, second, len(e.leafRows(t)))
		}
	})
	t.Run("after not after", func(t *testing.T) {
		e, m, _ := renewEnv(t)
		before, _ := m.Current()
		e.at(week + time.Hour)
		m.Step(ctx)
		after, na := m.Current()
		if after == "" || after == before || !na.After(e.clk.now()) {
			t.Fatalf("current %q (was %q): no leaf issued", after, before)
		}
		if _, err := m.LoadKeys(ctx); err != nil {
			t.Fatal(err)
		}
	})
}

func TestRenewalStoreFailure(t *testing.T) {
	ctx := context.Background()
	e := newEnv(t)
	e.f.Install(t, e.c)
	fs := &leafFailStore{Store: e.st}
	tr := e.f.Trust(e.coreOver(t, fs))
	m, err := signingkeys.New(ctx, signingkeys.Options{Trust: tr, LeafValidity: week})
	if err != nil {
		t.Fatal(err)
	}
	first, _ := m.Current()

	fs.setFailLeaf(true)
	e.at(84 * time.Hour)
	m.Step(ctx)
	f, ok := m.LastFailure()
	if !ok || f.Message == "" {
		t.Fatalf("LastFailure = %+v, %v after a failed insert", f, ok)
	}
	if tp, _ := m.Current(); tp != first {
		t.Fatalf("the current leaf moved to %q", tp)
	}
	set, err := m.LoadKeys(ctx)
	if err != nil || set.Active.KID != first || set.Signer == nil {
		t.Fatalf("the current leaf stopped signing: %v %q", err, set.Active.KID)
	}

	fs.setFailLeaf(false)
	retry := 84*time.Hour + 10*time.Hour + 30*time.Minute
	e.at(retry - time.Second)
	m.Step(ctx)
	if len(e.leafRows(t)) != 1 {
		t.Fatal("an attempt before the retry time")
	}
	e.at(retry)
	m.Step(ctx)
	if len(e.leafRows(t)) != 2 {
		t.Fatalf("%d rows after the retry, want 2", len(e.leafRows(t)))
	}
	if tp, _ := m.Current(); tp == first {
		t.Fatal("the retry did not make the new leaf current")
	}
	if _, ok := m.LastFailure(); ok {
		t.Fatal("failure not cleared")
	}
}

func TestFailureMessageIsOneBoundedLine(t *testing.T) {
	ctx := context.Background()
	e, m, p := renewEnv(t)
	p.err = fmt.Errorf("kms: %w: %s\nsecond line with detail", keyprovider.ErrUnavailable, strings.Repeat("é", 300))
	p.down.Store(true)
	e.at(84 * time.Hour)
	m.Step(ctx)
	f, ok := m.LastFailure()
	if !ok {
		t.Fatal("no failure")
	}
	if len(f.Message) > 200 || strings.ContainsAny(f.Message, "\r\n") || !utf8.ValidString(f.Message) || strings.Contains(f.Message, "second line") {
		t.Fatalf("message %q (%d bytes)", f.Message, len(f.Message))
	}
}

func TestStepReturnsNextDue(t *testing.T) {
	ctx := context.Background()
	e, m, _ := renewEnv(t)
	for _, d := range []time.Duration{0, time.Second, 20 * time.Second, time.Minute, time.Hour, 83 * time.Hour, 84 * time.Hour, 100 * time.Hour, week + time.Hour} {
		e.at(d)
		next := m.Step(ctx)
		now := e.clk.now()
		if next.Before(now) || next.After(now.Add(token.ReloadInterval)) {
			t.Fatalf("at %s: next is %s after now", d, next.Sub(now))
		}
	}
}

func TestConcurrentStepsIssueOnce(t *testing.T) {
	ctx := context.Background()
	e, m, _ := renewEnv(t)
	e.at(84 * time.Hour)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			m.Step(ctx)
		}()
	}
	wg.Wait()
	if n := len(e.leafRows(t)); n != 2 {
		t.Fatalf("%d leaf rows after 8 concurrent Steps, want 2", n)
	}
}

func TestRunStopsWithContext(t *testing.T) {
	_, m, _ := renewEnv(t)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		m.Run(ctx, nil)
		close(done)
	}()
	cancel()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not stop with its context")
	}
	// An already canceled context returns at once.
	done2 := make(chan struct{})
	go func() {
		m.Run(ctx, nil)
		close(done2)
	}()
	select {
	case <-done2:
	case <-time.After(5 * time.Second):
		t.Fatal("Run with a canceled context did not return")
	}
}

// Ruling 13 wins over the retry floor: a clock stepped outside the leaf's
// period issues at once although a retry is pending less than a minute ahead.
func TestClockStepBeatsPendingRetry(t *testing.T) {
	ctx := context.Background()
	e, m, p := renewEnv(t)
	p.down.Store(true)
	e.at(week - 30*time.Second)
	m.Step(ctx) // fails with the leaf still in its period: the retry is a minute ahead
	n := p.calls.Load()
	p.down.Store(false)
	e.at(week + 10*time.Second) // the leaf expired; the retry is 20 s ahead
	m.Step(ctx)
	if p.calls.Load() != n+1 {
		t.Fatalf("%d provider calls after the clock left the leaf's period, want %d", p.calls.Load(), n+1)
	}
	if tp, _ := m.Current(); tp == "" {
		t.Fatal("no usable leaf after the step")
	}
}

func TestStepNextDueEdges(t *testing.T) {
	ctx := context.Background()
	t.Run("renewal inside the reload interval", func(t *testing.T) {
		e, m, _ := renewEnv(t)
		e.at(84*time.Hour - 10*time.Second)
		if next, want := m.Step(ctx), time.UnixMilli(startMs).Add(84*time.Hour); !next.Equal(want) {
			t.Fatalf("next = %v, want exactly %v", next, want)
		}
	})
	t.Run("retry inside the reload interval", func(t *testing.T) {
		e, m, p := renewEnv(t)
		p.down.Store(true)
		e.at(week - 4*time.Minute) // a failure with 4 minutes left: retry a minute ahead
		m.Step(ctx)
		e.at(week - 4*time.Minute + 45*time.Second)
		now := e.clk.now()
		next := m.Step(ctx)
		if want := time.UnixMilli(startMs).Add(week - 3*time.Minute); !next.Equal(want) || next.Before(now) {
			t.Fatalf("next = %v, want the retry time %v", next, want)
		}
	})
}

// doorbell runs m.Run over a memory notifier and returns the notifier, a read
// counter (reads of the stored trust number that hints caused) and the count of
// OnChange calls. Run is parked before doorbell returns.
func doorbell(t *testing.T, m *signingkeys.Manager) (n *notify.Memory, reads, changes *atomic.Int32) {
	t.Helper()
	n, reads, changes = notify.NewMemory(), &atomic.Int32{}, &atomic.Int32{}
	signingkeys.SetTrustReadHook(func() { reads.Add(1) })
	parked := make(chan struct{}, 1)
	signingkeys.SetRunParkedHook(func() {
		select {
		case parked <- struct{}{}:
		default:
		}
	})
	m.SetOnChange(func() { changes.Add(1) })
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { defer close(done); m.Run(ctx, n) }()
	t.Cleanup(func() {
		cancel()
		<-done
		signingkeys.SetTrustReadHook(nil)
		signingkeys.SetRunParkedHook(nil)
	})
	select {
	case <-parked:
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not park")
	}
	changes.Store(0)
	return n, reads, changes
}

func waitCount(t *testing.T, c *atomic.Int32, want int32, what string) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for c.Load() < want {
		if time.Now().After(deadline) {
			t.Fatalf("%s = %d, want %d", what, c.Load(), want)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

func TestManagerReloadsOnHint(t *testing.T) {
	e, m, _ := renewEnv(t)
	n, reads, changes := doorbell(t, m)
	held := m.Bundle().TrustNumber

	// A message hint (sequence number above 0) causes no read.
	n.Publish(notify.Hint{ChannelID: 1, Seq: 5})
	time.Sleep(100 * time.Millisecond)
	if reads.Load() != 0 {
		t.Fatalf("a message hint caused %d reads", reads.Load())
	}

	// A hint when nothing changed: one read, no reload.
	n.Publish(notify.Hint{})
	waitCount(t, reads, 1, "reads")
	time.Sleep(100 * time.Millisecond)
	if changes.Load() != 0 || m.Bundle().TrustNumber != held {
		t.Fatalf("a hint with nothing changed reloaded: %d OnChange calls", changes.Load())
	}

	// Another Trust changed the material: the next read finds it. The fake
	// clock has not moved, so this hint waits out the one-second limit once.
	e.tx(t, func(ctx context.Context, tx store.Tx) error {
		_, err := tx.BumpTrustNumber(ctx, e.nowMs())
		return err
	})
	n.Publish(notify.Hint{})
	waitCount(t, changes, 1, "OnChange calls")
	if got := m.Bundle().TrustNumber; got <= held {
		t.Fatalf("number = %d, held %d before", got, held)
	}
	// The manager's own hint (a real OnChange publishes one) finds the numbers equal.
	before := changes.Load()
	n.Publish(notify.Hint{})
	time.Sleep(1200 * time.Millisecond)
	if changes.Load() != before {
		t.Fatalf("a second hint reloaded again: %d OnChange calls, want %d", changes.Load(), before)
	}
}

// A clock that moves past the second lets the next hint read at once.
func TestManagerHintReadsAtMostOncePerSecond(t *testing.T) {
	e, m, _ := renewEnv(t)
	n, reads, _ := doorbell(t, m)
	for range 100 {
		n.Publish(notify.Hint{})
	}
	time.Sleep(1500 * time.Millisecond)
	if got := reads.Load(); got < 1 || got > 2 {
		t.Fatalf("a burst of 100 hints caused %d reads, want at most 2", got)
	}
	base := reads.Load()
	e.clk.advance(1100 * time.Millisecond)
	n.Publish(notify.Hint{})
	waitCount(t, reads, base+1, "reads after the second passed")
}
