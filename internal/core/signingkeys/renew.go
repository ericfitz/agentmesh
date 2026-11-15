package signingkeys

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ericfitz/agentmesh/internal/auth/token"
	"github.com/ericfitz/agentmesh/internal/core/notify"
	"github.com/ericfitz/agentmesh/internal/store"
)

// MaxFailureBytes bounds Failure.Message.
const MaxFailureBytes = 200

// minRetry is the least time between two attempts after a failed issue.
const minRetry = time.Minute

// Failure is the last failed issue of a leaf.
type Failure struct {
	At      time.Time
	Message string // one line, at most MaxFailureBytes bytes; a key service error is the backend's redacted text
}

// LastFailure is the last failed issue; false when there is none or the last
// issue succeeded. Safe for concurrent use.
func (m *Manager) LastFailure() (Failure, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.failure == nil {
		return Failure{}, false
	}
	return *m.failure, true
}

// failureLine is the first line of err's text cut to MaxFailureBytes on a
// UTF-8 boundary. Provider errors are already the backend's redacted text.
func failureLine(err error) string {
	s := strings.TrimSpace(err.Error())
	if i := strings.IndexAny(s, "\r\n"); i >= 0 {
		s = strings.TrimSpace(s[:i])
	}
	if len(s) > MaxFailureBytes {
		s = s[:MaxFailureBytes]
		for len(s) > 0 && !utf8.ValidString(s) {
			s = s[:len(s)-1]
		}
	}
	return s
}

// Step does what is due at the core's clock (a reload, a renewal, a retry) and
// returns when to call it again: the earliest of the next reload
// (token.ReloadInterval after the last one), the renewal time and a pending
// retry (Plan ruling 13). The result is never before the core's now and never
// more than token.ReloadInterval after it.
//
// The next leaf is issued at the current leaf's issue time plus W/2 and signs
// from then on. After a failed issue the next attempt is one eighth of the time
// left before the current leaf's "not after", never sooner than one minute;
// with no current leaf, or the clock outside its period, the first attempt is
// at once and each later one a minute after the last. A renewal and a retry
// hold the issuing mutex for the whole issue, and what is due is decided
// again under it, so two concurrent Steps issue once.
func (m *Manager) Step(ctx context.Context) time.Time {
	now := m.trust.Now()

	m.mu.Lock()
	reloadDue := m.lastReload.IsZero() || !now.Before(m.lastReload.Add(token.ReloadInterval)) || now.Before(m.lastReload)
	if reloadDue {
		m.lastReload = now
	}
	m.mu.Unlock()
	if reloadDue {
		if err := m.Reload(ctx); err != nil {
			m.trust.Log.Warn("signingkeys: reload of the trust material failed", "error", failureLine(err))
		}
	}

	m.issueMu.Lock()
	m.renewLocked(ctx)
	m.issueMu.Unlock()

	return m.nextDue()
}

// renewLocked issues a leaf when one is due. Caller holds issueMu.
func (m *Manager) renewLocked(ctx context.Context) {
	now := m.trust.Now()
	m.mu.Lock()
	if m.stopped != "" {
		m.mu.Unlock()
		return
	}
	cur := m.cur
	inPeriod := m.inPeriod(cur, now)
	if !inPeriod && !m.retryAt.IsZero() && (!m.retryOutside || m.retryAt.After(now.Add(minRetry))) {
		// A retry timed for a leaf the clock has since left (a stepped clock):
		// Ruling 13 wins over the retry schedule.
		m.retryAt = time.Time{}
		m.publishLocked()
	}
	due := !inPeriod || !now.Before(cur.issuedAt.Add(m.validity/2))
	if due && !m.retryAt.IsZero() && now.Before(m.retryAt) {
		due = false
	}
	m.mu.Unlock()
	if !due {
		return
	}

	err := m.issueLocked(ctx)
	now = m.trust.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	if err == nil {
		m.failure, m.retryAt = nil, time.Time{}
		m.publishLocked()
		return
	}
	msg := failureLine(err)
	m.failure = &Failure{At: now, Message: msg}
	m.retryOutside = !m.inPeriod(m.cur, now)
	m.retryAt = now.Add(m.retryDelay(now))
	m.publishLocked()
	m.trust.Log.Warn("signingkeys: issuing the leaf failed", "error", msg, "retry_at", m.retryAt.UTC().Format(time.RFC3339))
}

// retryDelay is the wait after a failed issue at now. Caller holds mu.
func (m *Manager) retryDelay(now time.Time) time.Duration {
	if !m.inPeriod(m.cur, now) {
		return minRetry
	}
	d := m.cur.verified.NotAfter.Sub(now) / 8
	if d < minRetry {
		d = minRetry
	}
	return d
}

// nextDue is the time Step returns.
func (m *Manager) nextDue() time.Time {
	now := m.trust.Now()
	m.mu.Lock()
	defer m.mu.Unlock()
	next := m.lastReload.Add(token.ReloadInterval)
	var t time.Time
	switch {
	case m.stopped != "":
		t = next // nothing to issue until a reload ends the stop
	case !m.retryAt.IsZero():
		t = m.retryAt
	case m.inPeriod(m.cur, now):
		t = m.cur.issuedAt.Add(m.validity / 2)
	default:
		t = now
	}
	if t.Before(next) {
		next = t
	}
	if next.Before(now) {
		next = now
	}
	if limit := now.Add(token.ReloadInterval); next.After(limit) {
		next = limit
	}
	return next
}

// trustReadInterval is the least time between two reads of the stored trust
// number that hints cause (Plan ruling 15).
const trustReadInterval = time.Second

// trustReadHook, when set (export_test.go), is called before each read of the
// stored trust number that a hint causes.
var trustReadHook func()

// reloadIfTrustChanged reads the stored trust number and reloads when it
// differs from the number this process holds. The manager's own change finds
// the numbers equal: its reload already replaced the snapshot.
func (m *Manager) reloadIfTrustChanged(ctx context.Context) {
	if trustReadHook != nil {
		trustReadHook()
	}
	var n int64
	err := m.trust.Store.Read(ctx, func(ctx context.Context, tx store.Tx) error {
		var err error
		n, err = tx.TrustNumber(ctx)
		return err
	})
	if err != nil {
		if ctx.Err() == nil {
			m.trust.Log.Warn("signingkeys: reading the trust number failed", "error", failureLine(err))
		}
		return
	}
	if n == m.Bundle().TrustNumber {
		return
	}
	if err := m.Reload(ctx); err != nil && ctx.Err() == nil {
		m.trust.Log.Warn("signingkeys: reload of the trust material failed", "error", failureLine(err))
	}
}

// Run calls Step until ctx ends, sleeping until the time it returned. The
// returned time is on the core's clock: Run waits the difference between it and
// the core's now on a real timer, so a stepped clock only shortens or lengthens
// one wait (Step is at most token.ReloadInterval ahead). Run also wakes when
// Reload makes an issue due (the manager's wake channel).
//
// hints may be nil. A hint with sequence number 0 is the trust doorbell: Run
// reads the stored trust number (at most once a second on the core's clock; a
// hint inside that second causes one later read when it ends) and reloads when
// it differs from the number it holds, so a change another process made does
// not wait for the next periodic reload (Plan ruling 15). A hint with a
// sequence number above 0 is a message and causes no read. The notifier holds
// one pending hint per subscriber, so a Seq-0 hint published while Run is busy
// (in Step, say) can be dropped; the periodic reload every token.ReloadInterval
// (30 seconds) covers it.
func (m *Manager) Run(ctx context.Context, hints notify.Notifier) {
	var hintC <-chan notify.Hint
	if hints != nil {
		c, cancel := hints.Subscribe()
		defer cancel()
		hintC = c
	}
	var lastRead time.Time
	var trail *time.Timer
	var trailC <-chan time.Time
	defer func() {
		if trail != nil {
			trail.Stop()
		}
	}()
	read := func() {
		if trail != nil {
			trail.Stop()
			trail, trailC = nil, nil
		}
		lastRead = m.trust.Now()
		m.reloadIfTrustChanged(ctx)
	}
	for ctx.Err() == nil {
		next := m.Step(ctx)
		wait := next.Sub(m.trust.Now())
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		if runParkedHook != nil {
			runParkedHook()
		}
	parked:
		for {
			select {
			case <-ctx.Done():
				timer.Stop()
				return
			case <-timer.C:
				break parked
			case <-m.wake:
				timer.Stop()
				break parked
			case h := <-hintC:
				if h.Seq != 0 {
					continue
				}
				now := m.trust.Now()
				switch {
				case lastRead.IsZero() || now.Before(lastRead) || !now.Before(lastRead.Add(trustReadInterval)):
					read()
				case trailC == nil:
					w := min(max(lastRead.Add(trustReadInterval).Sub(now), 0), trustReadInterval)
					trail = time.NewTimer(w)
					trailC = trail.C
				}
			case <-trailC:
				trail, trailC = nil, nil
				read()
			}
		}
	}
}
