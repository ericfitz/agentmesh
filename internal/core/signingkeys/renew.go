package signingkeys

import (
	"context"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/ericfitz/agentmesh/internal/auth/token"
	"github.com/ericfitz/agentmesh/internal/core/notify"
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
		if _, err := m.reload(ctx); err != nil {
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
	cur := m.cur
	inPeriod := cur != nil && cur.verified.ValidAt(now, 0)
	if !inPeriod && !m.retryAt.IsZero() && (!m.retryOutside || m.retryAt.After(now.Add(minRetry))) {
		// A retry timed for a leaf the clock has since left (a stepped clock):
		// Ruling 13 wins over the retry schedule.
		m.retryAt = time.Time{}
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
		return
	}
	msg := failureLine(err)
	m.failure = &Failure{At: now, Message: msg}
	m.retryOutside = m.cur == nil || !m.cur.verified.ValidAt(now, 0)
	m.retryAt = now.Add(m.retryDelay(now))
	m.trust.Log.Warn("signingkeys: issuing the leaf failed", "error", msg, "retry_at", m.retryAt.UTC().Format(time.RFC3339))
}

// retryDelay is the wait after a failed issue at now. Caller holds mu.
func (m *Manager) retryDelay(now time.Time) time.Duration {
	if m.cur == nil || !m.cur.verified.ValidAt(now, 0) {
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
	case !m.retryAt.IsZero():
		t = m.retryAt
	case m.cur != nil && m.cur.verified.ValidAt(now, 0):
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

// Run calls Step until ctx ends, sleeping until the time it returned. The
// returned time is on the core's clock: Run waits the difference between it and
// the core's now on a real timer, so a stepped clock only shortens or lengthens
// one wait (Step is at most token.ReloadInterval ahead). hints may be nil; a
// hints is unused until Task 29 makes a hint that carries no message wake Run.
func (m *Manager) Run(ctx context.Context, _ notify.Notifier) {
	for ctx.Err() == nil {
		next := m.Step(ctx)
		wait := next.Sub(m.trust.Now())
		if wait < 0 {
			wait = 0
		}
		timer := time.NewTimer(wait)
		select {
		case <-ctx.Done():
			timer.Stop()
			return
		case <-timer.C:
		}
	}
}
