package signingkeys

import (
	"context"
	"time"

	"github.com/ericfitz/agentmesh/internal/store"
)

// The values of Stopped.
const (
	stopIntermediateExpired = "intermediate_expired"
	stopIntermediateRevoked = "intermediate_revoked"
	stopRootExpired         = "root_expired"
)

// Stopped is "" or why the manager no longer issues or signs:
// "intermediate_expired", "intermediate_revoked" or "root_expired". Every
// reload decides it again, so a renewed intermediate certificate ends the first
// stop with no restart.
func (m *Manager) Stopped() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.stopped
}

// reloaded is what one reload left for the caller to do once mu is free.
type reloaded struct {
	changed  bool
	stopped  string
	wake     bool
	ownLeaf  string // thumbprint of the current leaf when this reload found it revoked
	pickErr  error
	rollback []store.TrustCRL
	notify   func()
}

// Reload is the load of the trust material followed by the reactions of
// sections 4.8 and 4.15: it decides whether the manager has stopped, notices
// that the current leaf was revoked (the manager then signs with nothing and a
// new leaf is due now: Run is woken and the next Step issues it), writes back
// the CRLs a rollback of the stored rows removed, and calls OnChange when the
// trust number or the published set changed. It never issues (Plan ruling 33):
// it also runs inside LoadKeys, on a request's goroutine, and inside
// RotateSigningKey, which holds the issuing mutex.
func (m *Manager) Reload(ctx context.Context) error {
	// Pick reads the key file: it runs between two holds of mu, on the loaded
	// material (LoadKeys keeps one hold, as it needs the set from it).
	m.mu.Lock()
	l, err := m.loadLocked(ctx)
	m.mu.Unlock()
	if err != nil {
		return err
	}
	p, perr := m.trust.Pick(ctx, l.mat)
	m.mu.Lock()
	r := m.reactLocked(l, p, perr)
	m.mu.Unlock()
	m.finishReload(ctx, r)
	return nil
}

// stopReason is why a manager over p and mat may not issue at now, or "". The
// manager writes no matching rule of its own: p is what Trust.Pick found.
func (m *Manager) stopReason(p Picked, mat Material) string {
	now := m.trust.Now()
	switch {
	case now.Before(m.trust.Root.NotBefore) || now.After(m.trust.Root.NotAfter):
		return stopRootExpired
	case p.Use == nil:
		return stopIntermediateExpired
	case mat.RevokedKeys[keyIDOf(p.Use)]:
		return stopIntermediateRevoked
	}
	return ""
}

// loaded is what the load step of a reload captured for the reactions.
type loaded struct {
	now        time.Time
	wasOK      bool
	wasStopped string
	changed    bool
	mat        Material
	notify     func()
}

// loadLocked loads the material; caller holds mu.
func (m *Manager) loadLocked(ctx context.Context) (loaded, error) {
	l := loaded{now: m.trust.Now(), wasOK: m.inPeriod(m.cur, m.trust.Now()), wasStopped: m.stopped}
	changed, err := m.reloadLocked(ctx)
	if err != nil {
		return loaded{}, err
	}
	l.changed, l.mat, l.notify = changed, m.mat, m.onChange
	return l, nil
}

// reactLocked applies the reactions to what Pick found; caller holds mu. It
// tolerates a Pick taken from material older than m.mat (the window between
// Reload's two holds of mu); the next reload corrects it.
func (m *Manager) reactLocked(l loaded, p Picked, perr error) reloaded {
	r := reloaded{changed: l.changed, rollback: l.mat.Rollback, notify: l.notify}
	if perr != nil {
		// Nothing says the key is gone: keep the state the last reload decided.
		r.pickErr = perr
	} else {
		m.stopped = m.stopReason(p, l.mat)
	}
	r.stopped = m.stopped
	if m.stopped != l.wasStopped {
		r.changed = true
	}
	okAfter := m.inPeriod(m.cur, l.now)
	if l.wasOK && !okAfter && m.cur != nil && m.revoked[m.cur.thumbprint] {
		r.ownLeaf = m.cur.thumbprint
	}
	r.wake = m.stopped == "" && !okAfter && (l.wasOK || l.wasStopped != "")
	return r
}

// reloadReactLocked loads and reacts under one hold of mu (LoadKeys needs the
// set from the same hold); caller holds mu.
func (m *Manager) reloadReactLocked(ctx context.Context) (reloaded, error) {
	l, err := m.loadLocked(ctx)
	if err != nil {
		return reloaded{}, err
	}
	p, perr := m.trust.Pick(ctx, l.mat)
	return m.reactLocked(l, p, perr), nil
}

// finishReload does what a reload leaves that needs no lock of the manager: log
// lines, the wake, the write-back of a rollback and OnChange.
func (m *Manager) finishReload(ctx context.Context, r reloaded) {
	log := m.trust.Log
	if r.pickErr != nil {
		log.Warn("signingkeys: the configured intermediate key could not be matched; keeping the last state", "error", failureLine(r.pickErr))
	}
	if r.stopped != "" {
		log.Error("signingkeys: this process no longer issues or signs leaf certificates", "reason", r.stopped)
	}
	if r.ownLeaf != "" {
		log.Warn("signingkeys: the current leaf certificate is revoked; a new one is due now", "thumbprint", r.ownLeaf)
	}
	if r.wake {
		select {
		case m.wake <- struct{}{}:
		default:
		}
	}
	wrote := len(r.rollback) != 0 && m.writeBack(ctx, r.rollback) > 0
	if (r.changed || wrote) && r.notify != nil {
		r.notify()
	}
}

// writeBack puts the CRLs a rollback removed back (Decision 27: restore from
// backup): under the trust lock, one transaction writes each held CRL whose
// stored row is older or gone and raises the trust number. Held elsewhere, it
// waits for the next reload with one log line and no error. It reports how many
// CRLs it wrote.
func (m *Manager) writeBack(ctx context.Context, held []store.TrustCRL) (written int) {
	t := m.trust
	err := t.withLock(ctx, func(func(context.Context) error) error {
		return t.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			written = 0
			stored, err := tx.CRLs(ctx)
			if err != nil {
				return err
			}
			have := map[[2]string]int64{}
			for _, s := range stored {
				have[[2]string{s.Kind, s.IssuerKey}] = s.Number
			}
			for _, h := range held {
				if n, ok := have[[2]string{h.Kind, h.IssuerKey}]; ok && n >= h.Number {
					continue
				}
				if err := tx.PutCRL(ctx, h); err != nil {
					return err
				}
				written++
			}
			if written == 0 {
				return nil
			}
			_, err = tx.BumpTrustNumber(ctx, t.NowMs())
			return err
		})
	})
	switch {
	case err == nil:
		if written > 0 {
			t.Log.Warn("trust material rollback written back", "crls", written)
		}
		return written
	case isLockHeld(err):
		t.Log.Warn("trust material rollback: the write-back waits for the next reload, the trust lock is held by another caller or by the operation that is reloading")
	default:
		t.Log.Warn("trust material rollback: the write-back failed", "error", failureLine(err))
	}
	return 0
}
