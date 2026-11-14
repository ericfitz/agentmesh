package signingkeys

import (
	"context"

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
	m.mu.Lock()
	r, err := m.reloadReactLocked(ctx)
	m.mu.Unlock()
	if err != nil {
		return err
	}
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

// reloadReactLocked loads and reacts; caller holds mu.
func (m *Manager) reloadReactLocked(ctx context.Context) (reloaded, error) {
	now := m.trust.Now()
	wasOK := m.inPeriod(m.cur, now)
	wasStopped := m.stopped
	changed, err := m.reloadLocked(ctx)
	if err != nil {
		return reloaded{}, err
	}
	r := reloaded{changed: changed, rollback: m.mat.Rollback, notify: m.onChange}

	p, perr := m.trust.Pick(ctx, m.mat)
	if perr != nil {
		// Nothing says the key is gone: keep the state the last reload decided.
		r.pickErr = perr
	} else {
		m.stopped = m.stopReason(p, m.mat)
	}
	r.stopped = m.stopped
	if m.stopped != wasStopped {
		r.changed = true
	}
	okAfter := m.inPeriod(m.cur, now)
	if wasOK && !okAfter && m.cur != nil && m.revoked[m.cur.thumbprint] {
		r.ownLeaf = m.cur.thumbprint
	}
	r.wake = m.stopped == "" && !okAfter && (wasOK || wasStopped != "")
	return r, nil
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
	wrote := len(r.rollback) != 0 && m.writeBack(ctx, r.rollback)
	if (r.changed || wrote) && r.notify != nil {
		r.notify()
	}
}

// writeBack puts the CRLs a rollback removed back (Decision 27: restore from
// backup): under the trust lock, one transaction writes each held CRL whose
// stored row is older or gone and raises the trust number. Held elsewhere, it
// waits for the next reload with one log line and no error. It reports whether
// it wrote.
func (m *Manager) writeBack(ctx context.Context, held []store.TrustCRL) (wrote bool) {
	t := m.trust
	err := t.withLock(ctx, func(func(context.Context) error) error {
		return t.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			wrote = false
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
				wrote = true
			}
			if !wrote {
				return nil
			}
			_, err = tx.BumpTrustNumber(ctx, t.NowMs())
			return err
		})
	})
	switch {
	case err == nil:
		if wrote {
			t.Log.Warn("trust material rollback written back", "crls", len(held))
		}
		return wrote
	case isLockHeld(err):
		t.Log.Warn("trust material rollback: the write-back waits for the next reload, the trust lock is held elsewhere")
	default:
		t.Log.Warn("trust material rollback: the write-back failed", "error", failureLine(err))
	}
	return false
}
