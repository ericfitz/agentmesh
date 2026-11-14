package signingkeys

import (
	"context"
	"errors"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/keyprovider"
	"github.com/ericfitz/agentmesh/internal/store"
)

var _ interface {
	ListSigningKeys(ctx context.Context, admin string) (bus.SigningKeyList, error)
	RotateSigningKey(ctx context.Context, admin string, in bus.RotateSigningKeyInput) (bus.SigningKeyRotation, error)
} = (*Manager)(nil)

// countSigned is the number of human messages the leaf leafID signed: 0 until
// spec 2 adds messages that carry a signature.
func countSigned(_ context.Context, _ store.Tx, _ int64) (int64, error) { return 0, nil }

// ListSigningKeys is the admin API form of list: the unexpired leaves, the
// current one first, then previous, other and revoked, and the trust number.
// It reloads first, so the answer shows what the Store holds.
func (m *Manager) ListSigningKeys(ctx context.Context, admin string) (bus.SigningKeyList, error) {
	err := m.trust.Store.Read(ctx, func(ctx context.Context, tx store.Tx) error {
		return m.trust.RequireServerAdmin(ctx, tx, admin)
	})
	if err != nil {
		return bus.SigningKeyList{}, core.FromStore(err)
	}
	m.mu.Lock()
	r, err := m.reloadReactLocked(ctx)
	if err != nil {
		m.mu.Unlock()
		return bus.SigningKeyList{}, err
	}
	var cur, prev string
	if m.usable(m.cur, m.trust.Now()) {
		cur = m.cur.thumbprint
	}
	if m.prev != nil {
		prev = m.prev.thumbprint
	}
	l := signingKeyList(m.trust.Now(), m.mat, cur, prev)
	m.mu.Unlock()
	m.finishReload(ctx, r)
	return l, nil
}

// issueFailure maps a failure of the signing steps of a rotation (a leaf, the
// CRL) so that none is a 500 (the no-500 rule): an outage or a timeout of the
// key service or key file is a retryable unavailable; a stopped manager (no
// stored intermediate, expired, revoked, root expired) and any other failure of
// the key (a mismatch, an unreadable file, a refused signature) is an
// unavailable that is not retryable, because an operator must act. A canceled
// context is the caller gone: retryable and not logged. Errors that are bus
// errors already pass.
func issueFailure(log interface{ Error(string, ...any) }, err error) error {
	if err == nil {
		return nil
	}
	var be *bus.Error
	if errors.As(err, &be) {
		return err
	}
	gone := errors.Is(err, context.Canceled) // the caller went away: not an error of the key
	retryable := gone || errors.Is(err, keyprovider.ErrUnavailable) || errors.Is(err, context.DeadlineExceeded)
	if !retryable {
		log.Error("signingkeys: a forced renewal could not sign", "error", failureLine(err))
	}
	return &bus.Error{Code: bus.CodeUnavailable, Message: "cannot issue a leaf certificate: " + failureLine(err), Retryable: retryable, Cause: err}
}

// RotateSigningKey is the forced renewal (section 4.8, the seven steps in
// order): (1) a read transaction checks the administrator and the receipt of
// the idempotency key, and a replay returns the first answer and changes
// nothing; (2) the trust lock, or a retryable unavailable, and from there the
// issuing mutex; (3) a reload, which never issues; (4) a new leaf, signed and
// verified but not stored; (5) the next leaf CRL, which lists every unexpired
// leaf of the configured key but the new one; (6) the lease renewed, then one
// transaction: the administrator check again, the receipt, the new leaf's row,
// the CRL and the trust number; (7) after the commit the manager signs with the
// new leaf and OnChange runs. A rotation always revokes (Ruling 6).
//
// State (Definition of Done D): a second call with the same key replays and
// writes nothing; a second call without a key rotates again and revokes the
// first one's leaf; two calls at once (one process or two) leave one winner and
// a retryable unavailable for the other; a call that fails before its
// transaction leaves a lost, unused leaf key in memory and nothing stored, so
// the retry with the same key runs again.
func (m *Manager) RotateSigningKey(ctx context.Context, admin string, in bus.RotateSigningKeyInput) (bus.SigningKeyRotation, error) {
	t := m.trust
	payload := struct{}{} // the receipt payload is the empty object

	var (
		out      bus.SigningKeyRotation
		replayed bool
	)
	err := t.Store.Read(ctx, func(ctx context.Context, tx store.Tx) error {
		out, replayed = bus.SigningKeyRotation{}, false
		if err := t.RequireServerAdmin(ctx, tx, admin); err != nil {
			return err
		}
		r, err := t.WithReceipt(ctx, tx, admin, in.IdempotencyKey, payload, &out, func() error { return errReceiptMiss })
		if errors.Is(err, errReceiptMiss) {
			return nil
		}
		replayed = r
		return err
	})
	if err != nil {
		return bus.SigningKeyRotation{}, core.FromStore(err)
	}
	if replayed {
		return out, nil
	}

	err = t.withLock(ctx, func(renew func(context.Context) error) error {
		m.issueMu.Lock()
		defer m.issueMu.Unlock()
		out, replayed = bus.SigningKeyRotation{}, false

		if err := m.Reload(ctx); err != nil {
			return err
		}
		m.mu.Lock()
		mat := m.mat
		m.mu.Unlock()

		pl, err := m.mintLeaf(ctx, mat)
		if err != nil {
			return issueFailure(t.Log, err)
		}
		key, now := keyIDOf(pl.picked.Use), t.Now()
		targets, notCovered := coveredLeaves(mat, key, now, pl.row.Thumbprint)
		t.logNotCovered(notCovered)
		crl, newly, _, err := t.nextLeafCRL(ctx, mat, pl.picked, now, targets, true)
		if err != nil {
			return issueFailure(t.Log, err)
		}
		if err := renew(ctx); err != nil {
			return err
		}

		err = t.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			out, replayed = bus.SigningKeyRotation{}, false
			if err := t.RequireServerAdmin(ctx, tx, admin); err != nil {
				return err
			}
			r, err := t.WithReceipt(ctx, tx, admin, in.IdempotencyKey, payload, &out, func() error {
				entries, err := entriesOf(ctx, tx, newly)
				if err != nil {
					return err
				}
				revoked := revokedOf(entries, newly)
				if _, err := tx.PutTrustCertificate(ctx, pl.row); err != nil {
					return err
				}
				if err := tx.PutCRL(ctx, crl); err != nil {
					return err
				}
				n, err := tx.BumpTrustNumber(ctx, t.NowMs())
				if err != nil {
					return err
				}
				out = bus.SigningKeyRotation{Current: busLeaf(pl.key.verified, bus.SigningKeyCurrent), Revoked: revoked, TrustNumber: n}
				return nil
			})
			replayed = r
			return err
		})
		if err != nil || replayed {
			return err
		}
		if notify := m.adopt(pl); notify != nil {
			notify()
		}
		return nil
	})
	if err != nil {
		return bus.SigningKeyRotation{}, core.FromStore(err)
	}
	return out, nil
}
