package signingkeys

import (
	"context"
	"errors"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
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

// rotateError maps what a rotation returned: a stopped manager is an
// unavailable that is not retryable (an operator must act), and any other
// error is left to core.FromStore.
func rotateError(err error) error {
	for _, e := range []error{ErrNoIntermediate, ErrIntermediateExpired, ErrIntermediateRevoked, ErrRootExpired} {
		if errors.Is(err, e) {
			return bus.Errorf(bus.CodeUnavailable, false, "%s", err.Error())
		}
	}
	return core.FromStore(providerError(err))
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
			return err
		}
		key, now := keyIDOf(pl.picked.Use), t.Now()
		targets, notCovered := coveredLeaves(mat, key, now, pl.row.Thumbprint)
		t.logNotCovered(notCovered)
		crl, newly, _, err := t.nextLeafCRL(ctx, mat, pl.picked, now, targets, true)
		if err != nil {
			return err
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
				revoked, err := revokedLeaves(ctx, tx, newly)
				if err != nil {
					return err
				}
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
		return bus.SigningKeyRotation{}, rotateError(err)
	}
	return out, nil
}
