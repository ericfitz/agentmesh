package signingkeys

import (
	"context"
	"errors"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/store"
)

// The admin API forms (issue #6; Eric 2026-10-27 decision 6): the server's
// handlers call them with the authenticated identity and the Service checks
// that it may administer the server inside the transaction, as the other
// administrator operations do. The host command and the scheduler call List,
// Rotate and RotatePrepared, which are trusted and check nothing.

// busKey converts a row to the Bus form: the old key set in the leaf shape
// (ADR 0019 section 4.11; Task 15, until Task 23 replaces the set). The
// thumbprint is the KID, the state is current for the active row and previous
// for a retiring one, the validity is the row's creation and removal times,
// and the serial and the issuer thumbprint, which a row has not, are empty.
// The private key is never copied.
func busKey(r store.SigningKey) bus.SigningKey {
	state := bus.SigningKeyPrevious
	if r.State == store.SigningKeyActive {
		state = bus.SigningKeyCurrent
	}
	return bus.SigningKey{Thumbprint: r.KID, State: state, NotBefore: r.CreatedAt, NotAfter: r.RemoveAfter}
}

// ListSigningKeys returns the key set, the active key first, for an
// administrator. The trust number is 0 until Task 23.
func (s Service) ListSigningKeys(ctx context.Context, admin string) (bus.SigningKeyList, error) {
	out := bus.SigningKeyList{}
	err := s.Store.Read(ctx, func(ctx context.Context, tx store.Tx) error {
		out.Keys = nil
		if err := s.RequireServerAdmin(ctx, tx, admin); err != nil {
			return err
		}
		rows, err := tx.ListSigningKeys(ctx)
		if err != nil {
			return err
		}
		out.Keys = make([]bus.SigningKey, len(rows))
		for i, r := range rows {
			out.Keys[i] = busKey(r)
		}
		return nil
	})
	if err != nil {
		return bus.SigningKeyList{}, core.FromStore(err)
	}
	return out, nil
}

// errReceiptMiss ends the receipt peek of RotateSigningKey when no receipt
// exists, so WithReceipt never stores one from a read transaction.
var errReceiptMiss = errors.New("no receipt")

// RotateSigningKey rotates the active key for an administrator; it always
// revokes the previous key (ADR 0019 Ruling 6), so the cooldown never applies
// to this form. The order is fixed by Decision 26 and the idempotency rule:
//
//  1. a read transaction checks the administrator flag and the receipt of
//     in.IdempotencyKey: a replay returns the original result, and a receipt
//     for another payload is a conflict, both without calling Provider.Next;
//  2. PrepareRotation runs outside every transaction;
//  3. the write transaction checks the flag again, then WithReceipt runs
//     ApplyRotation with RevokePrevious, which stores the result as the
//     receipt in the same transaction, so a rotation and its receipt commit
//     together or not at all; the result's Revoked holds the deleted key;
//  4. OnChange runs after the commit, for a new rotation only.
//
// State (Definition of Done D): a second call with the same key replays; a
// second call without a key rotates again. Two calls at once with the same
// key: both may call Next, one wins the commit and the other reruns inside
// WithReceipt and replays the winner's result (the unused key is discarded; a
// store key was never persisted). A call that fails after Next leaves the rows
// and receipts as they were, so the retry with the same key runs again.
func (s Service) RotateSigningKey(ctx context.Context, admin string, in bus.RotateSigningKeyInput) (bus.SigningKeyRotation, error) {
	payload := struct{}{} // the receipt payload is the empty object

	var (
		out      bus.SigningKeyRotation
		replayed bool
	)
	err := s.Store.Read(ctx, func(ctx context.Context, tx store.Tx) error {
		out, replayed = bus.SigningKeyRotation{}, false
		if err := s.RequireServerAdmin(ctx, tx, admin); err != nil {
			return err
		}
		r, err := s.WithReceipt(ctx, tx, admin, in.IdempotencyKey, payload, &out, func() error { return errReceiptMiss })
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

	p, err := s.PrepareRotation(ctx)
	if err != nil {
		return bus.SigningKeyRotation{}, err
	}
	for attempt := 1; ; attempt++ {
		err = s.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			out, replayed = bus.SigningKeyRotation{}, false
			if err := s.RequireServerAdmin(ctx, tx, admin); err != nil {
				return err
			}
			r, err := s.WithReceipt(ctx, tx, admin, in.IdempotencyKey, payload, &out, func() error {
				res, e := s.ApplyRotation(ctx, tx, p, RotateInput{RevokePrevious: true})
				if e != nil {
					return e
				}
				out = bus.SigningKeyRotation{Current: busKey(res.Active), Revoked: []bus.RevokedLeaf{}}
				if res.Previous.KID != "" {
					out.Revoked = append(out.Revoked, bus.RevokedLeaf{Thumbprint: res.Previous.KID})
				}
				return nil
			})
			replayed = r
			return err
		})
		if rerun(err, attempt) {
			continue
		}
		break
	}
	if err != nil {
		return bus.SigningKeyRotation{}, core.FromStore(err)
	}
	if !replayed {
		s.changed()
	}
	return out, nil
}
