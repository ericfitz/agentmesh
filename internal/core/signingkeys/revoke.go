package signingkeys

import (
	"context"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"sort"
	"time"

	"github.com/ericfitz/agentmesh/internal/auth/token"
	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/store"
)

// expiredLeafGrace is how long past its "not after" a leaf row stays.
const expiredLeafGrace = time.Hour

// removeBatch bounds one RemoveExpiredLeaves call.
const removeBatch = 500

// RevokeInput names what Revoke lists: exactly one of the three.
type RevokeInput struct {
	All    bool              // every unexpired leaf under the configured key (the host form of rotate)
	Cert   *x509.Certificate // one leaf, which the configured intermediate key must have signed
	Serial *big.Int          // one serial number, listed as given (Ruling 32)
}

// RevokedEntry is one line the host command prints for a revocation: the serial
// number (hex) of the entry, the thumbprint of its certificate when a row or the
// input gave one ("" for a bare serial number no row has) and the count of
// Decision 16 (that of the leaf's row, 0 for none).
type RevokedEntry struct {
	Serial        string
	Thumbprint    string
	HumanMessages int64
}

// maxSerialBits is the longest serial number a CRL entry may carry: 20 octets
// (RFC 5280) as a positive DER integer leaves 159 bits.
const maxSerialBits = 159

// RevokeResult is what Revoke did. Revoked is the leaves this call newly listed
// (the Bus form); Entries is what the host command prints: for All the same
// leaves, for Cert and Serial the one entry of the input, listed now or already
// (Changed false), with the serial number a bare serial needs.
type RevokeResult struct {
	Revoked     []bus.RevokedLeaf
	Entries     []RevokedEntry
	NotCovered  []string // thumbprints of unexpired leaves under another intermediate key (Ruling 4)
	TrustNumber int64
	Changed     bool // false: every serial number was already listed; nothing was written
}

// validate refuses an input that is not exactly one of the three forms.
func (in RevokeInput) validate() error {
	n := 0
	if in.All {
		n++
	}
	if in.Cert != nil {
		n++
	}
	if in.Serial != nil {
		n++
	}
	switch {
	case n != 1:
		return refuse("revoke needs exactly one of all leaves, one certificate or one serial number")
	case in.Cert != nil && (len(in.Cert.Raw) == 0 || in.Cert.SerialNumber == nil || in.Cert.SerialNumber.Sign() <= 0):
		return refuse("the certificate is empty or has no usable serial number")
	case in.Serial != nil && in.Serial.Sign() <= 0:
		return refuse("the serial number must be positive")
	case in.Serial != nil && in.Serial.BitLen() > maxSerialBits:
		return refuse("the serial number is longer than 20 octets")
	}
	return nil
}

// target is one leaf (or one bare serial number) a revocation lists.
type target struct {
	serial     *big.Int
	thumbprint string // "" for a serial number no stored leaf has
	id         int64  // the leaf row; 0 for none
}

func (x target) text() string { return pki.SerialText(x.serial) }

// coveredLeaves splits the unexpired leaves of mat into those under issuer key
// key (the targets of an "all" revocation, in row order, minus keep) and the
// thumbprints of those under another key (Ruling 4: not covered).
func coveredLeaves(mat Material, key string, now time.Time, keep string) (covered []target, notCovered []string) {
	for _, l := range mat.Leaves {
		// A leaf still verifies token.Leeway past its end, so it counts as unexpired.
		if now.After(l.Verified.NotAfter.Add(token.Leeway)) {
			continue
		}
		tp := pki.Thumbprint(l.Verified.Leaf.Raw)
		if keyIDOf(l.Verified.Intermediate) != key {
			if !l.Revoked {
				notCovered = append(notCovered, tp)
			}
			continue
		}
		if tp != keep {
			covered = append(covered, target{serial: l.Verified.Leaf.SerialNumber, thumbprint: tp, id: l.ID})
		}
	}
	return covered, notCovered
}

// listedSerials is every leaf serial number (hex) already revoked under key:
// the entries of the stored CRL and every one the process kept (Decision 27).
func listedSerials(mat Material, key string) map[string]bool {
	out := map[string]bool{}
	if crl := mat.LeafCRLs[key]; crl != nil {
		for _, e := range crl.RevokedCertificateEntries {
			out[pki.SerialText(e.SerialNumber)] = true
		}
	}
	for _, s := range mat.Revoked.Leaves[key] {
		out[s] = true
	}
	return out
}

// nextLeafCRL builds the next leaf CRL of the picked key (section 4.8, step 5):
// every serial number already listed plus every target, signed by the
// intermediate key under SignTimeout, numbered pki.NextNumber over the stored
// number. newly is the targets that were not listed before, each once. With
// force false and nothing new, no CRL is made (row zero, signed false).
func (t Trust) nextLeafCRL(ctx context.Context, mat Material, p Picked, now time.Time, targets []target, force bool) (row store.TrustCRL, newly []target, signed bool, err error) {
	key := keyIDOf(p.Use)
	listed := listedSerials(mat, key)
	all := make(map[string]*big.Int, len(listed)+len(targets))
	for s := range listed {
		n, ok := new(big.Int).SetString(s, 16)
		if !ok {
			continue
		}
		all[s] = n
	}
	for _, x := range targets {
		if listed[x.text()] {
			continue
		}
		listed[x.text()] = true // each once
		newly = append(newly, x)
		all[x.text()] = x.serial
	}
	if len(newly) == 0 && !force {
		return store.TrustCRL{}, nil, false, nil
	}
	serials := make([]*big.Int, 0, len(all))
	for _, n := range all {
		serials = append(serials, n)
	}
	sort.Slice(serials, func(i, j int) bool { return serials[i].Cmp(serials[j]) < 0 })

	number := pki.NextNumber(now, priorNumber(mat, key))
	signCtx, cancel := context.WithTimeout(ctx, SignTimeout)
	defer cancel()
	signer, err := t.signerFor(signCtx, p)
	if err != nil {
		return store.TrustCRL{}, nil, false, providerError(err)
	}
	if !samePublic(signer.Public(), p.Use.PublicKey) {
		t.Log.Error(msgNotCertKey, "intermediate", pki.Thumbprint(p.Use.Raw))
		return store.TrustCRL{}, nil, false, errors.New("signingkeys: " + msgNotCertKey)
	}
	der, err := pki.CreateCRL(p.Use, CryptoSigner(signCtx, signer), number, now, serials)
	if err != nil {
		return store.TrustCRL{}, nil, false, providerError(err)
	}
	return store.TrustCRL{
		Kind: store.TrustLeafCRL, Thumbprint: pki.Thumbprint(der), DER: der, IssuerKey: key,
		Number: number, CreatedAt: t.NowMs(),
	}, newly, true, nil
}

// priorNumber is the number of the leaf CRL this process holds for key (the
// stored one, or the kept one after a rollback); 0 for none.
func priorNumber(mat Material, key string) int64 {
	if crl := mat.LeafCRLs[key]; crl != nil {
		return pki.CRLNumber(crl)
	}
	return 0
}

// logNotCovered says which unexpired leaves a revocation cannot cover.
func (t Trust) logNotCovered(notCovered []string) {
	for _, tp := range notCovered {
		t.Log.Warn("signingkeys: a leaf certificate under another intermediate key is not covered by this revocation", "thumbprint", tp)
	}
}

// Revoke is the host form of revocation: under the trust lock it loads the
// material, builds the next leaf CRL and writes it with the trust number in one
// transaction. It issues no leaf. Errors that wrap ErrCheck are refused inputs
// (the host command exits 2).
//
// State (Definition of Done D): a second run lists nothing new and writes
// nothing (Changed false); two runs at once, or one while a rotation runs, find
// the lock held and answer a retryable unavailable; a run that failed before its
// transaction left nothing, so the retry starts from the stored state.
func (t Trust) Revoke(ctx context.Context, mem *Memory, in RevokeInput) (RevokeResult, error) {
	if err := in.validate(); err != nil {
		return RevokeResult{}, err
	}
	if t.Provider == nil {
		return RevokeResult{}, errors.New("signingkeys: no key provider is configured")
	}
	var res RevokeResult
	err := t.withLock(ctx, func(renew func(context.Context) error) error {
		res = RevokeResult{}
		mat, err := t.Load(ctx, mem)
		if err != nil {
			return err
		}
		p, err := t.Pick(ctx, mat)
		if err != nil {
			return err
		}
		if err := t.check(p, mat); err != nil {
			return fmt.Errorf("%w: %w", ErrCheck, err)
		}
		key, now := keyIDOf(p.Use), t.Now()

		var targets []target
		switch {
		case in.All:
			var notCovered []string
			targets, notCovered = coveredLeaves(mat, key, now, "")
			res.NotCovered = notCovered
			t.logNotCovered(notCovered)
		case in.Cert != nil:
			if !signedByConfigured(in.Cert, p.Configured) {
				return refuse("the certificate was not signed by the configured intermediate key")
			}
			x := target{serial: in.Cert.SerialNumber, thumbprint: pki.Thumbprint(in.Cert.Raw)}
			x.id = leafRowID(mat, key, x.thumbprint)
			targets = []target{x}
		default:
			x := target{serial: in.Serial}
			for _, l := range mat.Leaves {
				if keyIDOf(l.Verified.Intermediate) == key && l.Verified.Leaf.SerialNumber.Cmp(in.Serial) == 0 {
					x.thumbprint, x.id = pki.Thumbprint(l.Verified.Leaf.Raw), l.ID
					break
				}
			}
			targets = []target{x}
		}

		row, newly, signed, err := t.nextLeafCRL(ctx, mat, p, now, targets, false)
		if err != nil {
			return err
		}
		shown := newly // what the host prints: the newly listed leaves, or the one input
		if !in.All {
			shown = targets
		}
		if !signed {
			res.TrustNumber = mat.Number
			return t.Store.Read(ctx, func(ctx context.Context, tx store.Tx) error {
				var err error
				res.Entries, err = entriesOf(ctx, tx, shown)
				return err
			})
		}
		if err := renew(ctx); err != nil {
			return err
		}
		return t.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
			res.Revoked, res.Entries, res.Changed = nil, nil, false
			entries, err := entriesOf(ctx, tx, shown)
			if err != nil {
				return err
			}
			if err := tx.PutCRL(ctx, row); err != nil {
				return err
			}
			n, err := tx.BumpTrustNumber(ctx, t.NowMs())
			if err != nil {
				return err
			}
			res.Revoked, res.Entries, res.TrustNumber, res.Changed = revokedOf(entries, newly), entries, n, true
			return nil
		})
	})
	if err != nil {
		return RevokeResult{}, closeError(err)
	}
	return res, nil
}

// entriesOf is the report lines of targets, with the human messages each
// signed.
func entriesOf(ctx context.Context, tx store.Tx, targets []target) ([]RevokedEntry, error) {
	out := make([]RevokedEntry, 0, len(targets))
	for _, x := range targets {
		n, err := countSigned(ctx, tx, x.id)
		if err != nil {
			return nil, err
		}
		out = append(out, RevokedEntry{Serial: x.text(), Thumbprint: x.thumbprint, HumanMessages: n})
	}
	return out, nil
}

// revokedOf is the Bus form of the entries of the newly listed leaves; a bare
// serial number has no thumbprint and is not a leaf of the Bus form.
func revokedOf(entries []RevokedEntry, newly []target) []bus.RevokedLeaf {
	isNew := make(map[string]bool, len(newly))
	for _, x := range newly {
		isNew[x.text()] = true
	}
	out := make([]bus.RevokedLeaf, 0, len(newly))
	for _, e := range entries {
		if isNew[e.Serial] && e.Thumbprint != "" {
			out = append(out, bus.RevokedLeaf{Thumbprint: e.Thumbprint, HumanMessages: e.HumanMessages})
		}
	}
	return out
}

func signedByConfigured(c *x509.Certificate, configured []*x509.Certificate) bool {
	for _, in := range configured {
		if c.CheckSignatureFrom(in) == nil {
			return true
		}
	}
	return false
}

func leafRowID(mat Material, key, thumbprint string) int64 {
	for _, l := range mat.Leaves {
		if keyIDOf(l.Verified.Intermediate) == key && pki.Thumbprint(l.Verified.Leaf.Raw) == thumbprint {
			return l.ID
		}
	}
	return 0
}

// List is the unexpired leaves with state other or revoked, and the trust
// number (the host form of list: a host process has no current or previous
// leaf).
func (t Trust) List(ctx context.Context, mem *Memory) (bus.SigningKeyList, error) {
	mat, err := t.Load(ctx, mem)
	if err != nil {
		return bus.SigningKeyList{}, err
	}
	return signingKeyList(t.Now(), mat, "", ""), nil
}

// signingKeyList is the unexpired leaves of mat in the order current, previous,
// other, revoked (row order within each); current and previous name leaves by
// thumbprint ("" for none), and a revoked leaf is revoked whatever it was.
func signingKeyList(now time.Time, mat Material, current, previous string) bus.SigningKeyList {
	groups := map[string][]bus.SigningKey{}
	for _, l := range mat.Leaves {
		if now.After(l.Verified.NotAfter) {
			continue
		}
		tp := pki.Thumbprint(l.Verified.Leaf.Raw)
		state := bus.SigningKeyOther
		switch {
		case l.Revoked:
			state = bus.SigningKeyRevoked
		case tp == current:
			state = bus.SigningKeyCurrent
		case tp == previous:
			state = bus.SigningKeyPrevious
		}
		groups[state] = append(groups[state], busLeaf(l.Verified, state))
	}
	out := bus.SigningKeyList{Keys: []bus.SigningKey{}, TrustNumber: mat.Number}
	for _, state := range []string{bus.SigningKeyCurrent, bus.SigningKeyPrevious, bus.SigningKeyOther, bus.SigningKeyRevoked} {
		out.Keys = append(out.Keys, groups[state]...)
	}
	return out
}

// busLeaf is the Bus form of a verified leaf: public facts only.
func busLeaf(v pki.Verified, state string) bus.SigningKey {
	return bus.SigningKey{
		Thumbprint:       pki.Thumbprint(v.Leaf.Raw),
		Serial:           pki.SerialText(v.Leaf.SerialNumber),
		IssuerThumbprint: pki.Thumbprint(v.Intermediate.Raw),
		State:            state,
		NotBefore:        v.NotBefore.UnixMilli(),
		NotAfter:         v.NotAfter.UnixMilli(),
	}
}

// RemoveExpiredLeaves deletes leaf rows whose "not after" is more than an hour
// past, at most 500 a call, and returns how many it deleted. An intermediate row
// is never deleted, and a revoked leaf's serial number stays on the CRL (Ruling
// 7). A leaf row is append-only, so no lock is taken and the trust number does
// not change; a second run finds nothing more to delete.
func (t Trust) RemoveExpiredLeaves(ctx context.Context) (int, error) {
	var n int
	err := t.Store.Tx(ctx, func(ctx context.Context, tx store.Tx) error {
		n = 0
		rows, err := tx.ExpiredLeafCertificates(ctx, t.Now().Add(-expiredLeafGrace).UnixMilli(), removeBatch)
		if err != nil || len(rows) == 0 {
			return err
		}
		ids := make([]int64, len(rows))
		for i, r := range rows {
			ids[i] = r.ID
		}
		n, err = tx.DeleteTrustCertificates(ctx, ids)
		return err
	})
	if err != nil {
		return 0, core.FromStore(err)
	}
	return n, nil
}
