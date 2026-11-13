package sqlstore

import (
	"context"
	"fmt"

	"github.com/jmoiron/sqlx"

	"github.com/ericfitz/agentmesh/internal/store"
)

// trust_material (ADR 0019 section 4.5) is new in v2; no v1 source. Every
// method is one statement (or one statement per chunk of ids) inside the
// caller's transaction, so a rerun of a failed transaction repeats it whole.

type trustRow struct {
	ID         int64  `db:"id"`
	Kind       string `db:"kind"`
	Thumbprint string `db:"thumbprint"`
	DER        []byte `db:"der"`
	IssuerKey  string `db:"issuer_key"`
	NotAfter   int64  `db:"not_after"`
	Number     int64  `db:"number"`
	KeyRef     string `db:"key_ref"`
	CreatedAt  int64  `db:"created_at"`
}

const trustColumns = "id, kind, thumbprint, der, issuer_key, not_after, number, key_ref, created_at"

func (r trustRow) certificate() store.TrustCertificate {
	return store.TrustCertificate{ID: r.ID, Kind: r.Kind, Thumbprint: r.Thumbprint, DER: r.DER,
		IssuerKey: r.IssuerKey, NotAfter: r.NotAfter, KeyRef: r.KeyRef, CreatedAt: r.CreatedAt}
}

func trustCertificateKind(kind string) error {
	if kind != store.TrustIntermediate && kind != store.TrustLeaf {
		return fmt.Errorf("%w: unknown trust certificate kind %q (want %s or %s)", store.ErrInvalid, kind, store.TrustIntermediate, store.TrustLeaf)
	}
	return nil
}

func validateTrustCertificate(c store.TrustCertificate) error {
	if err := trustCertificateKind(c.Kind); err != nil {
		return err
	}
	if c.Thumbprint == "" || len(c.DER) == 0 {
		return fmt.Errorf("%w: trust certificate thumbprint and DER must not be empty", store.ErrInvalid)
	}
	if c.NotAfter <= 0 || c.CreatedAt <= 0 {
		return fmt.Errorf("%w: trust certificate not_after and created_at must be positive", store.ErrInvalid)
	}
	if c.Kind == store.TrustIntermediate && c.IssuerKey != "" {
		return fmt.Errorf("%w: an intermediate trust certificate has no issuer key", store.ErrInvalid)
	}
	if c.Kind == store.TrustLeaf && (c.IssuerKey == "" || c.KeyRef != "") {
		return fmt.Errorf("%w: a leaf trust certificate needs an issuer key and no key ref", store.ErrInvalid)
	}
	return checkText("trust certificate", "thumbprint", c.Thumbprint, "issuer key", c.IssuerKey, "key ref", c.KeyRef)
}

func validateTrustCRL(c store.TrustCRL) error {
	switch {
	case c.Kind != store.TrustRootCRL && c.Kind != store.TrustLeafCRL:
		return fmt.Errorf("%w: unknown CRL kind %q (want %s or %s)", store.ErrInvalid, c.Kind, store.TrustRootCRL, store.TrustLeafCRL)
	case c.Thumbprint == "" || len(c.DER) == 0:
		return fmt.Errorf("%w: CRL thumbprint and DER must not be empty", store.ErrInvalid)
	case c.Number <= 0 || c.CreatedAt <= 0:
		return fmt.Errorf("%w: CRL number and created_at must be positive", store.ErrInvalid)
	case c.Kind == store.TrustRootCRL && c.IssuerKey != "":
		return fmt.Errorf("%w: the root CRL has no issuer key", store.ErrInvalid)
	case c.Kind == store.TrustLeafCRL && c.IssuerKey == "":
		return fmt.Errorf("%w: a leaf CRL needs an issuer key", store.ErrInvalid)
	}
	return checkText("CRL", "thumbprint", c.Thumbprint, "issuer key", c.IssuerKey)
}

func (t *tx) PutTrustCertificate(ctx context.Context, c store.TrustCertificate) (int64, error) {
	if err := t.writable(); err != nil {
		return 0, err
	}
	if err := validateTrustCertificate(c); err != nil {
		return 0, err
	}
	var id int64
	err := t.getW(ctx, &id, "INSERT INTO trust_material (kind, thumbprint, der, issuer_key, not_after, key_ref, created_at) VALUES (?, ?, ?, ?, ?, ?, ?) RETURNING id",
		c.Kind, c.Thumbprint, c.DER, c.IssuerKey, c.NotAfter, c.KeyRef, c.CreatedAt)
	if isConflict(err) {
		return 0, fmt.Errorf("%w: trust certificate %s %q exists", store.ErrConflict, c.Kind, c.Thumbprint)
	}
	if err != nil {
		return 0, err
	}
	return id, nil
}

func (t *tx) TrustCertificates(ctx context.Context, kind string) ([]store.TrustCertificate, error) {
	if err := trustCertificateKind(kind); err != nil {
		return nil, err
	}
	var rows []trustRow
	if err := t.sel(ctx, &rows, "SELECT "+trustColumns+" FROM trust_material WHERE kind = ? ORDER BY id", kind); err != nil {
		return nil, err
	}
	return trustCertificates(rows), nil
}

func trustCertificates(rows []trustRow) []store.TrustCertificate {
	out := make([]store.TrustCertificate, 0, len(rows))
	for _, r := range rows {
		out = append(out, r.certificate())
	}
	return out
}

func (t *tx) TrustCertificateByThumbprint(ctx context.Context, kind, thumbprint string) (store.TrustCertificate, bool, error) {
	if err := trustCertificateKind(kind); err != nil {
		return store.TrustCertificate{}, false, err
	}
	if badText(thumbprint) {
		return store.TrustCertificate{}, false, nil
	}
	var rows []trustRow
	if err := t.sel(ctx, &rows, "SELECT "+trustColumns+" FROM trust_material WHERE kind = ? AND thumbprint = ?", kind, thumbprint); err != nil {
		return store.TrustCertificate{}, false, err
	}
	if len(rows) == 0 {
		return store.TrustCertificate{}, false, nil
	}
	return rows[0].certificate(), true, nil
}

func (t *tx) PutCRL(ctx context.Context, c store.TrustCRL) error {
	if err := t.writable(); err != nil {
		return err
	}
	if err := validateTrustCRL(c); err != nil {
		return err
	}
	res, err := t.execW(ctx, "UPDATE trust_material SET thumbprint = ?, der = ?, number = ?, created_at = ? WHERE kind = ? AND issuer_key = ? AND number < ?",
		c.Thumbprint, c.DER, c.Number, c.CreatedAt, c.Kind, c.IssuerKey, c.Number)
	if err != nil {
		return err
	}
	if n, err := res.RowsAffected(); err != nil {
		return err
	} else if n > 0 {
		return nil
	}
	// No row replaced: insert, or the stored number is not lower.
	_, err = t.execW(ctx, "INSERT INTO trust_material (kind, thumbprint, der, issuer_key, number, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		c.Kind, c.Thumbprint, c.DER, c.IssuerKey, c.Number, c.CreatedAt)
	if isConflict(err) {
		return fmt.Errorf("%w: a %s for issuer key %q with number %d or higher is stored", store.ErrConflict, c.Kind, c.IssuerKey, c.Number)
	}
	return err
}

func (t *tx) CRLs(ctx context.Context) ([]store.TrustCRL, error) {
	var rows []trustRow
	if err := t.sel(ctx, &rows, "SELECT "+trustColumns+" FROM trust_material WHERE kind IN ('root_crl', 'leaf_crl')"+
		" ORDER BY (CASE WHEN kind = 'root_crl' THEN 0 ELSE 1 END), issuer_key"); err != nil {
		return nil, err
	}
	out := make([]store.TrustCRL, 0, len(rows))
	for _, r := range rows {
		out = append(out, store.TrustCRL{Kind: r.Kind, Thumbprint: r.Thumbprint, DER: r.DER, IssuerKey: r.IssuerKey, Number: r.Number, CreatedAt: r.CreatedAt})
	}
	return out, nil
}

func (t *tx) TrustNumber(ctx context.Context) (int64, error) {
	var n int64
	if err := t.get(ctx, &n, "SELECT number FROM trust_material WHERE kind = 'trust_number'"); err != nil {
		return 0, err
	}
	return n, nil
}

// BumpTrustNumber locks the row by writing it back first, so two bumps
// serialize on it and each reads the other's committed number.
func (t *tx) BumpTrustNumber(ctx context.Context, now int64) (int64, error) {
	if err := t.writable(); err != nil {
		return 0, err
	}
	var stored int64
	if err := t.getW(ctx, &stored, "UPDATE trust_material SET number = number WHERE kind = 'trust_number' RETURNING number"); err != nil {
		return 0, err
	}
	next := max(now, stored+1)
	if _, err := t.execW(ctx, "UPDATE trust_material SET number = ?, created_at = ? WHERE kind = 'trust_number'", next, now); err != nil {
		return 0, err
	}
	if n, ok := t.d.(ControlNotifier); ok {
		if err := n.NotifyControl(ctx, t.tx); err != nil {
			return 0, err
		}
	}
	return next, nil
}

func (t *tx) ExpiredLeafCertificates(ctx context.Context, before int64, limit int) ([]store.TrustCertificate, error) {
	if limit < 1 {
		return nil, fmt.Errorf("%w: expired leaf limit must be at least 1", store.ErrInvalid)
	}
	var rows []trustRow
	if err := t.sel(ctx, &rows, "SELECT "+trustColumns+" FROM trust_material WHERE kind = 'leaf' AND not_after < ? ORDER BY not_after, id LIMIT ?", before, limit); err != nil {
		return nil, err
	}
	return trustCertificates(rows), nil
}

const trustDeleteChunk = 500

func (t *tx) DeleteTrustCertificates(ctx context.Context, ids []int64) (int, error) {
	if err := t.writable(); err != nil {
		return 0, err
	}
	var chunks [][]int64
	for i := 0; i < len(ids); i += trustDeleteChunk {
		chunks = append(chunks, ids[i:min(i+trustDeleteChunk, len(ids))])
	}
	for _, ch := range chunks {
		q, args, err := sqlx.In("SELECT count(*) FROM trust_material WHERE kind <> 'leaf' AND id IN (?)", ch)
		if err != nil {
			return 0, err
		}
		var other int
		if err := t.get(ctx, &other, q, args...); err != nil {
			return 0, err
		}
		if other > 0 {
			return 0, fmt.Errorf("%w: only leaf trust certificate rows are deleted", store.ErrInvalid)
		}
	}
	total := 0
	for _, ch := range chunks {
		q, args, err := sqlx.In("DELETE FROM trust_material WHERE kind = 'leaf' AND id IN (?)", ch)
		if err != nil {
			return 0, err
		}
		res, err := t.execW(ctx, q, args...)
		if err != nil {
			return 0, err
		}
		n, err := res.RowsAffected()
		if err != nil {
			return 0, err
		}
		total += int(n)
	}
	return total, nil
}
