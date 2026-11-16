package store

import "context"

// Trust material kinds (ADR 0019 section 4.5). A certificate row is an
// intermediate or a leaf; a CRL row is the root CRL or the CRL of one
// intermediate key. The trust number row is internal to the Store.
const (
	TrustIntermediate = "intermediate"
	TrustLeaf         = "leaf"
	TrustRootCRL      = "root_crl"
	TrustLeafCRL      = "leaf_crl"
)

// TrustCertificate is one row of public trust material: an intermediate
// certificate or a leaf certificate. The Store holds facts; it never verifies
// a chain.
type TrustCertificate struct {
	ID         int64  // assigned by PutTrustCertificate; stable for the life of the row
	Kind       string // TrustIntermediate or TrustLeaf
	Thumbprint string
	DER        []byte
	IssuerKey  string // a leaf: the intermediate key's identifier; an intermediate: ""
	NotAfter   int64  // Unix milliseconds
	KeyRef     string // an intermediate with a key service: the pinned reference; else ""
	CreatedAt  int64
}

// TrustCRL is one stored certificate revocation list.
type TrustCRL struct {
	Kind       string // TrustRootCRL (IssuerKey "") or TrustLeafCRL
	Thumbprint string
	DER        []byte
	IssuerKey  string
	Number     int64
	CreatedAt  int64
}

// TrustMaterial holds the public trust material: certificates, CRLs and the
// trust number (Decision 39). The Store applies no rule to a row.
type TrustMaterial interface {
	// PutTrustCertificate inserts a row. ErrInvalid: a kind outside the two, an
	// empty thumbprint or DER, NotAfter or CreatedAt <= 0, an intermediate with
	// an IssuerKey, a leaf without one or with a KeyRef. ErrConflict: (kind,
	// thumbprint) exists. Write transactions only.
	PutTrustCertificate(ctx context.Context, c TrustCertificate) (id int64, err error)
	// TrustCertificates lists the rows of kind by id ascending; empty non-nil.
	TrustCertificates(ctx context.Context, kind string) ([]TrustCertificate, error)
	TrustCertificateByThumbprint(ctx context.Context, kind, thumbprint string) (TrustCertificate, bool, error)
	// PutCRL inserts the row of (kind, issuer key) or replaces it when c.Number
	// is higher than the stored one; otherwise ErrConflict. ErrInvalid as for
	// PutTrustCertificate, and for Number <= 0.
	PutCRL(ctx context.Context, c TrustCRL) error
	// CRLs lists the root CRL first, then the leaf CRLs by issuer key.
	CRLs(ctx context.Context) ([]TrustCRL, error)
	// TrustNumber reads the stored trust number (0 on a new store).
	TrustNumber(ctx context.Context) (int64, error)
	// BumpTrustNumber sets the number to the larger of now and the stored number
	// plus one and returns it (Decision 39). On Postgres it also sends the
	// control notification in the transaction.
	BumpTrustNumber(ctx context.Context, now int64) (int64, error)
	// ExpiredLeafCertificates lists at most limit leaf rows with NotAfter below
	// before, by NotAfter then id. ErrInvalid for limit < 1.
	ExpiredLeafCertificates(ctx context.Context, before int64, limit int) ([]TrustCertificate, error)
	// DeleteTrustCertificates deletes leaf rows by id and returns how many; an id
	// of any other row is ErrInvalid and nothing is deleted (intermediate rows
	// are never deleted, Ruling 33). Unknown ids are ignored.
	DeleteTrustCertificates(ctx context.Context, ids []int64) (int, error)
}
