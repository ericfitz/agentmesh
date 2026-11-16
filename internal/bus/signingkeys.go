package bus

// SigningKeysNotConfigured is the fixed text of the unavailable error (not
// retryable) that the signing key operations answer where the server has no
// signing keys: local mode, or a server built without a key service.
const SigningKeysNotConfigured = "this server has no signing keys (local mode)"

// The states of a SigningKey (ADR 0019 section 4.11).
const (
	SigningKeyCurrent  = "current"  // the answering process's current leaf
	SigningKeyPrevious = "previous" // its previous leaf
	SigningKeyOther    = "other"    // another process's leaf
	SigningKeyRevoked  = "revoked"
)

// SigningKey is one leaf certificate that signs bearers: public facts only,
// never a private key. Thumbprint is the certificate thumbprint (the kid),
// Serial its serial number in hex and IssuerThumbprint the thumbprint of the
// intermediate that issued it; the last two are empty while the old key set
// answers (until Task 23). State is one of the four constants above.
// NotBefore and NotAfter are Unix milliseconds.
type SigningKey struct {
	Thumbprint, Serial, IssuerThumbprint, State string
	NotBefore, NotAfter                         int64
}

// SigningKeyList is the unexpired leaves, the current one first, and the
// trust number (0 until the trust material is wired).
type SigningKeyList struct {
	Keys        []SigningKey
	TrustNumber int64
}

// RotateSigningKeyInput is the rotation's idempotency key; a rotation always
// revokes the previous leaf (ADR 0019 Ruling 6).
type RotateSigningKeyInput struct{ IdempotencyKey string }

// RevokedLeaf is one leaf a rotation revoked. HumanMessages counts the human
// messages it signed; always 0 until spec 2.
type RevokedLeaf struct {
	Thumbprint    string
	HumanMessages int64
}

// SigningKeyRotation reports a rotation: the new current leaf, the leaves it
// revoked (empty when the set had none) and the trust number.
type SigningKeyRotation struct {
	Current     SigningKey
	Revoked     []RevokedLeaf
	TrustNumber int64
}
