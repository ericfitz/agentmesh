package bus

// TrustBundle is the trust material a client verifies the server's certificate
// chains with (ADR 0019 section 4.9). A bundle in a session or receive answer
// has no Root and no Installation; the discover document's has both.
type TrustBundle struct {
	TrustNumber   int64
	Intermediates [][]byte // DER; every stored intermediate, the revoked and the expired included
	RootCRL       []byte   // DER; nil when none is installed
	LeafCRLs      [][]byte // DER; empty when no leaf was ever revoked
	Root          []byte   // DER; the discover document only
	Installation  string   // the discover document only
}
