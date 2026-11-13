package pki

import (
	"crypto"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"math/big"
)

// maxInstallationName is the longest installation name.
const maxInstallationName = 64

// Thumbprint is the SHA-256 of a certificate's DER encoding, base64url without
// padding: the form in which a root is pinned.
func Thumbprint(der []byte) string {
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// SubjectKeyID is the subject key identifier of a public key: the first 20
// bytes of the SHA-256 of its PKIX encoding (Plan ruling 4). The same key
// always gets the same identifier.
func SubjectKeyID(pub crypto.PublicKey) ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("pki: encode public key: %w", err)
	}
	sum := sha256.Sum256(der)
	return sum[:20], nil
}

// KeyID is the lowercase hex text of a key identifier.
func KeyID(ski []byte) string { return hex.EncodeToString(ski) }

// SerialText is the lowercase hex text of a serial number, without leading
// zeros.
func SerialText(n *big.Int) string { return n.Text(16) }

// ValidInstallationName checks the form of an installation name (Ruling 30):
// 1 to 64 characters of a to z, 0 to 9, "." and "-", the first a letter or a
// digit.
func ValidInstallationName(name string) error {
	if name == "" {
		return fmt.Errorf("installation name is empty")
	}
	if len(name) > maxInstallationName {
		return fmt.Errorf("installation name is %d bytes; at most %d", len(name), maxInstallationName)
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		alnum := c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
		if !alnum && (i == 0 || (c != '.' && c != '-')) {
			return fmt.Errorf("installation name %q: byte %d is not allowed (use a to z, 0 to 9, \".\" and \"-\", starting with a letter or digit)", name, i)
		}
	}
	return nil
}
