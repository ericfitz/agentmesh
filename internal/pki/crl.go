package pki

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// NextNumber is the number of the next CRL a signer issues: the clock in
// milliseconds, or one more than the previous number when the clock has not
// moved past it (Decisions 27 and 39).
func NextNumber(now time.Time, previous int64) int64 {
	if n := now.UnixMilli(); n > previous {
		return n
	}
	return previous + 1
}

// CreateCRL signs a CRL for issuer: "this update" is now, "next update" the
// issuer's "not after" (nobody enforces it, spec 4.9) and each entry's
// revocation time now. The issuer needs a subject key identifier and the CRL
// signing usage, which the profiles give.
func CreateCRL(issuer *x509.Certificate, key crypto.Signer, number int64, now time.Time, serials []*big.Int) ([]byte, error) {
	return createCRL(issuer, key, big.NewInt(number), now, serials)
}

func createCRL(issuer *x509.Certificate, key crypto.Signer, number *big.Int, now time.Time, serials []*big.Int) ([]byte, error) {
	entries := make([]x509.RevocationListEntry, 0, len(serials))
	for _, s := range serials {
		entries = append(entries, x509.RevocationListEntry{SerialNumber: s, RevocationTime: now})
	}
	next := issuer.NotAfter
	if next.Before(now) {
		// An issuer that expired before now still signs (its CRL then fails
		// CheckCRL); the encoding needs a next update that is not before this one.
		next = now
	}
	der, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number:                    number,
		ThisUpdate:                now,
		NextUpdate:                next,
		RevokedCertificateEntries: entries,
	}, issuer, key)
	if err != nil {
		return nil, fmt.Errorf("pki: create CRL: %w", err)
	}
	return der, nil
}

// ParseCRL parses a DER CRL and refuses one without a CRL number.
func ParseCRL(der []byte) (*x509.RevocationList, error) {
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse CRL: %w", err)
	}
	if crl.Number == nil || !crl.Number.IsInt64() {
		return nil, errors.New("pki: the CRL has no usable CRL number")
	}
	return crl, nil
}

// CheckCRL verifies the CRL's signature against issuer and that issuer was
// valid at the CRL's "this update" (Ruling 13).
func CheckCRL(crl *x509.RevocationList, issuer *x509.Certificate) error {
	if err := crl.CheckSignatureFrom(issuer); err != nil {
		return fmt.Errorf("pki: CRL signature: %w", err)
	}
	if crl.ThisUpdate.Before(issuer.NotBefore) || crl.ThisUpdate.After(issuer.NotAfter) {
		return errors.New("pki: the CRL's issuer was not valid at its \"this update\"")
	}
	return nil
}

// CRLNumber is the CRL's number; ParseCRL guarantees there is one.
func CRLNumber(crl *x509.RevocationList) int64 {
	if crl.Number == nil {
		return 0
	}
	return crl.Number.Int64()
}
