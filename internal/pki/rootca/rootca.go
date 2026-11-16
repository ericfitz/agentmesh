// Package rootca is the root tool's rules (ADR 0019 Decision 9, spec 4.3): a
// small root CA kept in a directory. It imports the standard library and
// internal/pki only.
package rootca

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"time"

	"github.com/ericfitz/agentmesh/internal/pki"
)

// ErrRefused marks a refused input: the command exits 2. Any other error is
// an I/O failure, exit 1.
var ErrRefused = errors.New("rootca: refused")

const (
	defaultInitDays = 3650
	defaultSignDays = 365
	defaultName     = "agentmesh root"
	day             = 24 * time.Hour
)

func refuse(format string, args ...any) error {
	return fmt.Errorf("%w: %s", ErrRefused, fmt.Sprintf(format, args...))
}

// Init makes the root key (ECDSA P-256), the self-signed root certificate and
// an empty state.json in dir, and returns the root's thumbprint. It never
// overwrites: root.key is created exclusively, and a directory that already
// holds any of the files is refused with the file named.
func Init(dir, name string, days int, now time.Time) (thumbprint string, err error) {
	if days < 0 {
		return "", refuse("days is %d, want 0 or more", days)
	}
	if days == 0 {
		days = defaultInitDays
	}
	if name == "" {
		name = defaultName
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", fmt.Errorf("rootca: %w", err)
	}
	for _, f := range []string{"root.pem", "state.json"} {
		if _, err := os.Stat(filepath.Join(dir, f)); err == nil {
			return "", refuse("%s already holds %s; it never overwrites a root", dir, f)
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("rootca: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", fmt.Errorf("rootca: %w", err)
	}
	keyPath := filepath.Join(dir, "root.key")
	f, err := os.OpenFile(keyPath, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if errors.Is(err, os.ErrExist) {
		return "", refuse("%s exists; if no root.pem was made, remove it and run again", keyPath)
	}
	if err != nil {
		return "", fmt.Errorf("rootca: %w", err)
	}
	_, werr := f.Write(pki.EncodePEM("PRIVATE KEY", keyDER))
	if cerr := f.Close(); werr == nil {
		werr = cerr
	}
	if werr != nil {
		return "", fmt.Errorf("rootca: write %s: %w", keyPath, werr)
	}
	root, err := pki.NewRoot(key, name, now, now.Add(time.Duration(days)*day))
	if err != nil {
		return "", fmt.Errorf("rootca: %w", err)
	}
	if err := writeFileAtomic(filepath.Join(dir, "root.pem"), pki.EncodePEM("CERTIFICATE", root.Raw)); err != nil {
		return "", err
	}
	if err := saveState(dir, &state{Version: stateVersion, Issued: []issued{}}); err != nil {
		return "", err
	}
	return pki.Thumbprint(root.Raw), nil
}

// Root reads dir's root certificate.
func Root(dir string) (*x509.Certificate, error) {
	b, err := os.ReadFile(filepath.Join(dir, "root.pem"))
	if err != nil {
		return nil, fmt.Errorf("rootca: %w", err)
	}
	c, err := pki.ParseCertificatePEM(b)
	if err != nil {
		return nil, fmt.Errorf("rootca: root.pem: %w", err)
	}
	return c, nil
}

func rootKey(dir string) (crypto.Signer, error) {
	b, err := os.ReadFile(filepath.Join(dir, "root.key"))
	if err != nil {
		return nil, fmt.Errorf("rootca: %w", err)
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return nil, errors.New("rootca: root.key holds no PEM block")
	}
	k, err := x509.ParsePKCS8PrivateKey(blk.Bytes)
	if err != nil {
		return nil, fmt.Errorf("rootca: root.key: %w", err)
	}
	s, ok := k.(crypto.Signer)
	if !ok {
		return nil, errors.New("rootca: root.key is not a signing key")
	}
	return s, nil
}

// Sign issues an intermediate certificate for csr under dir's root and
// records it in state.json before returning it. A name already recorded for
// another key is refused unless sameInstallation is set (Decision 37, Ruling
// 43); a renewal (the recorded key) and a new name need no flag.
func Sign(dir string, csr *x509.CertificateRequest, days int, sameInstallation bool, now time.Time) (*x509.Certificate, error) {
	if days < 0 {
		return nil, refuse("days is %d, want 0 or more", days)
	}
	if days == 0 {
		days = defaultSignDays
	}
	name := csr.Subject.CommonName
	if name == "" {
		return nil, refuse("the request has no subject common name; it must be the installation's name")
	}
	if err := pki.ValidInstallationName(name); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrRefused, err)
	}
	ski, err := pki.SubjectKeyID(csr.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("%w: the request's key: %v", ErrRefused, err)
	}
	keyID := pki.KeyID(ski)

	unlock, err := lockDir(dir)
	if err != nil {
		return nil, err
	}
	defer unlock()

	root, err := Root(dir)
	if err != nil {
		return nil, err
	}
	key, err := rootKey(dir)
	if err != nil {
		return nil, err
	}
	st, err := loadState(dir)
	if err != nil {
		return nil, err
	}
	taken, recorded, own := false, "", false
	for _, e := range st.Issued {
		if e.Name != name {
			continue
		}
		if e.Key == keyID {
			own = true
		} else if !taken {
			taken, recorded = true, e.Key
		}
	}
	taken = taken && !own
	if taken && !sameInstallation {
		return nil, refuse("the name %q is recorded with another key (%s); a second installation needs a name of its own, and one installation that changes its key passes -same-installation", name, recorded)
	}
	notAfter := now.Add(time.Duration(days) * day)
	if notAfter.After(root.NotAfter) {
		return nil, refuse("%d days ends after the root's expiry (%s)", days, root.NotAfter.UTC().Format(time.RFC3339))
	}
	cert, err := pki.IssueIntermediate(root, key, csr, now, notAfter)
	if errors.Is(err, pki.ErrRequestKey) {
		return nil, fmt.Errorf("%w: %v", ErrRefused, err)
	}
	if err != nil {
		return nil, fmt.Errorf("rootca: %w", err)
	}
	st.Issued = append(st.Issued, issued{
		Serial:     pki.SerialText(cert.SerialNumber),
		Thumbprint: pki.Thumbprint(cert.Raw),
		Name:       name,
		Key:        keyID,
		DER:        cert.Raw,
		NotAfter:   cert.NotAfter.UTC(),
	})
	if err := saveState(dir, st); err != nil {
		return nil, err
	}
	return cert, nil
}

// Revoke marks cert's key revoked: cert and every other issued certificate
// with the same subject key identifier. revoked lists the thumbprints this
// call newly revoked (empty on a repeat, which returns the current CRL with
// its number unchanged). state.json is replaced before root.crl, so a rerun
// after a failure completes the CRL.
func Revoke(dir string, cert *x509.Certificate, now time.Time) (crlDER []byte, revoked []string, err error) {
	thumb := pki.Thumbprint(cert.Raw)
	ski, err := pki.SubjectKeyID(cert.PublicKey)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: the certificate's key: %v", ErrRefused, err)
	}
	keyID := pki.KeyID(ski)

	unlock, err := lockDir(dir)
	if err != nil {
		return nil, nil, err
	}
	defer unlock()

	root, err := Root(dir)
	if err != nil {
		return nil, nil, err
	}
	st, err := loadState(dir)
	if err != nil {
		return nil, nil, err
	}
	known := false
	for _, e := range st.Issued {
		if e.Thumbprint == thumb {
			known = true
		}
	}
	if !known {
		return nil, nil, refuse("certificate %s was not issued by this root", thumb)
	}
	for i := range st.Issued {
		e := &st.Issued[i]
		if e.Key == keyID && !e.Revoked {
			e.Revoked = true
			revoked = append(revoked, e.Thumbprint)
		}
	}
	crlPath := filepath.Join(dir, "root.crl")
	if len(revoked) == 0 {
		if der, ok := currentCRL(crlPath, st); ok {
			return der, nil, nil
		}
		// A run died after state.json and before root.crl: complete it
		// with the number the state already holds.
	} else {
		st.CRLNumber = pki.NextNumber(now, st.CRLNumber)
		if err := saveState(dir, st); err != nil {
			return nil, nil, err
		}
	}
	key, err := rootKey(dir)
	if err != nil {
		return nil, nil, err
	}
	var serials []*big.Int
	for _, e := range st.Issued {
		if e.Revoked {
			n, ok := new(big.Int).SetString(e.Serial, 16)
			if !ok {
				return nil, nil, fmt.Errorf("rootca: state.json serial %q is not hexadecimal", e.Serial)
			}
			serials = append(serials, n)
		}
	}
	der, err := pki.CreateCRL(root, key, st.CRLNumber, now, serials)
	if err != nil {
		return nil, nil, fmt.Errorf("rootca: %w", err)
	}
	if err := writeFileAtomic(crlPath, pki.EncodePEM("X509 CRL", der)); err != nil {
		return nil, nil, err
	}
	return der, revoked, nil
}

// currentCRL returns root.crl's DER when it matches the state: the state's
// number and exactly the revoked serials.
func currentCRL(path string, st *state) ([]byte, bool) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, false
	}
	crl, err := pki.ParseCRLPEM(b)
	if err != nil || pki.CRLNumber(crl) != st.CRLNumber {
		return nil, false
	}
	want := map[string]bool{}
	for _, e := range st.Issued {
		if e.Revoked {
			want[e.Serial] = true
		}
	}
	if len(crl.RevokedCertificateEntries) != len(want) {
		return nil, false
	}
	for _, r := range crl.RevokedCertificateEntries {
		if !want[pki.SerialText(r.SerialNumber)] {
			return nil, false
		}
	}
	blk, _ := pem.Decode(b)
	return blk.Bytes, true
}
