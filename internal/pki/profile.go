package pki

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

// ErrLeafValidity: IssueLeaf was asked for a validity that is not positive or
// is above MaxLeafLifetime less LeafBackdate (the longest leaf CheckChain
// accepts).
var ErrLeafValidity = errors.New("pki: the leaf validity is out of range")

// ErrIssuerNotValid: IssueLeaf was asked to sign under an intermediate that is
// not valid at the issue time.
var ErrIssuerNotValid = errors.New("pki: the intermediate is not valid at the issue time")

// ErrRequestKey: the request's key is not ECDSA P-256. IssueIntermediate wraps
// it, so the root tool can tell a refused input (exit 2) from a failure (exit 1).
var ErrRequestKey = errors.New("pki: the request's key is not ECDSA P-256")

// serial returns a random positive 128-bit serial number.
func serial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	for {
		n, err := rand.Int(rand.Reader, limit)
		if err != nil {
			return nil, fmt.Errorf("pki: serial number: %w", err)
		}
		if n.Sign() > 0 {
			return n, nil
		}
	}
}

// NewRoot makes a self-signed root certificate: a CA that signs certificates
// and CRLs, with a subject key identifier and no extended key usage.
func NewRoot(key crypto.Signer, commonName string, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	ski, err := SubjectKeyID(key.Public())
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: commonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SubjectKeyId:          ski,
	}
	return create(tmpl, tmpl, key.Public(), key)
}

// NewRequest makes a DER certificate request whose subject common name is the
// installation name.
func NewRequest(key crypto.Signer, installation string) ([]byte, error) {
	if err := ValidInstallationName(installation); err != nil {
		return nil, err
	}
	der, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: installation},
	}, key)
	if err != nil {
		return nil, fmt.Errorf("pki: create request: %w", err)
	}
	return der, nil
}

// ParseRequest parses a DER request, verifies its own signature and refuses an
// empty or invalid common name. A bad request signature is caught here.
func ParseRequest(der []byte) (*x509.CertificateRequest, error) {
	csr, err := x509.ParseCertificateRequest(der)
	if err != nil {
		return nil, fmt.Errorf("parse request: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("request signature does not verify: %w", err)
	}
	if csr.Subject.CommonName == "" {
		return nil, errors.New("request has no subject common name (the installation name)")
	}
	if err := ValidInstallationName(csr.Subject.CommonName); err != nil {
		return nil, fmt.Errorf("request common name: %w", err)
	}
	return csr, nil
}

// IssueIntermediate signs an intermediate CA certificate for csr under root:
// path length 0, the agentmesh usage, the subject common name copied from the
// request. The request's key must be ECDSA P-256 (ErrRequestKey otherwise).
func IssueIntermediate(root *x509.Certificate, rootKey crypto.Signer, csr *x509.CertificateRequest, notBefore, notAfter time.Time) (*x509.Certificate, error) {
	pub, ok := csr.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, fmt.Errorf("%w (got %T)", ErrRequestKey, csr.PublicKey)
	}
	if err := ValidInstallationName(csr.Subject.CommonName); err != nil {
		return nil, fmt.Errorf("request common name: %w", err)
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	ski, err := SubjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: csr.Subject.CommonName},
		NotBefore:             notBefore,
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{ExtKeyUsageAgentmesh},
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            0,
		MaxPathLenZero:        true,
		SubjectKeyId:          ski,
		AuthorityKeyId:        root.SubjectKeyId,
	}
	return create(tmpl, root, pub, rootKey)
}

// IssueLeaf signs a leaf for pub under intermediate with the intermediate's
// key: CA false, digital signature, the agentmesh usage, a random 128-bit
// serial number, valid from now less LeafBackdate for validity, cut to the
// intermediate's "not after". It refuses a validity that is not positive or is
// above MaxLeafLifetime less LeafBackdate (ErrLeafValidity) and an
// intermediate that is not valid at now (ErrIssuerNotValid).
func IssueLeaf(intermediate *x509.Certificate, key crypto.Signer, pub ed25519.PublicKey, now time.Time, validity time.Duration) (*x509.Certificate, error) {
	if validity <= 0 || validity > MaxLeafLifetime-LeafBackdate {
		return nil, fmt.Errorf("%w: %s, want above 0 and at most %s", ErrLeafValidity, validity, MaxLeafLifetime-LeafBackdate)
	}
	if now.Before(intermediate.NotBefore) || now.After(intermediate.NotAfter) {
		return nil, fmt.Errorf("%w: %s is outside %s to %s", ErrIssuerNotValid, now.UTC().Format(time.RFC3339),
			intermediate.NotBefore.UTC().Format(time.RFC3339), intermediate.NotAfter.UTC().Format(time.RFC3339))
	}
	sn, err := serial()
	if err != nil {
		return nil, err
	}
	ski, err := SubjectKeyID(pub)
	if err != nil {
		return nil, err
	}
	notAfter := now.Add(validity)
	if notAfter.After(intermediate.NotAfter) {
		notAfter = intermediate.NotAfter
	}
	tmpl := &x509.Certificate{
		SerialNumber:          sn,
		Subject:               pkix.Name{CommonName: "agentmesh leaf"},
		NotBefore:             now.Add(-LeafBackdate),
		NotAfter:              notAfter,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{ExtKeyUsageAgentmesh},
		BasicConstraintsValid: true,
		SubjectKeyId:          ski,
		AuthorityKeyId:        intermediate.SubjectKeyId,
	}
	return create(tmpl, intermediate, pub, key)
}

// CheckRoot is what root_certificate_file must hold (Plan ruling 32): a CA
// certificate that may sign certificates, of any key type. It checks no time.
func CheckRoot(c *x509.Certificate) error {
	if !c.BasicConstraintsValid || !c.IsCA {
		return errors.New("root certificate is not a CA certificate")
	}
	if c.KeyUsage != 0 && c.KeyUsage&x509.KeyUsageCertSign == 0 {
		return errors.New("root certificate's key usage does not allow signing certificates")
	}
	return nil
}

func create(tmpl, parent *x509.Certificate, pub crypto.PublicKey, signer crypto.Signer) (*x509.Certificate, error) {
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parent, pub, signer)
	if err != nil {
		return nil, fmt.Errorf("pki: create certificate: %w", err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, fmt.Errorf("pki: parse new certificate: %w", err)
	}
	return c, nil
}
