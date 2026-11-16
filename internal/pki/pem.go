package pki

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
)

const (
	pemCertificate = "CERTIFICATE"
	pemRequest     = "CERTIFICATE REQUEST"
	pemCRL         = "X509 CRL"
)

// EncodePEM wraps der in one PEM block of the given type ("CERTIFICATE",
// "CERTIFICATE REQUEST" or "X509 CRL").
func EncodePEM(blockType string, der []byte) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: blockType, Bytes: der})
}

// onePEM returns the DER of the single block of the given type that b holds.
// It refuses anything else and says what it found.
func onePEM(b []byte, want string) ([]byte, error) {
	block, rest := pem.Decode(b)
	if block == nil {
		return nil, fmt.Errorf("not PEM")
	}
	if next, _ := pem.Decode(rest); next != nil {
		return nil, fmt.Errorf("2 PEM blocks; want one")
	}
	if block.Type != want {
		return nil, fmt.Errorf("PEM block of type %q; want %q", block.Type, want)
	}
	if len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("trailing text after the PEM block")
	}
	return block.Bytes, nil
}

// ParseCertificatePEM parses one CERTIFICATE block.
func ParseCertificatePEM(b []byte) (*x509.Certificate, error) {
	der, err := onePEM(b, pemCertificate)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// ParseRequestPEM parses one CERTIFICATE REQUEST block with ParseRequest's checks.
func ParseRequestPEM(b []byte) (*x509.CertificateRequest, error) {
	der, err := onePEM(b, pemRequest)
	if err != nil {
		return nil, err
	}
	return ParseRequest(der)
}

// ParseCRLPEM parses one X509 CRL block.
func ParseCRLPEM(b []byte) (*x509.RevocationList, error) {
	der, err := onePEM(b, pemCRL)
	if err != nil {
		return nil, err
	}
	return x509.ParseRevocationList(der)
}
