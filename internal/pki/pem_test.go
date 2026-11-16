package pki

import (
	"crypto/rand"
	"crypto/x509"
	"math/big"
	"strings"
	"testing"
	"time"
)

func TestParsePEM(t *testing.T) {
	f := newFixture(t)
	csrDER, err := NewRequest(p256(t), "prod")
	if err != nil {
		t.Fatal(err)
	}
	crlDER, err := x509.CreateRevocationList(rand.Reader, &x509.RevocationList{
		Number: bigOne(), ThisUpdate: f.now, NextUpdate: f.now.Add(time.Hour),
	}, f.root, f.rootKey)
	if err != nil {
		t.Fatal(err)
	}
	parsers := []struct {
		name, typ string
		der       []byte
		other     string
		parse     func([]byte) error
	}{
		{"certificate", "CERTIFICATE", f.inter.Raw, "X509 CRL", func(b []byte) error { _, err := ParseCertificatePEM(b); return err }},
		{"request", "CERTIFICATE REQUEST", csrDER, "CERTIFICATE", func(b []byte) error { _, err := ParseRequestPEM(b); return err }},
		{"crl", "X509 CRL", crlDER, "CERTIFICATE", func(b []byte) error { _, err := ParseCRLPEM(b); return err }},
	}
	for _, p := range parsers {
		t.Run(p.name, func(t *testing.T) {
			lf := EncodePEM(p.typ, p.der)
			crlf := []byte(strings.ReplaceAll(string(lf), "\n", "\r\n"))
			for name, b := range map[string][]byte{"LF": lf, "CRLF": crlf} {
				if err := p.parse(b); err != nil {
					t.Errorf("%s refused: %v", name, err)
				}
			}
			refused := map[string]struct {
				in   []byte
				want string
			}{
				"DER":      {p.der, "not PEM"},
				"two":      {append(append([]byte(nil), lf...), lf...), "2 PEM blocks; want one"},
				"type":     {EncodePEM(p.other, p.der), p.other},
				"trailing": {append(append([]byte(nil), lf...), "junk\n"...), "trailing text"},
			}
			for name, c := range refused {
				err := p.parse(c.in)
				if err == nil || !strings.Contains(err.Error(), c.want) {
					t.Errorf("%s: err = %v, want it to say %q", name, err, c.want)
				}
			}
		})
	}
}

func bigOne() *big.Int { return big.NewInt(1) }
