package signingkeys_test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/auth/token"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/trusttest"
	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"
)

const issuerURL = "http://localhost:8420"

// signBearer signs an RFC 9068 access token the way a manager would, with the
// kid and x5t#S256 of leaf, but with a key and a certificate the test chose.
func signBearer(t *testing.T, key any, alg jose.SignatureAlgorithm, leaf *x509.Certificate, iat time.Time, life time.Duration) string {
	t.Helper()
	tp := pki.Thumbprint(leaf.Raw)
	opts := (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", tp).WithHeader("x5t#S256", tp)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: alg, Key: key}, opts)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.Claims{
		Issuer: issuerURL, Subject: "alice", Audience: jwt.Audience{issuerURL}, ID: "jti-1",
		IssuedAt: jwt.NewNumericDate(iat), Expiry: jwt.NewNumericDate(iat.Add(life)),
	}
	extra := struct {
		ClientID string `json:"client_id"`
		Kind     string `json:"agentmesh_kind"`
	}{"alice", token.KindAgent}
	raw, err := jwt.Signed(signer).Claims(claims).Claims(extra).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func (e *env) issuer(t *testing.T, src token.KeySource) *token.Issuer {
	t.Helper()
	iss, err := token.NewIssuer(context.Background(), issuerURL, src, time.Hour, e.clk.now)
	if err != nil {
		t.Fatalf("NewIssuer: %v", err)
	}
	return iss
}

func accepted(t *testing.T, iss *token.Issuer, raw string, at time.Time) {
	t.Helper()
	sub, err := iss.Verify(context.Background(), raw, at)
	if err != nil || sub != "alice" {
		t.Fatalf("Verify = %q, %v, want accepted", sub, err)
	}
}

func refused(t *testing.T, iss *token.Issuer, raw string, at time.Time) error {
	t.Helper()
	sub, err := iss.Verify(context.Background(), raw, at)
	if err == nil || sub != "" {
		t.Fatalf("Verify = %q, %v, want refused", sub, err)
	}
	return err
}

func unknownKey(t *testing.T, iss *token.Issuer, raw string, at time.Time) {
	t.Helper()
	if err := refused(t, iss, raw, at); !errors.Is(err, token.ErrUnknownKey) {
		t.Fatalf("err = %v, want ErrUnknownKey", err)
	}
}

func TestBearerMatrix(t *testing.T) {
	ctx := context.Background()
	const day = 24 * time.Hour

	t.Run("other-replica", func(t *testing.T) {
		e, m, _ := renewEnv(t)
		now := e.clk.now()
		priv, leaf := e.f.Leaf(t, e.c, now, day)
		accepted(t, e.issuer(t, m), signBearer(t, priv, jose.EdDSA, leaf, now, time.Hour), now)
	})
	t.Run("row-missing", func(t *testing.T) {
		e, m, _ := renewEnv(t)
		now := e.clk.now()
		priv, leaf := leafUnderKey(t, e.f.Intermediate, interKey(t, e.f), now, day)
		unknownKey(t, e.issuer(t, m), signBearer(t, priv, jose.EdDSA, leaf, now, time.Hour), now)
	})
	t.Run("row-altered", func(t *testing.T) {
		e, m, _ := renewEnv(t)
		now := e.clk.now()
		priv, leaf := leafUnderKey(t, e.f.Intermediate, interKey(t, e.f), now, day)
		other := leafFor(t, e.f, now, day)
		// The row is filed under the signing leaf's thumbprint but holds another certificate.
		e.putRow(t, storeLeafRow(leaf, other.Raw, keyID(e.f.Intermediate)))
		unknownKey(t, e.issuer(t, m), signBearer(t, priv, jose.EdDSA, leaf, now, time.Hour), now)
	})
	t.Run("self-signed", func(t *testing.T) {
		// The forged row of threat 2: a leaf that signed itself, filed under the real
		// intermediate key.
		e, m, _ := renewEnv(t)
		now := e.clk.now()
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		ski, err := pki.SubjectKeyID(pub)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: randSerial(t), Subject: pkix.Name{CommonName: "agentmesh leaf"},
			NotBefore: now.Add(-pki.LeafBackdate), NotAfter: now.Add(day),
			KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{pki.ExtKeyUsageAgentmesh},
			BasicConstraintsValid: true, SubjectKeyId: ski, AuthorityKeyId: e.f.Intermediate.SubjectKeyId,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		e.putLeaf(t, leaf, keyID(e.f.Intermediate))
		unknownKey(t, e.issuer(t, m), signBearer(t, priv, jose.EdDSA, leaf, now, time.Hour), now)
	})
	t.Run("other-root", func(t *testing.T) {
		e, m, _ := renewEnv(t)
		now := e.clk.now()
		o := trusttest.New(t, now)
		e.putIntermediate(t, o.Intermediate, "")
		priv, leaf := o.Leaf(t, e.c, now, day)
		unknownKey(t, e.issuer(t, m), signBearer(t, priv, jose.EdDSA, leaf, now, time.Hour), now)
	})
	t.Run("expired", func(t *testing.T) {
		e, m, _ := renewEnv(t)
		now := e.clk.now()
		priv, leaf := e.f.Leaf(t, e.c, now, day)
		raw := signBearer(t, priv, jose.EdDSA, leaf, now, 3*day)
		iss := e.issuer(t, m)
		accepted(t, iss, raw, now)
		e.clk.advance(leaf.NotAfter.Add(59 * time.Second).Sub(now))
		accepted(t, iss, raw, e.clk.now())
		e.clk.advance(2 * time.Second)
		_ = refused(t, iss, raw, e.clk.now())
	})
	t.Run("revoked", func(t *testing.T) {
		e, m, _ := renewEnv(t)
		now := e.clk.now()
		priv, leaf := e.f.Leaf(t, e.c, now, day)
		raw := signBearer(t, priv, jose.EdDSA, leaf, now, time.Hour)
		iss := e.issuer(t, m)
		accepted(t, iss, raw, now)
		e.revokeLeaf(t, 9, leaf.SerialNumber)
		if err := m.Reload(ctx); err != nil {
			t.Fatal(err)
		}
		iss.Invalidate()
		_ = refused(t, iss, raw, now)
	})
	t.Run("sibling-installation", func(t *testing.T) {
		e, m, _ := renewEnv(t)
		now := e.clk.now()
		s := e.f.Sibling(t, "other")
		e.putIntermediate(t, s.Intermediate, "")
		priv, leaf := s.Leaf(t, e.c, now, day)
		unknownKey(t, e.issuer(t, m), signBearer(t, priv, jose.EdDSA, leaf, now, time.Hour), now)
	})
	t.Run("ca-without-usage", func(t *testing.T) {
		e, m, _ := renewEnv(t)
		now := e.clk.now()
		key := newP256(t)
		inter := craft(t, e.f, &key.PublicKey, func(c *x509.Certificate) { c.UnknownExtKeyUsage = nil })
		e.putIntermediate(t, inter, "")
		priv, leaf := leafUnderKey(t, inter, key, now, day)
		e.putLeaf(t, leaf, keyID(inter))
		unknownKey(t, e.issuer(t, m), signBearer(t, priv, jose.EdDSA, leaf, now, time.Hour), now)
	})
	t.Run("lifetime-over-ceiling", func(t *testing.T) {
		e, m, _ := renewEnv(t)
		now := e.clk.now()
		leaf, priv := overlongLeafKey(t, e.f, now, pki.MaxLeafLifetime+time.Second)
		e.putLeaf(t, leaf, keyID(e.f.Intermediate))
		unknownKey(t, e.issuer(t, m), signBearer(t, priv, jose.EdDSA, leaf, now, time.Hour), now)
	})
	t.Run("non-ed25519-leaf", func(t *testing.T) {
		// The chain check does not look at the leaf's key type; the loader refuses a
		// leaf whose key is not Ed25519, or the key set would not validate.
		e, m, _ := renewEnv(t)
		now := e.clk.now()
		key := newP256(t)
		ski, err := pki.SubjectKeyID(&key.PublicKey)
		if err != nil {
			t.Fatal(err)
		}
		tmpl := &x509.Certificate{
			SerialNumber: randSerial(t), Subject: pkix.Name{CommonName: "agentmesh leaf"},
			NotBefore: now.Add(-pki.LeafBackdate), NotAfter: now.Add(day),
			KeyUsage: x509.KeyUsageDigitalSignature, UnknownExtKeyUsage: []asn1.ObjectIdentifier{pki.ExtKeyUsageAgentmesh},
			BasicConstraintsValid: true, SubjectKeyId: ski, AuthorityKeyId: e.f.Intermediate.SubjectKeyId,
		}
		der, err := x509.CreateCertificate(rand.Reader, tmpl, e.f.Intermediate, &key.PublicKey, interKey(t, e.f))
		if err != nil {
			t.Fatal(err)
		}
		leaf, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		e.putLeaf(t, leaf, keyID(e.f.Intermediate))
		iss := e.issuer(t, m)
		unknownKey(t, iss, signBearer(t, key, jose.ES256, leaf, now, time.Hour), now)
		if _, err := m.LoadKeys(ctx); err != nil {
			t.Fatalf("a refused row broke the key set: %v", err)
		}
	})
	t.Run("expiry-cap", func(t *testing.T) {
		e, m, _ := renewEnv(t)
		_, na := m.Current()
		e.clk.advance(na.Add(-10 * time.Minute).Sub(e.clk.now()))
		iss := e.issuer(t, m)
		raw, exp, err := iss.Mint(ctx, token.MintInput{Identity: "alice", Kind: token.KindAgent, Lifetime: time.Hour})
		if err != nil {
			t.Fatal(err)
		}
		if !exp.Equal(na) {
			t.Fatalf("exp = %s, want the leaf's end %s", exp, na)
		}
		parts := strings.Split(raw, ".")
		payload, err := base64.RawURLEncoding.DecodeString(parts[1])
		if err != nil {
			t.Fatal(err)
		}
		var c struct {
			Exp int64 `json:"exp"`
		}
		if err := json.Unmarshal(payload, &c); err != nil || c.Exp != na.Unix() {
			t.Fatalf("exp claim = %d, %v, want %d", c.Exp, err, na.Unix())
		}
		accepted2, err := iss.Verify(ctx, raw, e.clk.now())
		if err != nil || accepted2 != "alice" {
			t.Fatalf("Verify = %q, %v", accepted2, err)
		}
	})
}
