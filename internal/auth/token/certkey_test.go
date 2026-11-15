package token

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/ericfitz/agentmesh/internal/auth/keys"
)

// certKey is a leaf key with a certificate valid in [notBefore, notAfter], made
// with the standard library (this package imports nothing else).
type certKey struct {
	signer crypto.Signer
	key    Key
	der    []byte
}

func thumbprintOf(der []byte) string {
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

func makeCert(t *testing.T, pub crypto.PublicKey, signerKey crypto.Signer, notBefore, notAfter time.Time) []byte {
	t.Helper()
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "leaf"},
		NotBefore:    notBefore,
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, signerKey)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// newCertKey makes an Ed25519 leaf valid from notBefore to notAfter, with a
// second certificate standing in for the intermediate.
func newCertKey(t *testing.T, notBefore, notAfter time.Time) certKey {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	der := makeCert(t, pub, priv, notBefore, notAfter)
	_, ipriv, _ := ed25519.GenerateKey(rand.Reader)
	inter := makeCert(t, ipriv.Public(), ipriv, notBefore, notAfter)
	return certKey{signer: priv, der: der, key: Key{
		KID: thumbprintOf(der), Algorithm: keys.EdDSA, Public: pub,
		Chain: [][]byte{der, inter}, NotBefore: notBefore, NotAfter: notAfter,
	}}
}

// cryptoSigner adapts a crypto.Signer to a ContextSigner.
type cryptoSigner struct{ crypto.Signer }

func (c cryptoSigner) SignContext(_ context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error) {
	return c.Sign(rand.Reader, digest, opts)
}

// longCertKey is a leaf valid long before and after t0, for tests that move the
// clock but not the certificate's period.
func longCertKey(t *testing.T) certKey {
	t.Helper()
	return newCertKey(t, t0.Add(-24*time.Hour), t0.Add(10*365*24*time.Hour))
}

// ksKey makes a leaf key with a chain and its Key record (alg must be EdDSA:
// a certificate key is EdDSA).
func ksKey(t *testing.T) (crypto.Signer, Key) {
	t.Helper()
	c := longCertKey(t)
	return c.signer, c.key
}

// setOf is a valid set: active signs, the others are retiring; Keys is
// active first.
func setOf(active crypto.Signer, activeKey Key, retiring ...Key) KeySet {
	return KeySet{Active: activeKey, Signer: cryptoSigner{active}, Keys: append([]Key{activeKey}, retiring...)}
}

// newIssuer is an issuer over a fresh leaf key (see newIssuerWith).
func newIssuer(t *testing.T) *Issuer { return newIssuerWith(t, longCertKey(t)) }

// newIssuerWith is an issuer at issURL over c, on the clock fixed at t0.
func newIssuerWith(t *testing.T, c certKey) *Issuer {
	t.Helper()
	src := &fakeSource{}
	src.put(setOf(c.signer, c.key), nil)
	i, err := NewIssuer(context.Background(), issURL, src, time.Hour, func() time.Time { return t0 })
	if err != nil {
		t.Fatal(err)
	}
	return i
}

func certSet(c certKey) KeySet {
	return KeySet{Active: c.key, Signer: cryptoSigner{c.signer}, Keys: []Key{c.key}}
}

func certIssuer(t *testing.T, c certKey, clk *clock) *Issuer {
	t.Helper()
	src := &fakeSource{}
	src.put(certSet(c), nil)
	return ksIssuer(t, src, clk)
}

func TestCertificateKeyValidate(t *testing.T) {
	c := newCertKey(t, t0.Add(-time.Hour), t0.Add(time.Hour))
	if err := certSet(c).validate(); err != nil {
		t.Fatalf("a good certificate key: %v", err)
	}
	other := newCertKey(t, t0.Add(-time.Hour), t0.Add(time.Hour))

	badKID := c.key
	badKID.KID = other.key.KID // a thumbprint, but not of Chain[0]
	otherPub := c.key
	otherPub.Public = other.key.Public // not the certificate's key
	otherPub.KID = c.key.KID

	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	ecDER := makeCert(t, ecKey.Public(), ecKey, t0.Add(-time.Hour), t0.Add(time.Hour))
	ecLeaf := Key{KID: thumbprintOf(ecDER), Algorithm: keys.ES256, Public: ecKey.Public(), Chain: [][]byte{ecDER}}

	declared := c.key
	declared.Algorithm = keys.ES256 // an Ed25519 leaf declared with ES256

	garbage := c.key
	garbage.Chain = [][]byte{[]byte("not DER")}
	garbage.KID = thumbprintOf(garbage.Chain[0])

	badInter := c.key
	badInter.Chain = [][]byte{c.der, []byte("not DER")}

	ecCert := Key{KID: c.key.KID, Algorithm: keys.EdDSA, Public: c.key.Public}
	ecCert.Chain = [][]byte{makeCert(t, ecKey.Public(), ecKey, t0.Add(-time.Hour), t0.Add(time.Hour))}
	ecCert.KID = thumbprintOf(ecCert.Chain[0]) // right thumbprint, but the certificate holds an ECDSA key

	cases := map[string]Key{
		"leaf cert holds ECDSA":     ecCert,
		"intermediate not DER":      badInter,
		"kid is not the thumbprint": badKID,
		"public is not the cert's":  otherPub,
		"ECDSA P-256 leaf":          ecLeaf,
		"EdDSA leaf declared ES256": declared,
		"chain that is not DER":     garbage,
	}
	for name, k := range cases {
		t.Run(name, func(t *testing.T) {
			set := KeySet{Active: k, Signer: cryptoSigner{c.signer}, Keys: []Key{k}}
			if err := set.validate(); err == nil {
				t.Fatal("validate accepted the key")
			}
			// Without a signer the key is still checked.
			if err := (KeySet{Active: k, Keys: []Key{k}}).validate(); err == nil {
				t.Fatal("validate accepted the key in a verify-only set")
			}
		})
	}
}

func TestSetWithoutSigner(t *testing.T) {
	_, k := ksKey(t)
	if err := (KeySet{Active: k}).validate(); err == nil {
		t.Error("a nil-signer set with a non-zero Active and no keys was accepted")
	}
	cases := map[string]KeySet{
		"zero active, other keys": {Keys: []Key{k}},
		"no keys":                 {},
	}
	for name, set := range cases {
		t.Run(name, func(t *testing.T) {
			if err := set.validate(); err != nil {
				t.Fatalf("validate: %v", err)
			}
			clk := &clock{t: t0}
			src := &fakeSource{}
			src.put(set, nil)
			i := ksIssuer(t, src, clk)
			_, _, err := i.Mint(context.Background(), MintInput{Identity: "alice", Kind: KindAgent})
			if !errors.Is(err, ErrSignerUnavailable) {
				t.Fatalf("Mint err = %v, want ErrSignerUnavailable", err)
			}
		})
	}

	// A bearer under a listed key verifies.
	s, ak := ksKey(t)
	clk := &clock{t: t0}
	src := &fakeSource{}
	src.put(setOf(s, ak), nil)
	i := ksIssuer(t, src, clk)
	raw, _, err := i.Mint(context.Background(), MintInput{Identity: "alice", Kind: KindAgent})
	if err != nil {
		t.Fatal(err)
	}
	src.put(KeySet{Keys: []Key{ak}}, nil)
	i.Invalidate()
	if id, err := i.Verify(context.Background(), raw, clk.Now()); err != nil || id != "alice" {
		t.Fatalf("Verify = %q, %v", id, err)
	}
	if _, _, err := i.Mint(context.Background(), MintInput{Identity: "alice", Kind: KindAgent}); !errors.Is(err, ErrSignerUnavailable) {
		t.Fatalf("Mint after the signer went away: %v", err)
	}
}

func TestMintHeaderCarriesThumbprint(t *testing.T) {
	clk := &clock{t: t0}
	c := newCertKey(t, t0.Add(-time.Hour), t0.Add(24*time.Hour))
	i := certIssuer(t, c, clk)
	raw, _, err := i.Mint(context.Background(), MintInput{Identity: "alice", Kind: KindAgent})
	if err != nil {
		t.Fatal(err)
	}
	tok, err := jwt.ParseSigned(raw, serverAlgorithms)
	if err != nil {
		t.Fatal(err)
	}
	h := tok.Headers[0]
	if h.KeyID != c.key.KID {
		t.Errorf("kid = %q, want %q", h.KeyID, c.key.KID)
	}
	if got, _ := h.ExtraHeaders["x5t#S256"].(string); got != c.key.KID {
		t.Errorf("x5t#S256 = %q, want %q", got, c.key.KID)
	}
}

func TestMintCapsExpiryAtLeaf(t *testing.T) {
	clk := &clock{t: t0}
	end := t0.Add(10 * time.Minute)
	c := newCertKey(t, t0.Add(-time.Hour), end)
	i := certIssuer(t, c, clk) // lifetime 1 hour
	raw, exp, err := i.Mint(context.Background(), MintInput{Identity: "alice", Kind: KindAgent})
	if err != nil {
		t.Fatal(err)
	}
	if !exp.Equal(end) {
		t.Errorf("returned expiry %v, want the leaf's end %v", exp, end)
	}
	_, claims := decodeJWT(t, raw)
	if got := int64(claims["exp"].(float64)); got != end.Unix() {
		t.Errorf("exp = %d, want %d", got, end.Unix())
	}
	// A lifetime shorter than the leaf's remainder is kept.
	_, exp, err = i.Mint(context.Background(), MintInput{Identity: "alice", Kind: KindAgent, Lifetime: time.Minute})
	if err != nil || !exp.Equal(t0.Add(time.Minute)) {
		t.Errorf("short lifetime: exp %v, err %v", exp, err)
	}
}

func TestMintOutsideValidity(t *testing.T) {
	for name, tc := range map[string]struct{ nb, na time.Time }{
		"expired":     {t0.Add(-2 * time.Hour), t0.Add(-time.Hour)},
		"not started": {t0.Add(time.Hour), t0.Add(2 * time.Hour)},
	} {
		t.Run(name, func(t *testing.T) {
			c := newCertKey(t, tc.nb, tc.na)
			i := certIssuer(t, c, &clock{t: t0})
			_, _, err := i.Mint(context.Background(), MintInput{Identity: "alice", Kind: KindAgent})
			if !errors.Is(err, ErrSignerUnavailable) {
				t.Fatalf("Mint err = %v, want ErrSignerUnavailable", err)
			}
		})
	}
}

func TestVerifyChecksValidity(t *testing.T) {
	c := newCertKey(t, t0.Add(-time.Hour), t0.Add(time.Hour))
	clk := &clock{t: t0}
	i := certIssuer(t, c, clk)
	raw, _, err := i.Mint(context.Background(), MintInput{Identity: "alice", Kind: KindAgent})
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	end := c.key.NotAfter
	for name, tc := range map[string]struct {
		now time.Time
		ok  bool
	}{
		"inside":               {t0, true},
		"ended 59 seconds ago": {end.Add(59 * time.Second), true},
		"ended 61 seconds ago": {end.Add(61 * time.Second), false},
		"starts in 59 seconds": {c.key.NotBefore.Add(-59 * time.Second), true},
		"starts in 61 seconds": {c.key.NotBefore.Add(-61 * time.Second), false},
	} {
		t.Run(name, func(t *testing.T) {
			// The issuer's clock is tc.now, so the token's own iat/exp (a minute
			// either side of it) never decide the outcome.
			clk2 := &clock{t: tc.now}
			j := certIssuer(t, c, clk2)
			// Sign with the leaf directly: Mint would refuse outside the period.
			claims := jwt.Claims{
				Issuer: issURL, Subject: "alice", Audience: jwt.Audience{issURL}, ID: "j",
				IssuedAt: jwt.NewNumericDate(tc.now), Expiry: jwt.NewNumericDate(tc.now.Add(time.Minute)),
			}
			tokRaw := signRaw(t, c.signer, c.key.KID, claims)
			_, err := j.Verify(ctx, tokRaw, tc.now)
			switch {
			case tc.ok && err != nil:
				t.Fatalf("Verify: %v", err)
			case !tc.ok && (err == nil || !errors.Is(err, ErrInvalid) || !strings.Contains(err.Error(), "the signing certificate is not valid at this time")):
				t.Fatalf("Verify err = %v, want the validity refusal", err)
			}
		})
	}
	// The minted token verifies inside the period.
	if _, err := i.Verify(ctx, raw, t0); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyRefusesAlgorithmMismatch(t *testing.T) {
	// A chain key is EdDSA; a token whose header says ES256 is refused even
	// when it carries a valid kid. (go-jose also refuses a key-type mismatch;
	// the explicit check makes the refusal independent of it.)
	c := newCertKey(t, t0.Add(-time.Hour), t0.Add(time.Hour))
	i := certIssuer(t, c, &clock{t: t0})
	ec := genKey(t, keys.ES256)
	raw := signRaw(t, ec, c.key.KID, goodClaims(&clock{t: t0}))
	_, err := i.Verify(context.Background(), raw, t0)
	if err == nil || !errors.Is(err, ErrInvalid) {
		t.Fatalf("Verify err = %v, want ErrInvalid", err)
	}
	if !strings.Contains(err.Error(), "algorithm") {
		t.Errorf("err = %v, want the algorithm refusal", err)
	}
}

func TestJWKSCarriesChain(t *testing.T) {
	c := newCertKey(t, t0.Add(-time.Hour), t0.Add(time.Hour))
	i := certIssuer(t, c, &clock{t: t0})
	set := i.JWKS(context.Background())
	if len(set.Keys) != 1 {
		t.Fatalf("%d keys", len(set.Keys))
	}
	k := set.Keys[0]
	if len(k.Certificates) != 2 {
		t.Fatalf("x5c has %d certificates, want 2", len(k.Certificates))
	}
	for n, der := range c.key.Chain {
		if string(k.Certificates[n].Raw) != string(der) {
			t.Errorf("x5c[%d] is not Chain[%d]", n, n)
		}
	}
	if got := base64.RawURLEncoding.EncodeToString(k.CertificateThumbprintSHA256); got != c.key.KID {
		t.Errorf("x5t#S256 = %q, want %q", got, c.key.KID)
	}
	raw, err := k.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"x5c":[`, `"x5t#S256":"` + c.key.KID + `"`, `"kid":"` + c.key.KID + `"`} {
		if !strings.Contains(string(raw), want) {
			t.Errorf("json %s lacks %s", raw, want)
		}
	}
}

func TestMintValidityEdges(t *testing.T) {
	nb, na := t0.Add(-time.Hour), t0.Add(time.Hour)
	c := newCertKey(t, nb, na)
	mint := func(at time.Time) (time.Time, error) {
		_, exp, err := certIssuer(t, c, &clock{t: at}).Mint(context.Background(), MintInput{Identity: "alice", Kind: KindAgent})
		return exp, err
	}
	if _, err := mint(na); !errors.Is(err, ErrSignerUnavailable) {
		t.Errorf("now == NotAfter: err %v, want ErrSignerUnavailable", err)
	}
	if exp, err := mint(na.Add(-time.Second)); err != nil || !exp.Equal(na) {
		t.Errorf("NotAfter-1s: exp %v, err %v, want exp == NotAfter", exp, err)
	}
	if _, err := mint(nb.Add(-time.Second)); !errors.Is(err, ErrSignerUnavailable) {
		t.Errorf("NotBefore-1s: err %v, want ErrSignerUnavailable", err)
	}
	if _, err := mint(nb); err != nil {
		t.Errorf("now == NotBefore: %v", err)
	}
}

// TestKeyNeedsAChain: validate refuses a key without a certificate chain, an
// empty one, and one whose first certificate does not hold the key, in the
// active slot and in a listed one, with a signer and without.
func TestKeyNeedsAChain(t *testing.T) {
	c := newCertKey(t, t0.Add(-time.Hour), t0.Add(time.Hour))
	if err := certSet(c).validate(); err != nil {
		t.Fatalf("control: %v", err)
	}
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := keys.KID(pub)
	if err != nil {
		t.Fatal(err)
	}
	noChain := Key{KID: kid, Algorithm: keys.EdDSA, Public: pub}
	emptyChain := noChain
	emptyChain.Chain = [][]byte{}
	foreign := c.key // the chain is c's, the key another
	foreign.Public = pub
	cases := map[string]Key{"nil chain": noChain, "empty chain": emptyChain, "chain of another key": foreign}
	for name, k := range cases {
		t.Run(name, func(t *testing.T) {
			if err := (KeySet{Active: k, Signer: cryptoSigner{c.signer}, Keys: []Key{k}}).validate(); err == nil {
				t.Error("validate accepted the key as active")
			}
			if err := (KeySet{Active: c.key, Signer: cryptoSigner{c.signer}, Keys: []Key{c.key, k}}).validate(); err == nil {
				t.Error("validate accepted the key as a listed key")
			}
			if err := (KeySet{Keys: []Key{k}}).validate(); err == nil {
				t.Error("validate accepted the key in a verify-only set")
			}
		})
	}
}
