package server

import (
	"context"
	"crypto/ed25519"
	"crypto/x509"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/go-jose/go-jose/v4"
	"github.com/go-jose/go-jose/v4/jwt"

	"github.com/ericfitz/agentmesh/internal/auth/keys"
	"github.com/ericfitz/agentmesh/internal/auth/token"
	"github.com/ericfitz/agentmesh/internal/core/identities"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/trusttest"
)

// TestTokenEndpoint503WhenLeafExpired: a server whose only leaf has ended and
// cannot be renewed (the intermediate key file is gone) answers the token
// endpoint 503 temporarily_unavailable on both grants, while a bearer of another
// replica's leaf that is still valid is served (ADR 0019 section 4.15). The
// fixture is made on the environment's fake clock (it starts in 2023; a fixture
// made at the real time is not valid yet on it).
func TestTokenEndpoint503WhenLeafExpired(t *testing.T) {
	f := newFedEnv(t, 0, nil)
	ctx := context.Background()
	start := f.clock.Now()
	fx := trusttest.New(t, start)
	m := fx.Manager(t, f.core) // issues the leaf at the fake clock's time, valid 168 hours
	iss, err := token.NewIssuer(ctx, "http://inproc", m, time.Hour, f.clock.Now)
	if err != nil {
		t.Fatal(err)
	}
	m.SetOnChange(iss.Invalidate)
	f.issuer, f.opts.Issuer = iss, iss
	f.opts.Registration = identities.ModeOpen
	f.auth = Bearer{Verifier: token.Verifier{Own: iss}, Now: f.clock.Now}

	key := genKey(t, keys.EdDSA)
	f.mustRegister("pat", key)
	assertionGrant := func() *http.Response {
		return f.exchange(f.assertionFor("pat", key, "http://inproc/v1/auth/token", 0), "")
	}
	exchangeGrant := func() *http.Response {
		return f.do("POST", "/v1/auth/token", "application/x-www-form-urlencoded", "",
			exchangeForm(f.prov.Mint(map[string]any{"sub": "g-1", "email": corpEric}), nil).Encode())
	}
	// Healthy: both grants answer.
	if r := assertionGrant(); r.StatusCode != 200 {
		t.Fatalf("assertion grant with a live leaf = %d %s", r.StatusCode, readBody(t, r))
	}
	if r := exchangeGrant(); r.StatusCode != 200 {
		t.Fatalf("token exchange with a live leaf = %d %s", r.StatusCode, readBody(t, r))
	}

	// Another replica's leaf that outlives this server's by 30 hours.
	otherPriv, otherLeaf := fx.Leaf(t, f.core, start.Add(100*time.Hour), 100*time.Hour)

	// This server's leaf ends at start+168h and its key is gone.
	if err := os.Remove(fx.KeyFile); err != nil {
		t.Fatal(err)
	}
	f.clock.Advance(170 * time.Hour)

	wantOAuthError(t, assertionGrant(), 503, "temporarily_unavailable", "the signing key is unavailable", "")
	wantOAuthError(t, exchangeGrant(), 503, "temporarily_unavailable", "the signing key is unavailable", "")

	// The other leaf is still in its period: its bearer is served.
	raw := leafBearer(t, otherPriv, otherLeaf, "pat", f.clock.Now(), time.Hour)
	if r := f.do("GET", "/v1/channels", "", "Bearer "+raw, ""); r.StatusCode != 200 {
		t.Fatalf("GET /v1/channels with the other leaf's bearer = %d %s, want 200", r.StatusCode, readBody(t, r))
	}
}

// leafBearer signs an access token for identity with a leaf's key (type at+jwt,
// the leaf's thumbprint as kid), issued at iat for life, for the issuer of the
// test environment.
func leafBearer(t *testing.T, priv ed25519.PrivateKey, leaf *x509.Certificate, identity string, iat time.Time, life time.Duration) string {
	t.Helper()
	tp := pki.Thumbprint(leaf.Raw)
	opts := (&jose.SignerOptions{}).WithType("at+jwt").WithHeader("kid", tp).WithHeader("x5t#S256", tp)
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.EdDSA, Key: priv}, opts)
	if err != nil {
		t.Fatal(err)
	}
	claims := jwt.Claims{
		Issuer: "http://inproc", Subject: identity, Audience: jwt.Audience{"http://inproc"}, ID: "jti-other-leaf",
		IssuedAt: jwt.NewNumericDate(iat), Expiry: jwt.NewNumericDate(iat.Add(life)),
	}
	extra := struct {
		ClientID string `json:"client_id"`
		Kind     string `json:"agentmesh_kind"`
	}{identity, token.KindAgent}
	raw, err := jwt.Signed(signer).Claims(claims).Claims(extra).Serialize()
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
