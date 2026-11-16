package server

import (
	"context"
	"net/http"
	"os"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/auth/keys"
	"github.com/ericfitz/agentmesh/internal/auth/token"
	"github.com/ericfitz/agentmesh/internal/core/identities"
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
	fx := f.fx
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
	raw := trusttest.LeafBearer(t, otherPriv, otherLeaf, "http://inproc", "pat", f.clock.Now(), time.Hour)
	if r := f.do("GET", "/v1/channels", "", "Bearer "+raw, ""); r.StatusCode != 200 {
		t.Fatalf("GET /v1/channels with the other leaf's bearer = %d %s, want 200", r.StatusCode, readBody(t, r))
	}
}
