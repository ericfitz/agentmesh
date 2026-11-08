package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/auth/keys"
	"github.com/ericfitz/agentmesh/internal/core/identities"
)

// TestJWKRequiresKty: a register request whose public_key_jwk lacks kty is
// refused by the schema (RFC 7517 section 4.1; issue #30, CATS
// OnlyRequiredFields sent a JWK with no kty and the documented 400 came from
// the handler, not the contract). The request with kty is accepted by it.
func TestJWKRequiresKty(t *testing.T) {
	schema := Spec().Components.Schemas["RegisterRequest"].Value
	body := func(jwk map[string]any) map[string]any {
		return map[string]any{"identity": "acme-coder-1", "public_key_jwk": jwk}
	}
	withKty := map[string]any{"kty": "OKP", "crv": "Ed25519", "x": "sOdMZWLCddpuUshtE1kZytlM8SPVCfOKjiUO9WHLkVU"}
	if err := schema.VisitJSON(body(withKty)); err != nil {
		t.Fatalf("a JWK with kty: %v", err)
	}
	noKty := map[string]any{"crv": "Ed25519", "x": "sOdMZWLCddpuUshtE1kZytlM8SPVCfOKjiUO9WHLkVU"}
	if err := schema.VisitJSON(body(noKty)); err == nil {
		t.Fatal("a JWK without kty was accepted by the schema")
	}
}

// TestRegisterRefusesLongKty: a kty over keys.MaxKtyBytes and a register with no
// kty both answer 400 validation, at the validator and (for the handler's own
// check) in keys.CheckKty.
func TestRegisterRefusesLongKty(t *testing.T) {
	e := newEnv(t, envOptions{issuer: true, registration: identities.ModeOpen})
	key := genKey(t, keys.EdDSA)
	post := func(mutate func(map[string]any)) *http.Response {
		jwk := jwkJSON(t, key)
		mutate(jwk)
		b, _ := json.Marshal(map[string]any{"identity": "longkty", "public_key_jwk": jwk})
		return e.do("POST", "/v1/auth/register", "application/json", "", string(b))
	}
	wantAuthProblem(t, post(func(j map[string]any) { j["kty"] = strings.Repeat("k", keys.MaxKtyBytes+1) }), 400, "validation", "")
	wantAuthProblem(t, post(func(j map[string]any) { delete(j, "kty") }), 400, "validation", "")
	for _, bad := range []any{nil, 7, "", strings.Repeat("k", keys.MaxKtyBytes+1)} {
		if err := keys.CheckKty(bad); err == nil {
			t.Errorf("CheckKty(%v) accepted", bad)
		}
	}
	if err := keys.CheckKty("OKP"); err != nil {
		t.Errorf("CheckKty(OKP): %v", err)
	}
}
