package server

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/auth/keys"
	"github.com/ericfitz/agentmesh/internal/core/identities"
)

// TestJWKDeclaresAcceptedMembers: JWK declares the members the server accepts
// (issue #30, CATS HappyPath built a register request from the schema's own
// properties, which held only kty, and the handler refused it). A key built
// from the declared properties registers; a kty or crv outside the enums is
// refused by the schema, not by go-jose.
func TestJWKDeclaresAcceptedMembers(t *testing.T) {
	jwk := Spec().Components.Schemas["JWK"].Value
	for _, name := range []string{"kty", "crv", "x", "y", "kid"} {
		if jwk.Properties[name] == nil {
			t.Errorf("JWK declares no %s", name)
		}
	}
	enum := func(name string) []any { return jwk.Properties[name].Value.Enum }
	if got, _ := json.Marshal(enum("kty")); string(got) != `["OKP","EC"]` {
		t.Errorf("kty enum %s", got)
	}
	if got, _ := json.Marshal(enum("crv")); string(got) != `["Ed25519","P-256"]` {
		t.Errorf("crv enum %s", got)
	}
	schema := Spec().Components.Schemas["RegisterRequest"].Value
	body := func(j map[string]any) map[string]any {
		return map[string]any{"identity": "acme-coder-1", "public_key_jwk": j}
	}
	if err := schema.VisitJSON(body(map[string]any{"kty": "zzz"})); err == nil || !strings.Contains(err.Error(), "kty") {
		t.Errorf(`kty "zzz": %v, want the enum refusal`, err)
	}
	if err := schema.VisitJSON(body(map[string]any{"kty": "OKP", "crv": "P-521", "x": "a"})); err == nil || !strings.Contains(err.Error(), "crv") {
		t.Errorf(`crv "P-521": %v, want the enum refusal`, err)
	}
	for _, alg := range []keys.Algorithm{keys.EdDSA, keys.ES256} {
		e := newEnv(t, envOptions{issuer: true, registration: identities.ModeOpen})
		j := jwkJSON(t, genKey(t, alg))
		// as CATS builds it: only the declared members.
		built := map[string]any{}
		for name := range jwk.Properties {
			if v, ok := j[name]; ok {
				built[name] = v
			}
		}
		if err := schema.VisitJSON(body(built)); err != nil {
			t.Fatalf("%s: schema refuses its own members: %v", alg, err)
		}
		b, _ := json.Marshal(body(built))
		if resp := e.do("POST", "/v1/auth/register", "application/json", "", string(b)); resp.StatusCode != http.StatusCreated {
			t.Fatalf("%s: register %d %s", alg, resp.StatusCode, readBody(t, resp))
		}
	}
}

// TestRegisterRefusesLongJWKMembers: crv, x, y and kid over
// keys.MaxJWKMemberBytes are 400 validation (the schema's maxLength and
// keys.CheckJWKStrings).
func TestRegisterRefusesLongJWKMembers(t *testing.T) {
	e := newEnv(t, envOptions{issuer: true, registration: identities.ModeOpen})
	key := genKey(t, keys.EdDSA)
	for _, name := range []string{"crv", "x", "y", "kid"} {
		j := jwkJSON(t, key)
		j[name] = strings.Repeat("a", keys.MaxJWKMemberBytes+1)
		b, _ := json.Marshal(map[string]any{"identity": "long" + name, "public_key_jwk": j})
		wantAuthProblem(t, e.do("POST", "/v1/auth/register", "application/json", "", string(b)), 400, "validation", "")
	}
	if err := keys.CheckJWKStrings(map[string]any{"x": strings.Repeat("a", keys.MaxJWKMemberBytes+1)}); err == nil {
		t.Error("CheckJWKStrings accepted a long x")
	}
}
