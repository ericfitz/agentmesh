package server

import (
	"encoding/json"
	"testing"

	"github.com/go-jose/go-jose/v4"

	"github.com/ericfitz/agentmesh/internal/auth/keys"
)

// TestSpecJWKExamplesRegister: every public key example of api/openapi.yaml is
// one the server accepts at register (issue #30, CATS: the JWK example's kid was
// not the key's RFC 7638 thumbprint, so the documented request answered 400
// "kid does not match the key"). keys.FromJWK is the check register runs.
func TestSpecJWKExamplesRegister(t *testing.T) {
	doc := Spec()
	schemas := doc.Components.Schemas
	examples := map[string]any{
		"JWK":                            schemas["JWK"].Value.Example,
		"JWKS.keys[0]":                   nil,
		"RegisterRequest.public_key_jwk": nil,
	}
	if ks, ok := schemas["JWKS"].Value.Example.(map[string]any)["keys"].([]any); ok && len(ks) > 0 {
		examples["JWKS.keys[0]"] = ks[0]
	}
	if r, ok := schemas["RegisterRequest"].Value.Example.(map[string]any); ok {
		examples["RegisterRequest.public_key_jwk"] = r["public_key_jwk"]
	}
	jwkKid := ""
	for name, ex := range examples {
		if ex == nil {
			t.Errorf("%s: no example", name)
			continue
		}
		raw, err := json.Marshal(ex)
		if err != nil {
			t.Fatal(err)
		}
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(raw); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		pub, _, kid, err := keys.FromJWK(jwk)
		if err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		want, err := keys.KID(pub)
		if err != nil || kid != want {
			t.Errorf("%s: kid %q, want the thumbprint %q (%v)", name, kid, want, err)
		}
		if jwkKid == "" {
			jwkKid = kid
		}
	}
	if reg, ok := schemas["Registration"].Value.Example.(map[string]any); ok && jwkKid != "" {
		if reg["kid"] != jwkKid {
			t.Errorf("Registration example kid %v differs from the JWK example kid %s", reg["kid"], jwkKid)
		}
	}
}
