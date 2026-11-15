package server

import (
	"crypto/ed25519"
	"encoding/base64"
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
		if name == "JWKS.keys[0]" {
			// A published key is a leaf certificate's: its kid is the certificate
			// thumbprint (x5t#S256), not the RFC 7638 one, and the chain is in x5c.
			checkLeafJWKExample(t, raw)
			continue
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

// checkLeafJWKExample checks the JWKS example's key as far as its members can
// be checked: the kid equals x5t#S256 (a 43-character base64url thumbprint),
// x5c has the leaf and its intermediate, and x is a public Ed25519 key. The
// example's certificates are placeholders (Eric 2026-11-14), so go-jose cannot
// parse x5c and the certificate-to-thumbprint check is gone; the key is built
// from the members without x5c.
func checkLeafJWKExample(t *testing.T, raw []byte) {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Errorf("JWKS.keys[0]: %v", err)
		return
	}
	if x5c, ok := m["x5c"].([]any); !ok || len(x5c) != 2 {
		t.Errorf("JWKS.keys[0]: x5c is %v, want the leaf and its intermediate as 2 strings", m["x5c"])
	} else {
		for i, e := range x5c {
			if _, ok := e.(string); !ok {
				t.Errorf("JWKS.keys[0]: x5c[%d] is not a string", i)
			}
		}
	}
	thumb, _ := m["x5t#S256"].(string)
	if m["kid"] != thumb {
		t.Errorf("JWKS.keys[0]: kid %v and x5t#S256 %q must be equal", m["kid"], thumb)
	}
	if b, err := base64.RawURLEncoding.DecodeString(thumb); err != nil || len(thumb) != 43 || len(b) != 32 {
		t.Errorf("JWKS.keys[0]: x5t#S256 %q is not 43 characters of base64url (%v)", thumb, err)
	}
	if m["alg"] != "EdDSA" {
		t.Errorf("JWKS.keys[0]: alg %v, want EdDSA", m["alg"])
	}
	delete(m, "x5c")
	delete(m, "x5t#S256")
	keyOnly, err := json.Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	var jwk jose.JSONWebKey
	if err := jwk.UnmarshalJSON(keyOnly); err != nil {
		t.Errorf("JWKS.keys[0]: %v", err)
		return
	}
	if !jwk.IsPublic() {
		t.Errorf("JWKS.keys[0] is not a public key")
	}
	if _, ok := jwk.Key.(ed25519.PublicKey); !ok {
		t.Errorf("JWKS.keys[0]: x is not an Ed25519 key")
	}
}
