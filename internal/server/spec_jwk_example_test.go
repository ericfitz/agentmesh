package server

import (
	"crypto/ed25519"
	"crypto/sha256"
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
		var jwk jose.JSONWebKey
		if err := jwk.UnmarshalJSON(raw); err != nil {
			t.Errorf("%s: %v", name, err)
			continue
		}
		if name == "JWKS.keys[0]" {
			// A published key is a leaf certificate's: its kid is the certificate
			// thumbprint (x5t#S256), not the RFC 7638 one, and the chain is in x5c.
			checkLeafJWKExample(t, jwk)
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

// checkLeafJWKExample checks the JWKS example's key the way the server builds
// it: the kid is the SHA-256 thumbprint of the first x5c certificate and equals
// x5t#S256, the key is that certificate's key, and the chain has the leaf and
// its intermediate.
func checkLeafJWKExample(t *testing.T, jwk jose.JSONWebKey) {
	t.Helper()
	if len(jwk.Certificates) != 2 {
		t.Errorf("JWKS.keys[0]: x5c has %d certificates, want the leaf and its intermediate", len(jwk.Certificates))
		return
	}
	leaf := jwk.Certificates[0]
	want := base64.RawURLEncoding.EncodeToString(sum256(leaf.Raw))
	if jwk.KeyID != want || base64.RawURLEncoding.EncodeToString(jwk.CertificateThumbprintSHA256) != want {
		t.Errorf("JWKS.keys[0]: kid %q and x5t#S256 must both be the leaf's thumbprint %q", jwk.KeyID, want)
	}
	if !jwk.IsPublic() {
		t.Errorf("JWKS.keys[0] is not a public key")
	}
	if pub, ok := jwk.Key.(ed25519.PublicKey); !ok || !pub.Equal(leaf.PublicKey) {
		t.Errorf("JWKS.keys[0]: x is not the leaf certificate's key")
	}
}

func sum256(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
