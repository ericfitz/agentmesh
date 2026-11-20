package keyprovider

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/auth/keys"
)

func TestSchemeOf(t *testing.T) {
	if got := Schemes(); strings.Join(got, ",") != "awskms,gcpkms,azurekms,hashivault" {
		t.Fatalf("Schemes = %v", got)
	}
	for _, s := range Schemes() {
		if got, err := SchemeOf(s + "://some/key"); err != nil || got != s {
			t.Errorf("SchemeOf(%s://) = %q, %v", s, got, err)
		}
	}
	if got, err := SchemeOf(""); err != nil || got != "" {
		t.Errorf("SchemeOf(\"\") = %q, %v", got, err)
	}
	for _, bad := range []string{"file://x", "awskms:/x", "AWSKMS://x", "awskms", "://x", "awskms://", "http://x"} {
		_, err := SchemeOf(bad)
		if err == nil {
			t.Errorf("SchemeOf(%q) accepted", bad)
			continue
		}
		if bad != "awskms://" && !strings.Contains(err.Error(), "awskms, gcpkms, azurekms or hashivault") {
			t.Errorf("SchemeOf(%q) error %q does not name the four", bad, err)
		}
	}
}

// A key URI may carry a token, so SchemeOf's errors name the scheme and never
// the URI.
func TestSchemeOfErrorsDoNotQuoteTheURI(t *testing.T) {
	for _, bad := range []string{
		"https://user:s3cret@host/key?token=s3cret",
		"s3cret-token-without-scheme",
		"awskms://",
		"AWSKMS://s3cret",
	} {
		_, err := SchemeOf(bad)
		if err == nil {
			t.Errorf("SchemeOf(%q) accepted", bad)
			continue
		}
		if strings.Contains(err.Error(), "s3cret") || strings.Contains(err.Error(), "host/key") {
			t.Errorf("SchemeOf(%q) error quotes the URI: %q", bad, err)
		}
	}
	if _, err := SchemeOf("https://u:p@h/k"); err == nil || !strings.Contains(err.Error(), `"https"`) {
		t.Errorf("an unknown scheme error should name the scheme: %v", err)
	}
}

func TestExternalKey(t *testing.T) {
	p256, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	k, err := ExternalKey(p256.Public(), "awskms://k1")
	if err != nil {
		t.Fatal(err)
	}
	kid, _ := keys.KID(p256.Public())
	if k.KID != kid || k.Algorithm != keys.ES256 || k.Ref != "awskms://k1" {
		t.Fatalf("key %+v", k)
	}
	p384, _ := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	rsaKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	for name, c := range map[string]struct {
		pub  crypto.PublicKey
		want string
	}{
		"ed25519": {edPub, "external signing key is Ed25519; only ECDSA P-256 (ES256) is supported"},
		"p384":    {p384.Public(), "external signing key is ECDSA P-384; only ECDSA P-256 (ES256) is supported"},
		"rsa":     {rsaKey.Public(), "external signing key is RSA; only ECDSA P-256 (ES256) is supported"},
	} {
		if _, err := ExternalKey(c.pub, "awskms://k"); err == nil || err.Error() != c.want {
			t.Errorf("%s: err = %v, want %q", name, err, c.want)
		}
	}
	if _, err := ExternalKey(p256.Public(), ""); err == nil {
		t.Error("an empty ref was accepted")
	}
}

func TestKeyNameDropsCredentialsAndQuery(t *testing.T) {
	for _, tc := range []struct{ in, want string }{
		{"awskms:///alias/agentmesh", "/alias/agentmesh"},
		{"awskms://alias/agentmesh", "alias/agentmesh"},
		{"hashivault://transit-key?address=https://v:8200&token=s3cret", "transit-key"},
		{"hashivault://user:pw@vault.example/key#frag", "vault.example/key"},
		{"azurekms://v.vault.azure.net/k?x=1", "v.vault.azure.net/k"},
		// A "/" in the password must not end the userinfo early (issue #44).
		{"hashivault://user:pa/ss@vault.example/key", "vault.example/key"},
		{"hashivault://user:pa/ss/word@vault.example/key", "vault.example/key"},
		{"hashivault://user:p@ss@vault.example/key", "vault.example/key"},
		{"hashivault://token@vault.example/key", "vault.example/key"},
		{"hashivault://user:pa/ss@vault.example/key?x=a@b", "vault.example/key"},
		{"not-a-uri", ""},
		{"", ""},
	} {
		if got := KeyName(tc.in); got != tc.want {
			t.Errorf("KeyName(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestErrUnavailableIsASentinel(t *testing.T) {
	if !errors.Is(fmt.Errorf("x: %w", ErrUnavailable), ErrUnavailable) {
		t.Fatal("not matchable")
	}
}
