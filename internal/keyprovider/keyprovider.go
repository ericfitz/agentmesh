// Package keyprovider is the port between the server's intermediate signing
// key and wherever its private key lives (issues #6 and #8; ADR 0019). The file
// provider keeps the key in an owner-only PEM file; an external provider (a KMS)
// keeps it out of the process and only signs. The package imports the standard
// library and internal/auth/keys only.
package keyprovider

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rsa"
	"errors"
	"fmt"
	"strings"

	"github.com/ericfitz/agentmesh/internal/auth/keys"
)

// Key is one signing key a provider names: the public half, its thumbprint
// kid and where the private half lives.
type Key struct {
	KID       string
	Algorithm keys.Algorithm
	Public    crypto.PublicKey
	// Ref names the key inside an external provider (a key URI); "" for the
	// file provider.
	Ref string
}

// Signer signs a digest under a context. It satisfies token.ContextSigner
// structurally: like crypto.Signer it returns DER for ES256 and the raw
// signature for EdDSA.
type Signer interface {
	Public() crypto.PublicKey
	SignContext(ctx context.Context, digest []byte, opts crypto.SignerOpts) ([]byte, error)
}

// Provider produces and opens signing keys.
type Provider interface {
	// Name is the provider's name: "file" or the scheme of an external one.
	Name() string
	// Next returns the key the configuration names: the one in the key file
	// or the one the configured key URI resolves to (external). It may call
	// the network, so callers run it outside every Store transaction.
	Next(ctx context.Context) (Key, error)
	// Signer opens k for signing. It makes no network call.
	Signer(ctx context.Context, k Key) (Signer, error)
}

// ErrUnavailable marks a failure of the external key service itself (it is
// unreachable, throttling or out of time), as opposed to a refusal or a bug. A
// provider wraps it; the signing key rules answer a retryable `unavailable`
// for it, and the server exits 1 rather than 2 when it is found at start.
var ErrUnavailable = errors.New("key provider unavailable")

// Schemes are the key URI schemes of the external providers, in the order the
// error texts name them.
func Schemes() []string { return []string{"awskms", "gcpkms", "azurekms", "hashivault"} }

// SchemeOf returns the provider scheme of a key URI: "" for the empty URI
// (no external provider), else one of Schemes. A missing "://", an empty rest or
// a scheme not in Schemes (the match is case-sensitive) is an error.
func SchemeOf(uri string) (string, error) {
	if uri == "" {
		return "", nil
	}
	scheme, rest, ok := strings.Cut(uri, "://")
	if !ok {
		return "", fmt.Errorf("key URI has no scheme: use one of %s", schemeList())
	}
	for _, s := range Schemes() {
		if scheme == s {
			if rest == "" {
				return "", fmt.Errorf("key URI names no key after %s://", s)
			}
			return s, nil
		}
	}
	return "", fmt.Errorf("key URI has unknown scheme %q: use one of %s", scheme, schemeList())
}

func schemeList() string {
	s := Schemes()
	return strings.Join(s[:len(s)-1], ", ") + " or " + s[len(s)-1]
}

// KeyName is the part of an external key URI that is safe to print: what
// follows "://" without any user info, query or fragment ("" when the URI has
// no "://"). A URI may carry credentials or a token, so logs and messages name
// the key with this and never print the URI.
func KeyName(uri string) string {
	_, rest, ok := strings.Cut(uri, "://")
	if !ok {
		return ""
	}
	if i := strings.IndexAny(rest, "?#"); i >= 0 {
		rest = rest[:i]
	}
	authority, _, _ := strings.Cut(rest, "/")
	if i := strings.LastIndex(authority, "@"); i >= 0 {
		rest = rest[i+1:]
	}
	return rest
}

// ExternalKey wraps the public key an external provider reports for ref. Only
// ECDSA P-256 (ES256) is supported, because KMS signing returns a DER
// signature the issuer converts for ES256 alone (decision 1); every other key,
// Ed25519 included, is an error.
func ExternalKey(pub crypto.PublicKey, ref string) (Key, error) {
	if ref == "" {
		return Key{}, errors.New("external signing key has no key URI")
	}
	alg, err := keys.AlgorithmOf(pub)
	if err != nil || alg != keys.ES256 {
		return Key{}, fmt.Errorf("external signing key is %s; only ECDSA P-256 (ES256) is supported", describe(pub))
	}
	kid, err := keys.KID(pub)
	if err != nil {
		return Key{}, err
	}
	return Key{KID: kid, Algorithm: keys.ES256, Public: pub, Ref: ref}, nil
}

func describe(pub crypto.PublicKey) string {
	switch k := pub.(type) {
	case ed25519.PublicKey:
		return "Ed25519"
	case *ecdsa.PublicKey:
		if k != nil && k.Curve != nil {
			return "ECDSA " + k.Curve.Params().Name
		}
		return "ECDSA"
	case *rsa.PublicKey:
		return "RSA"
	default:
		return fmt.Sprintf("a %T", pub)
	}
}
