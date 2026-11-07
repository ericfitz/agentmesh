package server

import (
	"context"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// SigningKeys is the seam to the signing key rules (issue #6): the server
// imports no key provider. Each method receives the authenticated identity
// and checks that it is an administrator.
type SigningKeys interface {
	ListSigningKeys(ctx context.Context, admin string) ([]bus.SigningKey, error)
	RotateSigningKey(ctx context.Context, admin string, in bus.RotateSigningKeyInput) (bus.SigningKeyRotation, error)
}

// signingKeys is Options.SigningKeys, or the refusing stand-in.
func (a *api) signingKeys() SigningKeys {
	if a.opts.SigningKeys == nil {
		return noSigningKeys{}
	}
	return a.opts.SigningKeys
}

// noSigningKeys answers every call unavailable (not retryable) with
// bus.SigningKeysNotConfigured.
type noSigningKeys struct{}

func signingKeysNotConfigured() error {
	return bus.Errorf(bus.CodeUnavailable, false, "%s", bus.SigningKeysNotConfigured)
}

func (noSigningKeys) ListSigningKeys(context.Context, string) ([]bus.SigningKey, error) {
	return nil, signingKeysNotConfigured()
}

func (noSigningKeys) RotateSigningKey(context.Context, string, bus.RotateSigningKeyInput) (bus.SigningKeyRotation, error) {
	return bus.SigningKeyRotation{}, signingKeysNotConfigured()
}

func signingKeyToGen(k bus.SigningKey) gen.SigningKey {
	return gen.SigningKey{
		Kid: k.KID, State: gen.SigningKeyState(k.State), Provider: gen.SigningKeyProvider(k.Provider),
		ProviderRef: k.ProviderRef, Algorithm: gen.SigningKeyAlgorithm(k.Algorithm),
		CreatedAt: k.CreatedAt, RetiredAt: k.RetiredAt, RemoveAfter: k.RemoveAfter,
	}
}

// ListSigningKeys lists the server's signing key set, the active key first.
func (a *api) ListSigningKeys(ctx context.Context, _ gen.ListSigningKeysRequestObject) (gen.ListSigningKeysResponseObject, error) {
	ks, err := a.signingKeys().ListSigningKeys(ctx, IdentityFrom(ctx))
	if err != nil {
		return nil, err
	}
	return gen.ListSigningKeys200JSONResponse(signingKeyListToGen(ks)), nil
}

// signingKeyListToGen converts the keys to their wire list; keys is required
// (empty, never null).
func signingKeyListToGen(ks []bus.SigningKey) gen.SigningKeyList {
	out := gen.SigningKeyList{Keys: make([]gen.SigningKey, len(ks))}
	for i, k := range ks {
		out.Keys[i] = signingKeyToGen(k)
	}
	return out
}

// RotateSigningKey rotates the active signing key.
func (a *api) RotateSigningKey(ctx context.Context, req gen.RotateSigningKeyRequestObject) (gen.RotateSigningKeyResponseObject, error) {
	res, err := a.signingKeys().RotateSigningKey(ctx, IdentityFrom(ctx), rotateSigningKeyInput(req))
	if err != nil {
		return nil, err
	}
	return gen.RotateSigningKey200JSONResponse(signingKeyRotationToGen(res)), nil
}

// rotateSigningKeyInput reads the query and the Idempotency-Key header; an
// absent revoke_previous is false.
func rotateSigningKeyInput(req gen.RotateSigningKeyRequestObject) bus.RotateSigningKeyInput {
	return bus.RotateSigningKeyInput{
		RevokePrevious: derefOr(req.Params.RevokePrevious),
		IdempotencyKey: idemKey(req.Params.IdempotencyKey),
	}
}

// signingKeyRotationToGen converts a rotation to its wire form; previous is
// absent when the set had no previous key (an empty KID).
func signingKeyRotationToGen(res bus.SigningKeyRotation) gen.SigningKeyRotation {
	out := gen.SigningKeyRotation{Active: signingKeyToGen(res.Active), Revoked: res.Revoked}
	if res.Previous.KID != "" {
		p := signingKeyToGen(res.Previous)
		out.Previous = &p
	}
	return out
}
