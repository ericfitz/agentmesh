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
	ListSigningKeys(ctx context.Context, admin string) (bus.SigningKeyList, error)
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

func (noSigningKeys) ListSigningKeys(context.Context, string) (bus.SigningKeyList, error) {
	return bus.SigningKeyList{}, signingKeysNotConfigured()
}

func (noSigningKeys) RotateSigningKey(context.Context, string, bus.RotateSigningKeyInput) (bus.SigningKeyRotation, error) {
	return bus.SigningKeyRotation{}, signingKeysNotConfigured()
}

func signingKeyToGen(k bus.SigningKey) gen.SigningKey {
	return gen.SigningKey{
		Thumbprint: k.Thumbprint, Serial: k.Serial, IssuerThumbprint: k.IssuerThumbprint,
		NotBefore: k.NotBefore, NotAfter: k.NotAfter, State: gen.SigningKeyState(k.State),
	}
}

// ListSigningKeys lists the unexpired signing leaves, the current one first.
func (a *api) ListSigningKeys(ctx context.Context, _ gen.ListSigningKeysRequestObject) (gen.ListSigningKeysResponseObject, error) {
	l, err := a.signingKeys().ListSigningKeys(ctx, IdentityFrom(ctx))
	if err != nil {
		return nil, err
	}
	return gen.ListSigningKeys200JSONResponse(signingKeyListToGen(l)), nil
}

// signingKeyListToGen converts the list to its wire form; keys is required
// (empty, never null).
func signingKeyListToGen(l bus.SigningKeyList) gen.SigningKeyList {
	out := gen.SigningKeyList{Keys: make([]gen.SigningKey, len(l.Keys)), TrustNumber: l.TrustNumber}
	for i, k := range l.Keys {
		out.Keys[i] = signingKeyToGen(k)
	}
	return out
}

// RotateSigningKey rotates the signing leaf; it always revokes the previous one.
func (a *api) RotateSigningKey(ctx context.Context, req gen.RotateSigningKeyRequestObject) (gen.RotateSigningKeyResponseObject, error) {
	res, err := a.signingKeys().RotateSigningKey(ctx, IdentityFrom(ctx), rotateSigningKeyInput(req))
	if err != nil {
		return nil, err
	}
	return gen.RotateSigningKey200JSONResponse(signingKeyRotationToGen(res)), nil
}

// rotateSigningKeyInput reads the Idempotency-Key header.
func rotateSigningKeyInput(req gen.RotateSigningKeyRequestObject) bus.RotateSigningKeyInput {
	return bus.RotateSigningKeyInput{IdempotencyKey: idemKey(req.Params.IdempotencyKey)}
}

func revokedLeafToGen(r bus.RevokedLeaf) gen.RevokedLeaf {
	return gen.RevokedLeaf{Thumbprint: r.Thumbprint, HumanMessages: r.HumanMessages}
}

// signingKeyRotationToGen converts a rotation to its wire form; revoked is
// required (empty, never null).
func signingKeyRotationToGen(res bus.SigningKeyRotation) gen.SigningKeyRotation {
	out := gen.SigningKeyRotation{
		Current: signingKeyToGen(res.Current), Revoked: make([]gen.RevokedLeaf, len(res.Revoked)), TrustNumber: res.TrustNumber,
	}
	for i, r := range res.Revoked {
		out.Revoked[i] = revokedLeafToGen(r)
	}
	return out
}
