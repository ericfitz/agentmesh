package remote

import (
	"context"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// FromGenSigningKey converts a wire key, refusing a state, provider or
// algorithm outside the closed sets.
func FromGenSigningKey(g gen.SigningKey) (ab2bus.SigningKey, error) {
	if !g.State.Valid() {
		return ab2bus.SigningKey{}, unknownWire("state", string(g.State))
	}
	if !g.Provider.Valid() {
		return ab2bus.SigningKey{}, unknownWire("provider", string(g.Provider))
	}
	if !g.Algorithm.Valid() {
		return ab2bus.SigningKey{}, unknownWire("algorithm", string(g.Algorithm))
	}
	return ab2bus.SigningKey{
		KID: g.Kid, State: string(g.State), Provider: string(g.Provider), ProviderRef: g.ProviderRef,
		Algorithm: string(g.Algorithm), CreatedAt: g.CreatedAt, RetiredAt: g.RetiredAt, RemoveAfter: g.RemoveAfter,
	}, nil
}

// ListSigningKeys lists the server's signing key set, the active key first.
func (b *Bus) ListSigningKeys(ctx context.Context) ([]ab2bus.SigningKey, error) {
	r, err := b.c.ListSigningKeysWithResponse(ctx)
	if err != nil {
		return nil, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), r.ApplicationproblemJSONDefault, r.Body, nil); err != nil {
		return nil, err
	}
	if r.JSON200 == nil {
		return nil, unparsable(r.StatusCode())
	}
	return FromGenSigningKeyList(*r.JSON200)
}

// FromGenSigningKeyList converts a wire key list, refusing a key outside the
// closed sets; the result is never nil.
func FromGenSigningKeyList(l gen.SigningKeyList) ([]ab2bus.SigningKey, error) {
	out := make([]ab2bus.SigningKey, 0, len(l.Keys))
	for _, g := range l.Keys {
		k, err := FromGenSigningKey(g)
		if err != nil {
			return nil, err
		}
		out = append(out, k)
	}
	return out, nil
}

// RotateSigningKey rotates the active signing key.
func (b *Bus) RotateSigningKey(ctx context.Context, in ab2bus.RotateSigningKeyInput) (ab2bus.SigningKeyRotation, error) {
	req := RotateSigningKeyRequest(in)
	r, err := b.c.RotateSigningKeyWithResponse(ctx, &req.Params)
	if err != nil {
		return ab2bus.SigningKeyRotation{}, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), r.ApplicationproblemJSONDefault, r.Body, nil); err != nil {
		return ab2bus.SigningKeyRotation{}, err
	}
	if r.JSON200 == nil {
		return ab2bus.SigningKeyRotation{}, unparsable(r.StatusCode())
	}
	return FromGenSigningKeyRotation(*r.JSON200)
}

// RotateSigningKeyRequest builds the request for RotateSigningKey;
// revoke_previous is present only when true.
func RotateSigningKeyRequest(in ab2bus.RotateSigningKeyInput) gen.RotateSigningKeyRequestObject {
	p := gen.RotateSigningKeyParams{IdempotencyKey: key(in.IdempotencyKey)}
	if in.RevokePrevious {
		p.RevokePrevious = ptr(true)
	}
	return gen.RotateSigningKeyRequestObject{Params: p}
}

// FromGenSigningKeyRotation converts a wire rotation, refusing a key outside
// the closed sets; an absent previous is the zero SigningKey.
func FromGenSigningKeyRotation(g gen.SigningKeyRotation) (ab2bus.SigningKeyRotation, error) {
	out := ab2bus.SigningKeyRotation{Revoked: g.Revoked}
	var err error
	if out.Active, err = FromGenSigningKey(g.Active); err != nil {
		return ab2bus.SigningKeyRotation{}, err
	}
	if g.Previous != nil {
		if out.Previous, err = FromGenSigningKey(*g.Previous); err != nil {
			return ab2bus.SigningKeyRotation{}, err
		}
	}
	return out, nil
}
