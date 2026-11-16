package remote

import (
	"context"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// FromGenSigningKey converts a wire leaf, refusing a state outside the closed
// set.
func FromGenSigningKey(g gen.SigningKey) (ab2bus.SigningKey, error) {
	if !g.State.Valid() {
		return ab2bus.SigningKey{}, unknownWire("state", string(g.State))
	}
	return ab2bus.SigningKey{
		Thumbprint: g.Thumbprint, Serial: g.Serial, IssuerThumbprint: g.IssuerThumbprint,
		State: string(g.State), NotBefore: g.NotBefore, NotAfter: g.NotAfter,
	}, nil
}

// ListSigningKeys lists the unexpired signing leaves, the current one first.
func (b *Bus) ListSigningKeys(ctx context.Context) (ab2bus.SigningKeyList, error) {
	r, err := b.c.ListSigningKeysWithResponse(ctx)
	if err != nil {
		return ab2bus.SigningKeyList{}, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil); err != nil {
		return ab2bus.SigningKeyList{}, err
	}
	if r.JSON200 == nil {
		return ab2bus.SigningKeyList{}, unparsable(r.StatusCode())
	}
	return FromGenSigningKeyList(*r.JSON200)
}

// FromGenSigningKeyList converts a wire key list, refusing a key outside the
// closed set; Keys is never nil.
func FromGenSigningKeyList(l gen.SigningKeyList) (ab2bus.SigningKeyList, error) {
	out := ab2bus.SigningKeyList{Keys: make([]ab2bus.SigningKey, 0, len(l.Keys)), TrustNumber: l.TrustNumber}
	for _, g := range l.Keys {
		k, err := FromGenSigningKey(g)
		if err != nil {
			return ab2bus.SigningKeyList{}, err
		}
		out.Keys = append(out.Keys, k)
	}
	return out, nil
}

// RotateSigningKey rotates the signing leaf; the previous leaf is revoked.
func (b *Bus) RotateSigningKey(ctx context.Context, in ab2bus.RotateSigningKeyInput) (ab2bus.SigningKeyRotation, error) {
	req := RotateSigningKeyRequest(in)
	r, err := b.c.RotateSigningKeyWithResponse(ctx, &req.Params)
	if err != nil {
		return ab2bus.SigningKeyRotation{}, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil); err != nil {
		return ab2bus.SigningKeyRotation{}, err
	}
	if r.JSON200 == nil {
		return ab2bus.SigningKeyRotation{}, unparsable(r.StatusCode())
	}
	return FromGenSigningKeyRotation(*r.JSON200)
}

// RotateSigningKeyRequest builds the request for RotateSigningKey: the
// Idempotency-Key header, present only when set.
func RotateSigningKeyRequest(in ab2bus.RotateSigningKeyInput) gen.RotateSigningKeyRequestObject {
	return gen.RotateSigningKeyRequestObject{Params: gen.RotateSigningKeyParams{IdempotencyKey: key(in.IdempotencyKey)}}
}

// FromGenRevokedLeaf converts a wire revoked leaf.
func FromGenRevokedLeaf(g gen.RevokedLeaf) ab2bus.RevokedLeaf {
	return ab2bus.RevokedLeaf{Thumbprint: g.Thumbprint, HumanMessages: g.HumanMessages}
}

// FromGenSigningKeyRotation converts a wire rotation, refusing a leaf outside
// the closed set; Revoked is never nil.
func FromGenSigningKeyRotation(g gen.SigningKeyRotation) (ab2bus.SigningKeyRotation, error) {
	cur, err := FromGenSigningKey(g.Current)
	if err != nil {
		return ab2bus.SigningKeyRotation{}, err
	}
	out := ab2bus.SigningKeyRotation{Current: cur, Revoked: make([]ab2bus.RevokedLeaf, 0, len(g.Revoked)), TrustNumber: g.TrustNumber}
	for _, r := range g.Revoked {
		out.Revoked = append(out.Revoked, FromGenRevokedLeaf(r))
	}
	return out, nil
}
