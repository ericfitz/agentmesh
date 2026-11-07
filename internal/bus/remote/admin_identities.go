package remote

import (
	"context"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// Reset sends the scope query parameter only when in.Scope is set: the
// document's default is data, so "" and data are the same request.
func (b *Bus) Reset(ctx context.Context, in ab2bus.ResetInput) error {
	req := AdminResetRequest(in)
	r, err := b.c.AdminResetWithResponse(ctx, &req.Params)
	if err != nil {
		return errorOf(ctx, 0, nil, nil, err)
	}
	return errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil)
}

// AdminResetRequest builds the request for Reset; an empty scope is absent.
func AdminResetRequest(in ab2bus.ResetInput) gen.AdminResetRequestObject {
	p := gen.AdminResetParams{IdempotencyKey: key(in.IdempotencyKey)}
	if in.Scope != "" {
		s := gen.AdminResetParamsScope(in.Scope)
		p.Scope = &s
	}
	return gen.AdminResetRequestObject{Params: p}
}

// ResetCredential removes every registered key of in.Identity.
func (b *Bus) ResetCredential(ctx context.Context, in ab2bus.ResetCredentialInput) (ab2bus.ResetCredentialResult, error) {
	req := ResetCredentialRequest(in)
	r, err := b.c.ResetCredentialWithResponse(ctx, req.Identity, &req.Params)
	if err != nil {
		return ab2bus.ResetCredentialResult{}, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil); err != nil {
		return ab2bus.ResetCredentialResult{}, err
	}
	if r.JSON200 == nil {
		return ab2bus.ResetCredentialResult{}, unparsable(r.StatusCode())
	}
	return FromGenCredentialReset(*r.JSON200), nil
}

// ResetCredentialRequest builds the request for ResetCredential.
func ResetCredentialRequest(in ab2bus.ResetCredentialInput) gen.ResetCredentialRequestObject {
	return gen.ResetCredentialRequestObject{Identity: in.Identity, Params: gen.ResetCredentialParams{IdempotencyKey: key(in.IdempotencyKey)}}
}

// FromGenCredentialReset converts a wire credential reset result to the domain type.
func FromGenCredentialReset(g gen.CredentialReset) ab2bus.ResetCredentialResult {
	return ab2bus.ResetCredentialResult{Identity: g.Identity, KeysRemoved: g.KeysRemoved}
}

// CreateIdentityByEmail creates the human identity bound to in.Email, or
// answers the existing one.
func (b *Bus) CreateIdentityByEmail(ctx context.Context, in ab2bus.CreateIdentityByEmailInput) (ab2bus.CreateIdentityByEmailResult, error) {
	req := CreateIdentityByEmailRequest(in)
	r, err := b.c.CreateIdentityByEmailWithResponse(ctx, &req.Params, *req.Body)
	if err != nil {
		return ab2bus.CreateIdentityByEmailResult{}, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil); err != nil {
		return ab2bus.CreateIdentityByEmailResult{}, err
	}
	if r.JSON200 == nil {
		return ab2bus.CreateIdentityByEmailResult{}, unparsable(r.StatusCode())
	}
	return FromGenHumanIdentity(*r.JSON200), nil
}

// CreateIdentityByEmailRequest builds the request for CreateIdentityByEmail;
// Body is always set.
func CreateIdentityByEmailRequest(in ab2bus.CreateIdentityByEmailInput) gen.CreateIdentityByEmailRequestObject {
	return gen.CreateIdentityByEmailRequestObject{
		Params: gen.CreateIdentityByEmailParams{IdempotencyKey: key(in.IdempotencyKey)},
		Body:   &gen.CreateIdentityByEmailJSONRequestBody{Email: in.Email},
	}
}

// FromGenHumanIdentity converts a wire human identity result to the domain type.
func FromGenHumanIdentity(g gen.HumanIdentity) ab2bus.CreateIdentityByEmailResult {
	return ab2bus.CreateIdentityByEmailResult{Identity: g.Identity, Created: g.Created}
}
