package server

import (
	"context"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core/identities"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// AdminReset wipes the bus data (Decision 48, Eric 2026-10-21 Milestone 5 item
// 1). An absent scope is data, the document's default; the validator has
// already refused any value outside the enum.
func (a *api) AdminReset(ctx context.Context, req gen.AdminResetRequestObject) (gen.AdminResetResponseObject, error) {
	in := adminResetInput(req)
	if err := (identities.Service{Core: a.core}).Reset(ctx, IdentityFrom(ctx), in.IdempotencyKey, in.Scope); err != nil {
		return nil, err
	}
	return gen.AdminReset204Response{}, nil
}

// adminResetInput reads the query and the Idempotency-Key header; an absent
// scope is data.
func adminResetInput(req gen.AdminResetRequestObject) bus.ResetInput {
	scope := bus.ResetData
	if req.Params.Scope != nil {
		scope = bus.ResetScope(*req.Params.Scope)
	}
	return bus.ResetInput{Scope: scope, IdempotencyKey: idemKey(req.Params.IdempotencyKey)}
}

// ResetCredential removes every registered key of the path identity
// (Decisions 58, 73). A bearer already minted stays valid until it expires.
func (a *api) ResetCredential(ctx context.Context, req gen.ResetCredentialRequestObject) (gen.ResetCredentialResponseObject, error) {
	in := resetCredentialInput(req)
	n, err := (identities.Service{Core: a.core}).ResetCredentialAs(ctx, IdentityFrom(ctx), in.Identity, in.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	return gen.ResetCredential200JSONResponse(credentialResetToGen(bus.ResetCredentialResult{Identity: in.Identity, KeysRemoved: n})), nil
}

// resetCredentialInput reads the path and the Idempotency-Key header.
func resetCredentialInput(req gen.ResetCredentialRequestObject) bus.ResetCredentialInput {
	return bus.ResetCredentialInput{Identity: req.Identity, IdempotencyKey: idemKey(req.Params.IdempotencyKey)}
}

// credentialResetToGen converts a credential reset result to its wire form.
func credentialResetToGen(r bus.ResetCredentialResult) gen.CredentialReset {
	return gen.CredentialReset{Identity: r.Identity, KeysRemoved: r.KeysRemoved}
}

// CreateIdentityByEmail creates the human identity bound to the body's
// email, or answers the existing one (spec 4.3). Administrator only.
func (a *api) CreateIdentityByEmail(ctx context.Context, req gen.CreateIdentityByEmailRequestObject) (gen.CreateIdentityByEmailResponseObject, error) {
	in := createIdentityByEmailInput(req)
	id, created, err := (identities.Service{Core: a.core}).CreateIdentityByEmailAs(ctx, IdentityFrom(ctx), in.Email, in.IdempotencyKey)
	if err != nil {
		return nil, err
	}
	return gen.CreateIdentityByEmail200JSONResponse(humanIdentityToGen(bus.CreateIdentityByEmailResult{Identity: id, Created: created})), nil
}

// createIdentityByEmailInput reads the body (required: the generated handler
// refuses a request without one) and the Idempotency-Key header.
func createIdentityByEmailInput(req gen.CreateIdentityByEmailRequestObject) bus.CreateIdentityByEmailInput {
	return bus.CreateIdentityByEmailInput{Email: req.Body.Email, IdempotencyKey: idemKey(req.Params.IdempotencyKey)}
}

// humanIdentityToGen converts a human identity result to its wire form.
func humanIdentityToGen(r bus.CreateIdentityByEmailResult) gen.HumanIdentity {
	return gen.HumanIdentity{Identity: r.Identity, Created: r.Created}
}
