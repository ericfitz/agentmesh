package remote

import (
	"context"
	"fmt"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// unknownWire is the internal error of a closed enumeration member this
// client does not know (a server speaking another protocol).
func unknownWire(field, v string) error {
	return &ab2bus.Error{Code: ab2bus.CodeInternal, Message: fmt.Sprintf("server sent unknown %s %q", field, v)}
}

// FromGenScope converts a wire scope, refusing a state or retire mode outside
// the closed sets.
func FromGenScope(g gen.Scope) (ab2bus.Scope, error) {
	out := ab2bus.Scope{
		Name: g.Name, CreatedAt: g.CreatedAt, DoneAt: deref(g.DoneAt), LastActivity: g.LastActivity,
		Channels: deref(g.Channels), Identities: deref(g.Identities),
	}
	switch s := ab2bus.ScopeState(g.State); s {
	case ab2bus.ScopeOpen, ab2bus.ScopeDone, ab2bus.ScopeRetired:
		out.State = s
	default:
		return ab2bus.Scope{}, unknownWire("state", string(g.State))
	}
	if g.Retire != nil {
		switch m := ab2bus.RetireMode(*g.Retire); m {
		case ab2bus.RetireWithBridge, ab2bus.RetireNormal:
			out.Retire = m
		default:
			return ab2bus.Scope{}, unknownWire("retire", string(*g.Retire))
		}
	}
	return out, nil
}

// FromGenBridge converts a wire bridge, refusing a state outside the closed
// set.
func FromGenBridge(g gen.Bridge) (ab2bus.Bridge, error) {
	out := ab2bus.Bridge{
		Channel: g.Channel, Scope: g.Scope, SlackChannelID: deref(g.SlackChannelId), SlackName: g.SlackName,
		CreatedAt: g.CreatedAt, ArchivedAt: deref(g.ArchivedAt),
	}
	switch s := ab2bus.BridgeState(g.State); s {
	case ab2bus.BridgeCreating, ab2bus.BridgeLive, ab2bus.BridgeArchived:
		out.State = s
	default:
		return ab2bus.Bridge{}, unknownWire("state", string(g.State))
	}
	return out, nil
}

// CreateScope makes an open scope.
func (b *Bus) CreateScope(ctx context.Context, in ab2bus.CreateScopeInput) (ab2bus.Scope, error) {
	req := CreateScopeRequest(in)
	r, err := b.c.CreateScopeWithResponse(ctx, &req.Params, *req.Body)
	if err != nil {
		return ab2bus.Scope{}, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), r.ApplicationproblemJSONDefault, r.Body, nil); err != nil {
		return ab2bus.Scope{}, err
	}
	if r.JSON200 == nil {
		return ab2bus.Scope{}, unparsable(r.StatusCode())
	}
	return FromGenScope(*r.JSON200)
}

// CreateScopeRequest builds the request for CreateScope; Body is always set.
func CreateScopeRequest(in ab2bus.CreateScopeInput) gen.CreateScopeRequestObject {
	return gen.CreateScopeRequestObject{
		Params: gen.CreateScopeParams{IdempotencyKey: key(in.IdempotencyKey)},
		Body:   &gen.CreateScopeJSONRequestBody{Name: in.Name},
	}
}

// ListScopes lists the open and done scopes.
func (b *Bus) ListScopes(ctx context.Context) ([]ab2bus.Scope, error) {
	r, err := b.c.ListScopesWithResponse(ctx)
	if err != nil {
		return nil, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), r.ApplicationproblemJSONDefault, r.Body, nil); err != nil {
		return nil, err
	}
	if r.JSON200 == nil {
		return nil, unparsable(r.StatusCode())
	}
	return FromGenScopeList(*r.JSON200)
}

// FromGenScopeList converts a wire scope list, refusing a scope outside the
// closed sets.
func FromGenScopeList(l gen.ScopeList) ([]ab2bus.Scope, error) {
	out := make([]ab2bus.Scope, len(l.Scopes))
	for i, g := range l.Scopes {
		sc, err := FromGenScope(g)
		if err != nil {
			return nil, err
		}
		out[i] = sc
	}
	return out, nil
}

// GetScope returns one scope with its channel and identity names.
func (b *Bus) GetScope(ctx context.Context, name string) (ab2bus.Scope, error) {
	r, err := b.c.GetScopeWithResponse(ctx, name)
	if err != nil {
		return ab2bus.Scope{}, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), r.ApplicationproblemJSONDefault, r.Body, nil); err != nil {
		return ab2bus.Scope{}, err
	}
	if r.JSON200 == nil {
		return ab2bus.Scope{}, unparsable(r.StatusCode())
	}
	return FromGenScope(*r.JSON200)
}

// DoneScope marks a scope done. A retire mode outside the closed set is
// refused with validation before anything is sent, as the local Bus does.
func (b *Bus) DoneScope(ctx context.Context, in ab2bus.DoneScopeInput) (ab2bus.Scope, error) {
	if in.Retire != ab2bus.RetireWithBridge && in.Retire != ab2bus.RetireNormal {
		return ab2bus.Scope{}, &ab2bus.Error{Code: ab2bus.CodeValidation,
			Message: fmt.Sprintf("retire must be %q or %q, got %q", ab2bus.RetireWithBridge, ab2bus.RetireNormal, string(in.Retire))}
	}
	req := DoneScopeRequest(in)
	r, err := b.c.DoneScopeWithResponse(ctx, req.Scope, &req.Params, *req.Body)
	if err != nil {
		return ab2bus.Scope{}, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), r.ApplicationproblemJSONDefault, r.Body, nil); err != nil {
		return ab2bus.Scope{}, err
	}
	if r.JSON200 == nil {
		return ab2bus.Scope{}, unparsable(r.StatusCode())
	}
	return FromGenScope(*r.JSON200)
}

// DoneScopeRequest builds the request for DoneScope; Body is always set. It
// does not validate the retire mode (DoneScope does, before sending).
func DoneScopeRequest(in ab2bus.DoneScopeInput) gen.DoneScopeRequestObject {
	return gen.DoneScopeRequestObject{
		Scope:  in.Name,
		Params: gen.DoneScopeParams{IdempotencyKey: key(in.IdempotencyKey)},
		Body:   &gen.DoneScopeJSONRequestBody{Retire: gen.DoneScopeRequestRetire(in.Retire)},
	}
}

// CreateAgentIdentity creates an agent identity, optionally in a scope, and
// its one-time enrollment token.
func (b *Bus) CreateAgentIdentity(ctx context.Context, in ab2bus.CreateAgentIdentityInput) (ab2bus.AgentIdentity, error) {
	req := CreateAgentIdentityRequest(in)
	r, err := b.c.CreateAgentIdentityWithResponse(ctx, *req.Body)
	if err != nil {
		return ab2bus.AgentIdentity{}, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), r.ApplicationproblemJSONDefault, r.Body, nil); err != nil {
		return ab2bus.AgentIdentity{}, err
	}
	if r.JSON200 == nil {
		return ab2bus.AgentIdentity{}, unparsable(r.StatusCode())
	}
	return FromGenAgentIdentity(*r.JSON200), nil
}

// CreateAgentIdentityRequest builds the request for CreateAgentIdentity; Body
// is always set and an empty scope is absent.
func CreateAgentIdentityRequest(in ab2bus.CreateAgentIdentityInput) gen.CreateAgentIdentityRequestObject {
	return gen.CreateAgentIdentityRequestObject{
		Body: &gen.CreateAgentIdentityJSONRequestBody{Name: in.Name, Scope: strPtr(in.Scope)},
	}
}

// FromGenAgentIdentity converts a wire agent identity result to the domain type.
func FromGenAgentIdentity(g gen.AgentIdentity) ab2bus.AgentIdentity {
	return ab2bus.AgentIdentity{Identity: g.Identity, Scope: deref(g.Scope), Created: g.Created, EnrollmentToken: g.EnrollmentToken, ExpiresAt: g.ExpiresAt}
}

// CreateBridge bridges a channel to a new private Slack channel.
func (b *Bus) CreateBridge(ctx context.Context, in ab2bus.CreateBridgeInput) (ab2bus.BridgeCreated, error) {
	req := CreateBridgeRequest(in)
	r, err := b.c.CreateBridgeWithResponse(ctx, *req.Body)
	if err != nil {
		return ab2bus.BridgeCreated{}, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), r.ApplicationproblemJSONDefault, r.Body, nil); err != nil {
		return ab2bus.BridgeCreated{}, err
	}
	if r.JSON200 == nil {
		return ab2bus.BridgeCreated{}, unparsable(r.StatusCode())
	}
	return FromGenBridgeCreated(*r.JSON200)
}

// CreateBridgeRequest builds the request for CreateBridge; Body is always set
// and an empty Slack name is absent.
func CreateBridgeRequest(in ab2bus.CreateBridgeInput) gen.CreateBridgeRequestObject {
	return gen.CreateBridgeRequestObject{
		Body: &gen.CreateBridgeJSONRequestBody{Channel: in.Channel, SlackName: strPtr(in.SlackName)},
	}
}

// FromGenBridgeCreated converts a wire created bridge, refusing a bridge
// state outside the closed set; not_invited is never nil.
func FromGenBridgeCreated(g gen.BridgeCreated) (ab2bus.BridgeCreated, error) {
	br, err := FromGenBridge(g.Bridge)
	if err != nil {
		return ab2bus.BridgeCreated{}, err
	}
	out := ab2bus.BridgeCreated{Bridge: br, NotInvited: make([]ab2bus.BridgeNotInvited, len(g.NotInvited))}
	for i, n := range g.NotInvited {
		out.NotInvited[i] = ab2bus.BridgeNotInvited{Identity: n.Identity, Reason: n.Reason}
	}
	return out, nil
}

// ListBridges lists every bridge.
func (b *Bus) ListBridges(ctx context.Context) ([]ab2bus.Bridge, error) {
	r, err := b.c.ListBridgesWithResponse(ctx)
	if err != nil {
		return nil, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), r.ApplicationproblemJSONDefault, r.Body, nil); err != nil {
		return nil, err
	}
	if r.JSON200 == nil {
		return nil, unparsable(r.StatusCode())
	}
	return FromGenBridgeList(*r.JSON200)
}

// FromGenBridgeList converts a wire bridge list, refusing a bridge outside
// the closed sets.
func FromGenBridgeList(l gen.BridgeList) ([]ab2bus.Bridge, error) {
	out := make([]ab2bus.Bridge, len(l.Bridges))
	for i, g := range l.Bridges {
		br, err := FromGenBridge(g)
		if err != nil {
			return nil, err
		}
		out[i] = br
	}
	return out, nil
}

// GetBridge returns the bridge of a channel.
func (b *Bus) GetBridge(ctx context.Context, channel string) (ab2bus.Bridge, error) {
	r, err := b.c.GetBridgeWithResponse(ctx, channel)
	if err != nil {
		return ab2bus.Bridge{}, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), r.ApplicationproblemJSONDefault, r.Body, nil); err != nil {
		return ab2bus.Bridge{}, err
	}
	if r.JSON200 == nil {
		return ab2bus.Bridge{}, unparsable(r.StatusCode())
	}
	return FromGenBridge(*r.JSON200)
}

// RemoveBridge archives the Slack channel of a channel's bridge and deletes
// the bridge.
func (b *Bus) RemoveBridge(ctx context.Context, in ab2bus.RemoveBridgeInput) error {
	req := RemoveBridgeRequest(in)
	r, err := b.c.RemoveBridgeWithResponse(ctx, req.Channel)
	if err != nil {
		return errorOf(ctx, 0, nil, nil, err)
	}
	return errorOf(ctx, r.StatusCode(), r.ApplicationproblemJSONDefault, r.Body, nil)
}

// RemoveBridgeRequest builds the request for RemoveBridge.
func RemoveBridgeRequest(in ab2bus.RemoveBridgeInput) gen.RemoveBridgeRequestObject {
	return gen.RemoveBridgeRequestObject{Channel: in.Channel}
}
