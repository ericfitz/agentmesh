package server

import (
	"context"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// Channel, ACL and subscription handlers (Task 6). Each passes the identity
// from the context and the idempotency key from the header straight to the
// core; names arrive as bound by the generated code (Decision 80).

func idemKey(k *string) string {
	if k == nil {
		return ""
	}
	return *k
}

func channelACLFromGen(in []gen.ACLEntry) []bus.ACLEntry {
	out := make([]bus.ACLEntry, len(in))
	for i, e := range in {
		out[i] = bus.ACLEntry{Identity: e.Identity, Permissions: make([]bus.Permission, len(e.Permissions))}
		for j, p := range e.Permissions {
			out[i].Permissions[j] = bus.Permission(p)
		}
	}
	return out
}

func channelACLToGen(in []bus.ACLEntry) []gen.ACLEntry {
	out := make([]gen.ACLEntry, len(in))
	for i, e := range in {
		out[i] = aclEntryToGen(e)
	}
	return out
}

func aclEntryToGen(e bus.ACLEntry) gen.ACLEntry {
	out := gen.ACLEntry{Identity: e.Identity, Permissions: make([]gen.ACLEntryPermissions, len(e.Permissions))}
	for j, p := range e.Permissions {
		out.Permissions[j] = gen.ACLEntryPermissions(p)
	}
	return out
}

func channelInfoToGen(c bus.ChannelInfo) gen.ChannelInfo {
	out := gen.ChannelInfo{Name: c.Name, Kind: gen.ChannelInfoKind(c.Kind), Creator: c.Creator, CreatedAt: c.CreatedAt}
	if c.Scope != "" {
		out.Scope = &c.Scope
	}
	out.Capabilities = capabilityStrings(c.Capabilities)
	return out
}

// capabilityStrings copies the capabilities as strings; never nil, because a
// nil slice would marshal as null.
func capabilityStrings(in []bus.ChannelCapability) []string {
	out := make([]string, len(in))
	for i, c := range in {
		out[i] = string(c)
	}
	return out
}

func (a *api) ListChannels(ctx context.Context, _ gen.ListChannelsRequestObject) (gen.ListChannelsResponseObject, error) {
	chs, err := a.channels.List(ctx, IdentityFrom(ctx))
	if err != nil {
		return nil, err
	}
	out := make(gen.ListChannels200JSONResponse, len(chs))
	for i, c := range chs {
		out[i] = channelToGen(c)
	}
	return out, nil
}

// channelToGen converts a channel to its wire form.
func channelToGen(c bus.Channel) gen.Channel {
	return gen.Channel{Name: c.Name, Kind: gen.ChannelKind(c.Kind), Capabilities: capabilityStrings(c.Capabilities)}
}

func (a *api) CreateChannel(ctx context.Context, req gen.CreateChannelRequestObject) (gen.CreateChannelResponseObject, error) {
	info, err := a.channels.Create(ctx, IdentityFrom(ctx), createChannelInput(req))
	if err != nil {
		return nil, err
	}
	return gen.CreateChannel201JSONResponse(channelInfoToGen(info)), nil
}

// createChannelInput reads the request; no body is an empty input, and the
// core judges it.
func createChannelInput(req gen.CreateChannelRequestObject) bus.CreateChannelInput {
	in := bus.CreateChannelInput{IdempotencyKey: idemKey(req.Params.IdempotencyKey)}
	if req.Body != nil {
		in.Name = req.Body.Name
		if req.Body.Scope != nil {
			in.Scope = *req.Body.Scope
		}
		if req.Body.Kind != nil {
			in.Kind = bus.Kind(*req.Body.Kind)
		}
		// Absent acl is nil (the configured default); [] is empty (Milestone 2 choice 9).
		if req.Body.Acl != nil {
			in.ACL = channelACLFromGen(*req.Body.Acl)
		}
	}
	return in
}

func (a *api) DeleteChannel(ctx context.Context, req gen.DeleteChannelRequestObject) (gen.DeleteChannelResponseObject, error) {
	if err := a.channels.Delete(ctx, IdentityFrom(ctx), deleteChannelInput(req)); err != nil {
		return nil, err
	}
	return gen.DeleteChannel204Response{}, nil
}

// deleteChannelInput reads the path and the idempotency header.
func deleteChannelInput(req gen.DeleteChannelRequestObject) bus.DeleteChannelInput {
	return bus.DeleteChannelInput{Name: req.Channel, IdempotencyKey: idemKey(req.Params.IdempotencyKey)}
}

func (a *api) RenameChannel(ctx context.Context, req gen.RenameChannelRequestObject) (gen.RenameChannelResponseObject, error) {
	if err := a.channels.Rename(ctx, IdentityFrom(ctx), renameChannelInput(req)); err != nil {
		return nil, err
	}
	return gen.RenameChannel204Response{}, nil
}

// renameChannelInput reads the request; no body leaves the new name empty.
func renameChannelInput(req gen.RenameChannelRequestObject) bus.RenameChannelInput {
	in := bus.RenameChannelInput{Name: req.Channel, IdempotencyKey: idemKey(req.Params.IdempotencyKey)}
	if req.Body != nil {
		in.NewName = req.Body.Name
	}
	return in
}

func (a *api) GetACL(ctx context.Context, req gen.GetACLRequestObject) (gen.GetACLResponseObject, error) {
	acl, err := a.channels.ACL(ctx, IdentityFrom(ctx), req.Channel)
	if err != nil {
		return nil, err
	}
	return gen.GetACL200JSONResponse(channelACLToGen(acl)), nil
}

func (a *api) SetACL(ctx context.Context, req gen.SetACLRequestObject) (gen.SetACLResponseObject, error) {
	if err := a.channels.SetACL(ctx, IdentityFrom(ctx), setACLInput(req)); err != nil {
		return nil, err
	}
	return gen.SetACL204Response{}, nil
}

// setACLInput reads the request; no body leaves the entries nil.
func setACLInput(req gen.SetACLRequestObject) bus.SetACLInput {
	in := bus.SetACLInput{Channel: req.Channel, IdempotencyKey: idemKey(req.Params.IdempotencyKey)}
	if req.Body != nil {
		in.Entries = channelACLFromGen(*req.Body)
	}
	return in
}

func (a *api) Subscribe(ctx context.Context, req gen.SubscribeRequestObject) (gen.SubscribeResponseObject, error) {
	if err := a.channels.Subscribe(ctx, IdentityFrom(ctx), subscribeInput(req)); err != nil {
		return nil, err
	}
	return gen.Subscribe204Response{}, nil
}

// subscribeInput reads the request; no body or an absent from is "".
func subscribeInput(req gen.SubscribeRequestObject) bus.SubscribeInput {
	in := bus.SubscribeInput{Channel: req.Channel, IdempotencyKey: idemKey(req.Params.IdempotencyKey)}
	if req.Body != nil && req.Body.From != nil {
		in.From = string(*req.Body.From)
	}
	return in
}

func (a *api) Unsubscribe(ctx context.Context, req gen.UnsubscribeRequestObject) (gen.UnsubscribeResponseObject, error) {
	if err := a.channels.Unsubscribe(ctx, IdentityFrom(ctx), unsubscribeInput(req)); err != nil {
		return nil, err
	}
	return gen.Unsubscribe204Response{}, nil
}

// unsubscribeInput reads the path and the idempotency header.
func unsubscribeInput(req gen.UnsubscribeRequestObject) bus.UnsubscribeInput {
	return bus.UnsubscribeInput{Channel: req.Channel, IdempotencyKey: idemKey(req.Params.IdempotencyKey)}
}

func (a *api) ListTagSubscriptions(ctx context.Context, _ gen.ListTagSubscriptionsRequestObject) (gen.ListTagSubscriptionsResponseObject, error) {
	sets, err := a.channels.TagSubscriptions(ctx, IdentityFrom(ctx))
	if err != nil {
		return nil, err
	}
	out := make(gen.ListTagSubscriptions200JSONResponse, len(sets))
	for i, s := range sets {
		out[i] = append([]string{}, s...)
	}
	return out, nil
}

func (a *api) SubscribeTags(ctx context.Context, req gen.SubscribeTagsRequestObject) (gen.SubscribeTagsResponseObject, error) {
	if err := a.channels.SubscribeTags(ctx, IdentityFrom(ctx), subscribeTagsInput(req)); err != nil {
		return nil, err
	}
	return gen.SubscribeTags204Response{}, nil
}

// subscribeTagsInput reads the request; no body leaves the patterns nil.
func subscribeTagsInput(req gen.SubscribeTagsRequestObject) bus.TagSubscribeInput {
	in := bus.TagSubscribeInput{IdempotencyKey: idemKey(req.Params.IdempotencyKey)}
	if req.Body != nil {
		in.Patterns = req.Body.Patterns
	}
	return in
}

func (a *api) UnsubscribeTags(ctx context.Context, req gen.UnsubscribeTagsRequestObject) (gen.UnsubscribeTagsResponseObject, error) {
	if err := a.channels.UnsubscribeTags(ctx, IdentityFrom(ctx), unsubscribeTagsInput(req)); err != nil {
		return nil, err
	}
	return gen.UnsubscribeTags204Response{}, nil
}

// unsubscribeTagsInput reads the repeated pattern query values and the
// idempotency header.
func unsubscribeTagsInput(req gen.UnsubscribeTagsRequestObject) bus.TagSubscribeInput {
	return bus.TagSubscribeInput{Patterns: req.Params.Pattern, IdempotencyKey: idemKey(req.Params.IdempotencyKey)}
}
