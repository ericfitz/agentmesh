package remote

import (
	"context"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// Channel, ACL and subscription methods. Every channel name goes to the
// generated client as given (choice 17); the generated client escapes it.

func (b *Bus) ListChannels(ctx context.Context) ([]ab2bus.Channel, error) {
	r, err := b.c.ListChannelsWithResponse(ctx)
	if err != nil {
		return nil, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil); err != nil {
		return nil, err
	}
	if r.JSON200 == nil {
		return nil, unparsable(r.StatusCode())
	}
	out := make([]ab2bus.Channel, len(*r.JSON200))
	for i, c := range *r.JSON200 {
		out[i] = FromGenChannel(c)
	}
	return out, nil
}

// FromGenChannel converts a wire channel to the domain type.
func FromGenChannel(c gen.Channel) ab2bus.Channel {
	return ab2bus.Channel{Name: c.Name, Kind: fromGenKind(c.Kind), Capabilities: fromGenCapabilities(c.Capabilities)}
}

// CreateChannelRequest builds the request for CreateChannel; Body is always
// set, and a nil ACL stays absent (the configured default) while an empty one
// is sent as [].
func CreateChannelRequest(in ab2bus.CreateChannelInput) gen.CreateChannelRequestObject {
	body := gen.CreateChannelRequest{Name: in.Name}
	if in.Kind != "" {
		k := gen.CreateChannelRequestKind(in.Kind)
		body.Kind = &k
	}
	if in.Scope != "" {
		body.Scope = &in.Scope
	}
	if in.ACL != nil { // nil is the configured default; empty is "no entries"
		acl := make([]gen.ACLEntry, len(in.ACL))
		for i, e := range in.ACL {
			acl[i] = toGenACLEntry(e)
		}
		body.Acl = &acl
	}
	return gen.CreateChannelRequestObject{Params: gen.CreateChannelParams{IdempotencyKey: key(in.IdempotencyKey)}, Body: &body}
}

func (b *Bus) CreateChannel(ctx context.Context, in ab2bus.CreateChannelInput) (ab2bus.ChannelInfo, error) {
	req := CreateChannelRequest(in)
	r, err := b.c.CreateChannelWithResponse(ctx, &req.Params, *req.Body)
	if err != nil {
		return ab2bus.ChannelInfo{}, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil); err != nil {
		return ab2bus.ChannelInfo{}, err
	}
	if r.JSON201 == nil {
		return ab2bus.ChannelInfo{}, unparsable(r.StatusCode())
	}
	return FromGenChannelInfo(*r.JSON201), nil
}

// fromGenCapabilities copies the strings unfiltered; an absent array (nil)
// is the empty set, never an error.
func fromGenCapabilities(in []string) []ab2bus.ChannelCapability {
	out := make([]ab2bus.ChannelCapability, len(in))
	for i, c := range in {
		out[i] = ab2bus.ChannelCapability(c)
	}
	return out
}

// FromGenChannelInfo converts a wire channel description to the domain type.
func FromGenChannelInfo(c gen.ChannelInfo) ab2bus.ChannelInfo {
	return ab2bus.ChannelInfo{
		Channel: ab2bus.Channel{Name: c.Name, Kind: ab2bus.Kind(c.Kind), Capabilities: fromGenCapabilities(c.Capabilities)},
		Creator: c.Creator, Scope: deref(c.Scope), CreatedAt: c.CreatedAt,
	}
}

// DeleteChannelRequest builds the request for DeleteChannel.
func DeleteChannelRequest(in ab2bus.DeleteChannelInput) gen.DeleteChannelRequestObject {
	return gen.DeleteChannelRequestObject{Channel: in.Name, Params: gen.DeleteChannelParams{IdempotencyKey: key(in.IdempotencyKey)}}
}

func (b *Bus) DeleteChannel(ctx context.Context, in ab2bus.DeleteChannelInput) error {
	req := DeleteChannelRequest(in)
	r, err := b.c.DeleteChannelWithResponse(ctx, req.Channel, &req.Params)
	if err != nil {
		return errorOf(ctx, 0, nil, nil, err)
	}
	return errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil)
}

// RenameChannelRequest builds the request for RenameChannel; Body is always
// set.
func RenameChannelRequest(in ab2bus.RenameChannelInput) gen.RenameChannelRequestObject {
	return gen.RenameChannelRequestObject{
		Channel: in.Name, Params: gen.RenameChannelParams{IdempotencyKey: key(in.IdempotencyKey)},
		Body: &gen.RenameChannelRequest{Name: in.NewName},
	}
}

func (b *Bus) RenameChannel(ctx context.Context, in ab2bus.RenameChannelInput) error {
	req := RenameChannelRequest(in)
	r, err := b.c.RenameChannelWithResponse(ctx, req.Channel, &req.Params, *req.Body)
	if err != nil {
		return errorOf(ctx, 0, nil, nil, err)
	}
	return errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil)
}

func (b *Bus) ACL(ctx context.Context, channel string) ([]ab2bus.ACLEntry, error) {
	r, err := b.c.GetACLWithResponse(ctx, channel)
	if err != nil {
		return nil, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil); err != nil {
		return nil, err
	}
	if r.JSON200 == nil {
		return nil, unparsable(r.StatusCode())
	}
	out := make([]ab2bus.ACLEntry, len(*r.JSON200))
	for i, e := range *r.JSON200 {
		out[i] = FromGenACLEntry(e)
	}
	return out, nil
}

// SetACLRequest builds the request for SetACL; Body is always set, and nil
// entries are sent as [].
func SetACLRequest(in ab2bus.SetACLInput) gen.SetACLRequestObject {
	entries := make([]gen.ACLEntry, len(in.Entries))
	for i, e := range in.Entries {
		entries[i] = toGenACLEntry(e)
	}
	return gen.SetACLRequestObject{Channel: in.Channel, Params: gen.SetACLParams{IdempotencyKey: key(in.IdempotencyKey)}, Body: &entries}
}

func (b *Bus) SetACL(ctx context.Context, in ab2bus.SetACLInput) error {
	req := SetACLRequest(in)
	r, err := b.c.SetACLWithResponse(ctx, req.Channel, &req.Params, *req.Body)
	if err != nil {
		return errorOf(ctx, 0, nil, nil, err)
	}
	return errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil)
}

// SubscribeRequest builds the request for Subscribe; Body is always set, and
// from is absent when empty.
func SubscribeRequest(in ab2bus.SubscribeInput) gen.SubscribeRequestObject {
	var body gen.SubscribeRequest
	if in.From != "" {
		f := gen.SubscribeRequestFrom(in.From)
		body.From = &f
	}
	return gen.SubscribeRequestObject{Channel: in.Channel, Params: gen.SubscribeParams{IdempotencyKey: key(in.IdempotencyKey)}, Body: &body}
}

func (b *Bus) Subscribe(ctx context.Context, in ab2bus.SubscribeInput) error {
	req := SubscribeRequest(in)
	r, err := b.c.SubscribeWithResponse(ctx, req.Channel, &req.Params, *req.Body)
	if err != nil {
		return errorOf(ctx, 0, nil, nil, err)
	}
	return errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil)
}

// UnsubscribeRequest builds the request for Unsubscribe.
func UnsubscribeRequest(in ab2bus.UnsubscribeInput) gen.UnsubscribeRequestObject {
	return gen.UnsubscribeRequestObject{Channel: in.Channel, Params: gen.UnsubscribeParams{IdempotencyKey: key(in.IdempotencyKey)}}
}

func (b *Bus) Unsubscribe(ctx context.Context, in ab2bus.UnsubscribeInput) error {
	req := UnsubscribeRequest(in)
	r, err := b.c.UnsubscribeWithResponse(ctx, req.Channel, &req.Params)
	if err != nil {
		return errorOf(ctx, 0, nil, nil, err)
	}
	return errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil)
}

// SubscribeTagsRequest builds the request for SubscribeTags; Body is always
// set.
func SubscribeTagsRequest(in ab2bus.TagSubscribeInput) gen.SubscribeTagsRequestObject {
	return gen.SubscribeTagsRequestObject{
		Params: gen.SubscribeTagsParams{IdempotencyKey: key(in.IdempotencyKey)},
		Body:   &gen.TagPatterns{Patterns: in.Patterns},
	}
}

func (b *Bus) SubscribeTags(ctx context.Context, in ab2bus.TagSubscribeInput) error {
	req := SubscribeTagsRequest(in)
	r, err := b.c.SubscribeTagsWithResponse(ctx, &req.Params, *req.Body)
	if err != nil {
		return errorOf(ctx, 0, nil, nil, err)
	}
	return errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil)
}

func (b *Bus) UnsubscribeTags(ctx context.Context, in ab2bus.TagSubscribeInput) error {
	// Decision (Eric, 2026-10-21): Milestone 4 item 6, options A and C. The
	// patterns travel as a repeated `pattern` query value, one per pattern, so
	// a comma stays inside its pattern (TestUnsubscribeTagsCommaAgrees). The
	// guard stays: no pattern, or one empty pattern alone, is answered here
	// with the core's validation and nothing is sent; every other input goes
	// to the wire as given (choice 17) and the core judges it.
	if len(in.Patterns) == 0 || (len(in.Patterns) == 1 && in.Patterns[0] == "") {
		return &ab2bus.Error{Code: ab2bus.CodeValidation, Message: "a tag subscription needs at least one pattern"}
	}
	req := UnsubscribeTagsRequest(in)
	r, err := b.c.UnsubscribeTagsWithResponse(ctx, &req.Params)
	if err != nil {
		return errorOf(ctx, 0, nil, nil, err)
	}
	return errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil)
}

// UnsubscribeTagsRequest builds the request for UnsubscribeTags: one
// repeated pattern query value per pattern.
func UnsubscribeTagsRequest(in ab2bus.TagSubscribeInput) gen.UnsubscribeTagsRequestObject {
	return gen.UnsubscribeTagsRequestObject{Params: gen.UnsubscribeTagsParams{Pattern: in.Patterns, IdempotencyKey: key(in.IdempotencyKey)}}
}

func (b *Bus) TagSubscriptions(ctx context.Context) ([][]string, error) {
	r, err := b.c.ListTagSubscriptionsWithResponse(ctx)
	if err != nil {
		return nil, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil); err != nil {
		return nil, err
	}
	if r.JSON200 == nil {
		return nil, unparsable(r.StatusCode())
	}
	return *r.JSON200, nil
}
