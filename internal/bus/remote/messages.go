package remote

import (
	"context"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// Send posts the message; the idempotency key travels as the header.
//
// An empty channel is the one name this method judges itself: core Send answers
// validation for it, while the wire's empty path segment is the router's 404
// not_found, so the request is not sent (the plan's empty-name contingency, a
// Decision 80 departure limited to the empty name).
// Decision (Eric, 2026-10-21): Milestone 4 item 6 (option A: keep the guard).
func (b *Bus) Send(ctx context.Context, in ab2bus.SendInput) (ab2bus.SendResult, error) {
	if in.Channel == "" {
		return ab2bus.SendResult{}, ab2bus.Errorf(ab2bus.CodeValidation, false, "channel is required")
	}
	req := SendMessageRequest(in)
	resp, err := b.c.SendMessageWithResponse(ctx, req.Channel, &req.Params, *req.Body)
	if err != nil {
		return ab2bus.SendResult{}, errorOf(ctx, 0, nil, nil, err)
	}
	if e := errorOf(ctx, resp.StatusCode(), resp.ApplicationproblemJSONDefault, resp.Body, nil); e != nil {
		return ab2bus.SendResult{}, e
	}
	if resp.JSON201 == nil {
		return ab2bus.SendResult{}, unparsable(resp.StatusCode())
	}
	return FromGenSendResult(*resp.JSON201), nil
}

// SendMessageRequest builds the request for Send; Body is always set, and its
// optional members are absent for their zero values.
func SendMessageRequest(in ab2bus.SendInput) gen.SendMessageRequestObject {
	return gen.SendMessageRequestObject{
		Channel: in.Channel,
		Params:  gen.SendMessageParams{IdempotencyKey: key(in.IdempotencyKey)},
		Body: &gen.SendRequest{
			Content: in.Content, Subject: strPtr(in.Subject), Type: strPtr(in.Type),
			ReplyTo: in.ReplyTo, Metadata: mapPtr(in.Metadata), Tags: slicePtr(in.Tags),
			Session: strPtr(in.Session),
		},
	}
}

// FromGenSendResult converts a wire send receipt to the domain type.
func FromGenSendResult(r gen.SendResult) ab2bus.SendResult {
	return ab2bus.SendResult{Seq: r.Seq, MemoryID: r.MemoryId}
}

// History reads a window of the channel; count 0 is absent.
func (b *Bus) History(ctx context.Context, in ab2bus.HistoryInput) ([]ab2bus.Message, error) {
	req := HistoryRequest(in)
	resp, err := b.c.HistoryWithResponse(ctx, req.Channel, &req.Params)
	if err != nil {
		return nil, errorOf(ctx, 0, nil, nil, err)
	}
	if e := errorOf(ctx, resp.StatusCode(), resp.ApplicationproblemJSONDefault, resp.Body, nil); e != nil {
		return nil, e
	}
	if resp.JSON200 == nil {
		return nil, unparsable(resp.StatusCode())
	}
	out := make([]ab2bus.Message, len(*resp.JSON200))
	for i, m := range *resp.JSON200 {
		if out[i], err = FromGenMessage(m); err != nil {
			return nil, err
		}
	}
	return out, nil
}

// HistoryRequest builds the request for History; count 0 and an empty tag
// list are absent.
func HistoryRequest(in ab2bus.HistoryInput) gen.HistoryRequestObject {
	p := gen.HistoryParams{Before: in.Before, After: in.After, Thread: in.Thread, Tags: queryTags(in.Tags)}
	if in.Count != 0 {
		p.Count = ptr(in.Count)
	}
	return gen.HistoryRequestObject{Channel: in.Channel, Params: p}
}

// Search queries readable channels; empty strings and zero counts are absent.
func (b *Bus) Search(ctx context.Context, in ab2bus.SearchInput) (ab2bus.SearchResult, error) {
	req := SearchRequest(in)
	resp, err := b.c.SearchWithResponse(ctx, &req.Params)
	if err != nil {
		return ab2bus.SearchResult{}, errorOf(ctx, 0, nil, nil, err)
	}
	if e := errorOf(ctx, resp.StatusCode(), resp.ApplicationproblemJSONDefault, resp.Body, nil); e != nil {
		return ab2bus.SearchResult{}, e
	}
	if resp.JSON200 == nil {
		return ab2bus.SearchResult{}, unparsable(resp.StatusCode())
	}
	return FromGenSearchResult(*resp.JSON200)
}

// SearchRequest builds the request for Search; an empty string and a zero
// count are absent (the query is always sent).
func SearchRequest(in ab2bus.SearchInput) gen.SearchRequestObject {
	p := gen.SearchParams{
		Q: ptr(in.Query), Channel: strPtr(in.Channel), Sender: strPtr(in.Sender),
		Since: in.Since, Until: in.Until, Thread: in.Thread, Tags: queryTags(in.Tags),
		Cursor: strPtr(in.Cursor),
	}
	if in.Mode != "" {
		p.Mode = ptr(gen.SearchParamsMode(in.Mode))
	}
	if in.Count != 0 {
		p.Count = ptr(in.Count)
	}
	return gen.SearchRequestObject{Params: p}
}

// FromGenSearchResult converts a wire page of hits; a hit with an unknown
// sender kind is an internal error.
func FromGenSearchResult(r gen.SearchResult) (ab2bus.SearchResult, error) {
	out := ab2bus.SearchResult{
		Next: deref(r.Next), SemanticUnavailable: deref(r.SemanticUnavailable),
		Hits: make([]ab2bus.SearchHit, len(r.Hits)),
	}
	for i, h := range r.Hits {
		m, err := FromGenMessage(h.Message)
		if err != nil {
			return ab2bus.SearchResult{}, err
		}
		out.Hits[i] = ab2bus.SearchHit{Message: m, Score: h.Score}
	}
	return out, nil
}

// queryTags is the tags query parameter: nil for an empty list. A
// form/explode:false query array cannot encode the empty set (the validator
// rejects "tags="), and the core reads an empty tag list as no filter, so the
// empty list travels as an absent parameter (a wire-encoding rule).
func queryTags(tags []string) *[]string {
	if len(tags) == 0 {
		return nil
	}
	return &tags
}
