package server

import (
	"context"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// SendMessage maps the request to messaging.Service.Send; the Idempotency-Key
// header is the receipt key (Decision 66).
func (a *api) SendMessage(ctx context.Context, req gen.SendMessageRequestObject) (gen.SendMessageResponseObject, error) {
	in, err := sendInput(req)
	if err != nil {
		return nil, err
	}
	res, err := a.messaging.Send(ctx, IdentityFrom(ctx), in)
	if err != nil {
		return nil, err
	}
	return gen.SendMessage201JSONResponse(sendResultToGen(res)), nil
}

// sendInput reads the request; the body is required.
func sendInput(req gen.SendMessageRequestObject) (bus.SendInput, error) {
	if req.Body == nil {
		return bus.SendInput{}, bus.Errorf(bus.CodeValidation, false, "the request body is required")
	}
	b := req.Body
	return bus.SendInput{
		Channel:        req.Channel,
		Subject:        derefOr(b.Subject),
		Content:        b.Content,
		Type:           derefOr(b.Type),
		ReplyTo:        b.ReplyTo,
		Metadata:       derefOr(b.Metadata),
		Tags:           derefOr(b.Tags),
		Session:        derefOr(b.Session),
		IdempotencyKey: derefOr(req.Params.IdempotencyKey),
	}, nil
}

// sendResultToGen converts a send receipt to its wire form.
func sendResultToGen(r bus.SendResult) gen.SendResult {
	return gen.SendResult{Seq: r.Seq, MemoryId: r.MemoryID}
}

// History maps the query to messaging.Service.History; count absent is 0.
func (a *api) History(ctx context.Context, req gen.HistoryRequestObject) (gen.HistoryResponseObject, error) {
	msgs, err := a.messaging.History(ctx, IdentityFrom(ctx), historyInput(req))
	if err != nil {
		return nil, err
	}
	out := make(gen.History200JSONResponse, len(msgs))
	for i, m := range msgs {
		out[i] = toGenMessage(m)
	}
	return out, nil
}

// historyInput reads the path and the query; an absent count is 0.
func historyInput(req gen.HistoryRequestObject) bus.HistoryInput {
	p := req.Params
	return bus.HistoryInput{
		Channel: req.Channel, Before: p.Before, After: p.After,
		Count: derefOr(p.Count), Tags: derefOr(p.Tags), Thread: p.Thread,
	}
}

// Search maps the query to search.Service.Search.
func (a *api) Search(ctx context.Context, req gen.SearchRequestObject) (gen.SearchResponseObject, error) {
	res, err := a.search.Search(ctx, IdentityFrom(ctx), searchInput(req))
	if err != nil {
		return nil, err
	}
	return gen.Search200JSONResponse(searchResultToGen(res)), nil
}

// searchInput reads the query; an absent member is its zero value.
func searchInput(req gen.SearchRequestObject) bus.SearchInput {
	p := req.Params
	in := bus.SearchInput{
		Query: derefOr(p.Q), Channel: derefOr(p.Channel), Sender: derefOr(p.Sender),
		Since: p.Since, Until: p.Until, Thread: p.Thread, Tags: derefOr(p.Tags),
		Count: derefOr(p.Count), Cursor: derefOr(p.Cursor),
	}
	if p.Mode != nil {
		in.Mode = string(*p.Mode)
	}
	return in
}

// searchResultToGen converts a page of hits; next and semantic_unavailable
// are absent, never null or false, when unset.
func searchResultToGen(res bus.SearchResult) gen.SearchResult {
	out := gen.SearchResult{Hits: make([]gen.SearchHit, len(res.Hits))}
	for i, h := range res.Hits {
		out.Hits[i] = gen.SearchHit{Message: toGenMessage(h.Message), Score: h.Score}
	}
	if res.Next != "" {
		n := res.Next
		out.Next = &n
	}
	if res.SemanticUnavailable {
		t := true
		out.SemanticUnavailable = &t
	}
	return out
}
