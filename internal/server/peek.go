package server

import (
	"context"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// Peek answers the read-only pending counts (Decision (Eric, 2026-10-21),
// Milestone 6 item 2). It takes no Idempotency-Key: it writes nothing.
func (a *api) Peek(ctx context.Context, req gen.PeekRequestObject) (gen.PeekResponseObject, error) {
	r, err := a.delivery.Peek(ctx, IdentityFrom(ctx), peekInput(req))
	if err != nil {
		return nil, err
	}
	return gen.Peek200JSONResponse(peekToGen(r)), nil
}

func peekInput(req gen.PeekRequestObject) ab2bus.PeekInput {
	return ab2bus.PeekInput{Session: req.Session, IncludeOwn: derefOr(req.Params.IncludeOwn)}
}

// peekToGen is the wire form of the pending counts; channels is [].
func peekToGen(r ab2bus.PeekResult) gen.Peek {
	out := gen.Peek{Count: r.Count}
	out.Channels = make([]struct {
		Channel string `json:"channel"`
		Count   int    `json:"count"`
	}, 0, len(r.Channels))
	for _, c := range r.Channels {
		out.Channels = append(out.Channels, struct {
			Channel string `json:"channel"`
			Count   int    `json:"count"`
		}{Channel: c.Channel, Count: c.Count})
	}
	return out
}
