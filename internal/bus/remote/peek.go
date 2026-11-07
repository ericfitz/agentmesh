package remote

import (
	"context"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// PeekRequest builds the request for Peek; include_own is sent only when true.
func PeekRequest(in ab2bus.PeekInput) gen.PeekRequestObject {
	params := gen.PeekParams{}
	if in.IncludeOwn {
		params.IncludeOwn = ptr(true)
	}
	return gen.PeekRequestObject{Session: in.Session, Params: params}
}

// FromGenPeek converts the wire pending counts.
func FromGenPeek(p gen.Peek) ab2bus.PeekResult {
	out := ab2bus.PeekResult{Count: p.Count, Channels: make([]ab2bus.PeekChannel, 0, len(p.Channels))}
	for _, c := range p.Channels {
		out.Channels = append(out.Channels, ab2bus.PeekChannel{Channel: c.Channel, Count: c.Count})
	}
	return out
}

// Peek is GET /v1/sessions/{session}/peek.
func (b *Bus) Peek(ctx context.Context, in ab2bus.PeekInput) (ab2bus.PeekResult, error) {
	req := PeekRequest(in)
	r, err := b.c.PeekWithResponse(ctx, req.Session, &req.Params)
	if err != nil {
		return ab2bus.PeekResult{}, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil); err != nil {
		return ab2bus.PeekResult{}, err
	}
	if r.JSON200 == nil {
		return ab2bus.PeekResult{}, unparsable(r.StatusCode())
	}
	return FromGenPeek(*r.JSON200), nil
}
