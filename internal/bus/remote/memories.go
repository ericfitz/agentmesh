package remote

import (
	"context"
	"net/http"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// mtResponse is the part of every generated response the error mapping reads.
type mtResponse interface {
	StatusCode() int
	GetBody() []byte
}

// mtCheck maps a generated response (or the transport error) to nil or a Bus
// error. httpResp reads the response's HTTPResponse (run only when err is nil).
// ok is whether the typed success member for the expected status is
// set; a 2xx without it is an unparsable success and reported as internal.
func mtCheck[R mtResponse](ctx context.Context, r R, err error, httpResp func(R) *http.Response, ok func(R) bool) error {
	if err != nil {
		return errorOf(ctx, 0, nil, nil, err)
	}
	if e := errorOf(ctx, r.StatusCode(), headerOf(httpResp(r)), r.GetBody(), nil); e != nil {
		return e
	}
	if !ok(r) {
		return unparsable(r.StatusCode())
	}
	return nil
}

func (b *Bus) GetMemory(ctx context.Context, id int64) (ab2bus.Message, error) {
	r, err := b.c.GetMemoryWithResponse(ctx, id)
	if err := mtCheck(ctx, r, err, func(r *gen.GetMemoryResponse) *http.Response { return r.HTTPResponse }, func(r *gen.GetMemoryResponse) bool { return r.JSON200 != nil }); err != nil {
		return ab2bus.Message{}, err
	}
	return FromGenMessage(*r.JSON200)
}

// Edit sends the edit; a nil pointer member stays absent, an empty one clears.
func (b *Bus) Edit(ctx context.Context, in ab2bus.EditMemoryInput) (ab2bus.EditResult, error) {
	req := EditMemoryRequest(in)
	r, err := b.c.EditMemoryWithResponse(ctx, req.Id, &req.Params, *req.Body)
	if err := mtCheck(ctx, r, err, func(r *gen.EditMemoryResponse) *http.Response { return r.HTTPResponse }, func(r *gen.EditMemoryResponse) bool { return r.JSON201 != nil }); err != nil {
		return ab2bus.EditResult{}, err
	}
	return FromGenEditResult(*r.JSON201), nil
}

// EditMemoryRequest builds the request for Edit; Body is always set. A nil
// Tags stays absent and an empty one is sent (it clears); IfRevision 0 is absent.
func EditMemoryRequest(in ab2bus.EditMemoryInput) gen.EditMemoryRequestObject {
	return gen.EditMemoryRequestObject{
		Id:     in.ID,
		Params: gen.EditMemoryParams{IdempotencyKey: key(in.IdempotencyKey)},
		Body: &gen.EditMemoryRequest{
			Content: in.Content, Subject: in.Subject, Type: in.Type,
			Metadata: in.Metadata, Tags: slicePtr(in.Tags), IfRevision: int64Ptr(in.IfRevision),
		},
	}
}

// FromGenEditResult converts a wire edit receipt to the domain type.
func FromGenEditResult(e gen.EditResult) ab2bus.EditResult {
	return ab2bus.EditResult{Seq: e.Seq, MemoryID: e.MemoryId, Revision: e.Revision, Replaced: e.Replaced}
}

// Delete tombstones the memory.
func (b *Bus) Delete(ctx context.Context, in ab2bus.DeleteMemoryInput) error {
	req := DeleteMemoryRequest(in)
	r, err := b.c.DeleteMemoryWithResponse(ctx, req.Id, &req.Params)
	return mtCheck(ctx, r, err, func(r *gen.DeleteMemoryResponse) *http.Response { return r.HTTPResponse }, func(*gen.DeleteMemoryResponse) bool { return true })
}

// DeleteMemoryRequest builds the request for Delete.
func DeleteMemoryRequest(in ab2bus.DeleteMemoryInput) gen.DeleteMemoryRequestObject {
	return gen.DeleteMemoryRequestObject{Id: in.ID, Params: gen.DeleteMemoryParams{IdempotencyKey: key(in.IdempotencyKey)}}
}

func (b *Bus) Revisions(ctx context.Context, id int64) ([]ab2bus.Message, error) {
	r, err := b.c.ListMemoryRevisionsWithResponse(ctx, id)
	if err := mtCheck(ctx, r, err, func(r *gen.ListMemoryRevisionsResponse) *http.Response { return r.HTTPResponse }, func(r *gen.ListMemoryRevisionsResponse) bool { return r.JSON200 != nil }); err != nil {
		return nil, err
	}
	out := make([]ab2bus.Message, len(*r.JSON200))
	for i, m := range *r.JSON200 {
		if out[i], err = FromGenMessage(m); err != nil {
			return nil, err
		}
	}
	return out, nil
}
