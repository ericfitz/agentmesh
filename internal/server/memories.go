package server

import (
	"context"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

func (a *api) GetMemory(ctx context.Context, r gen.GetMemoryRequestObject) (gen.GetMemoryResponseObject, error) {
	m, err := a.memories.Get(ctx, IdentityFrom(ctx), r.Id)
	if err != nil {
		return nil, err
	}
	return gen.GetMemory200JSONResponse(toGenMessage(m)), nil
}

// EditMemory maps the request to memories.Service.Edit.
func (a *api) EditMemory(ctx context.Context, r gen.EditMemoryRequestObject) (gen.EditMemoryResponseObject, error) {
	in, err := editMemoryInput(r)
	if err != nil {
		return nil, err
	}
	res, err := a.memories.Edit(ctx, IdentityFrom(ctx), in)
	if err != nil {
		return nil, err
	}
	return gen.EditMemory201JSONResponse(editResultToGen(res)), nil
}

// editMemoryInput reads the request; the body is required. A nil pointer
// member keeps the live revision's value, an empty one clears it.
func editMemoryInput(r gen.EditMemoryRequestObject) (ab2bus.EditMemoryInput, error) {
	if r.Body == nil {
		return ab2bus.EditMemoryInput{}, ab2bus.Errorf(ab2bus.CodeValidation, false, "the request body is required")
	}
	b := r.Body
	in := ab2bus.EditMemoryInput{
		ID: r.Id, Subject: b.Subject, Content: b.Content, Type: b.Type, Metadata: b.Metadata,
		IdempotencyKey: idemKey(r.Params.IdempotencyKey),
	}
	if b.IfRevision != nil {
		in.IfRevision = *b.IfRevision
	}
	if b.Tags != nil {
		// A present empty list stays non-nil: it clears; absent keeps.
		in.Tags = append([]string{}, *b.Tags...)
	}
	return in, nil
}

// editResultToGen converts an edit receipt to its wire form.
func editResultToGen(r ab2bus.EditResult) gen.EditResult {
	return gen.EditResult{Seq: r.Seq, MemoryId: r.MemoryID, Revision: r.Revision, Replaced: r.Replaced}
}

func (a *api) ListMemoryRevisions(ctx context.Context, r gen.ListMemoryRevisionsRequestObject) (gen.ListMemoryRevisionsResponseObject, error) {
	ms, err := a.memories.Revisions(ctx, IdentityFrom(ctx), r.Id)
	if err != nil {
		return nil, err
	}
	out := make(gen.ListMemoryRevisions200JSONResponse, len(ms))
	for i, m := range ms {
		out[i] = toGenMessage(m)
	}
	return out, nil
}

func (a *api) DeleteMemory(ctx context.Context, r gen.DeleteMemoryRequestObject) (gen.DeleteMemoryResponseObject, error) {
	if err := a.memories.Delete(ctx, IdentityFrom(ctx), deleteMemoryInput(r)); err != nil {
		return nil, err
	}
	return gen.DeleteMemory204Response{}, nil
}

// deleteMemoryInput reads the path and the Idempotency-Key header.
func deleteMemoryInput(r gen.DeleteMemoryRequestObject) ab2bus.DeleteMemoryInput {
	return ab2bus.DeleteMemoryInput{ID: r.Id, IdempotencyKey: idemKey(r.Params.IdempotencyKey)}
}
