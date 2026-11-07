package remote

import (
	"context"
	"net/http"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// FromGenTaskResult converts a wire task update result to the domain type.
func FromGenTaskResult(r gen.TaskUpdateResult) ab2bus.TaskUpdateResult {
	return ab2bus.TaskUpdateResult{Task: FromGenTask(r.Task), Replaced: r.Replaced, Deleted: deref(r.Deleted)}
}

// Create sends the new task; zero members are absent.
func (b *Bus) Create(ctx context.Context, in ab2bus.TaskCreateInput) (ab2bus.Task, error) {
	req := CreateTaskRequest(in)
	r, err := b.c.CreateTaskWithResponse(ctx, req.Channel, &req.Params, *req.Body)
	if err := mtCheck(ctx, r, err, func(r *gen.CreateTaskResponse) *http.Response { return r.HTTPResponse }, func(r *gen.CreateTaskResponse) bool { return r.JSON201 != nil }); err != nil {
		return ab2bus.Task{}, err
	}
	return FromGenTask(*r.JSON201), nil
}

// CreateTaskRequest builds the request for Create; Body is always set.
func CreateTaskRequest(in ab2bus.TaskCreateInput) gen.CreateTaskRequestObject {
	return gen.CreateTaskRequestObject{
		Channel: in.Channel,
		Params:  gen.CreateTaskParams{IdempotencyKey: key(in.IdempotencyKey)},
		Body: &gen.TaskCreateRequest{
			Subject: in.Subject, Description: strPtr(in.Description), Parent: int64Ptr(in.Parent),
			Before: int64Ptr(in.Before), After: int64Ptr(in.After),
			BlockedBy: slicePtr(in.BlockedBy), Metadata: mapPtr(in.Metadata),
		},
	}
}

// GetTask reads one task.
func (b *Bus) GetTask(ctx context.Context, id int64) (ab2bus.Task, error) {
	r, err := b.c.GetTaskWithResponse(ctx, id)
	if err := mtCheck(ctx, r, err, func(r *gen.GetTaskResponse) *http.Response { return r.HTTPResponse }, func(r *gen.GetTaskResponse) bool { return r.JSON200 != nil }); err != nil {
		return ab2bus.Task{}, err
	}
	return FromGenTask(*r.JSON200), nil
}

// List lists a channel's tasks; an empty filter is absent.
func (b *Bus) List(ctx context.Context, in ab2bus.TaskListInput) ([]ab2bus.TaskSummary, error) {
	req := ListTasksRequest(in)
	r, err := b.c.ListTasksWithResponse(ctx, req.Channel, &req.Params)
	if err := mtCheck(ctx, r, err, func(r *gen.ListTasksResponse) *http.Response { return r.HTTPResponse }, func(r *gen.ListTasksResponse) bool { return r.JSON200 != nil }); err != nil {
		return nil, err
	}
	out := make([]ab2bus.TaskSummary, len(*r.JSON200))
	for i, s := range *r.JSON200 {
		out[i] = FromGenTaskSummary(s)
	}
	return out, nil
}

// ListTasksRequest builds the request for List; an empty status or owner is absent.
func ListTasksRequest(in ab2bus.TaskListInput) gen.ListTasksRequestObject {
	return gen.ListTasksRequestObject{
		Channel: in.Channel,
		Params:  gen.ListTasksParams{Status: strPtr(in.Status), Owner: strPtr(in.Owner)},
	}
}

// Update sends the patch; a nil pointer member leaves the field unchanged.
func (b *Bus) Update(ctx context.Context, p ab2bus.TaskPatch) (ab2bus.TaskUpdateResult, error) {
	req := UpdateTaskRequest(p)
	r, err := b.c.UpdateTaskWithResponse(ctx, req.Id, &req.Params, *req.Body)
	if err := mtCheck(ctx, r, err, func(r *gen.UpdateTaskResponse) *http.Response { return r.HTTPResponse }, func(r *gen.UpdateTaskResponse) bool { return r.JSON200 != nil }); err != nil {
		return ab2bus.TaskUpdateResult{}, err
	}
	return FromGenTaskResult(*r.JSON200), nil
}

// UpdateTaskRequest builds the request for Update; Body is always set and
// Delete is present only when true.
func UpdateTaskRequest(p ab2bus.TaskPatch) gen.UpdateTaskRequestObject {
	body := gen.TaskPatch{
		Status: p.Status, Owner: p.Owner, Subject: p.Subject, Description: p.Description,
		Parent: p.Parent, Before: int64Ptr(p.Before), After: int64Ptr(p.After),
		AddBlockedBy: slicePtr(p.AddBlockedBy), RemoveBlockedBy: slicePtr(p.RemoveBlockedBy),
		LeasedUntil: p.LeasedUntil, Metadata: mapPtr(p.Metadata),
	}
	if p.Delete {
		body.Delete = ptr(true)
	}
	return gen.UpdateTaskRequestObject{
		Id:     p.ID,
		Params: gen.UpdateTaskParams{IdempotencyKey: key(p.IdempotencyKey)},
		Body:   &body,
	}
}

// Claim claims the task, with an optional lease.
func (b *Bus) Claim(ctx context.Context, in ab2bus.TaskClaimInput) (ab2bus.TaskUpdateResult, error) {
	req := ClaimTaskRequest(in)
	r, err := b.c.ClaimTaskWithResponse(ctx, req.Id, &req.Params, *req.Body)
	if err := mtCheck(ctx, r, err, func(r *gen.ClaimTaskResponse) *http.Response { return r.HTTPResponse }, func(r *gen.ClaimTaskResponse) bool { return r.JSON200 != nil }); err != nil {
		return ab2bus.TaskUpdateResult{}, err
	}
	return FromGenTaskResult(*r.JSON200), nil
}

// ClaimTaskRequest builds the request for Claim; Body is always set and a
// zero lease is absent.
func ClaimTaskRequest(in ab2bus.TaskClaimInput) gen.ClaimTaskRequestObject {
	return gen.ClaimTaskRequestObject{
		Id:     in.ID,
		Params: gen.ClaimTaskParams{IdempotencyKey: key(in.IdempotencyKey)},
		Body:   &gen.ClaimTaskRequest{LeasedUntil: int64Ptr(in.LeasedUntil)},
	}
}

// Release releases a task: it clears the owner and lease and returns it to pending.
func (b *Bus) Release(ctx context.Context, in ab2bus.TaskReleaseInput) (ab2bus.TaskUpdateResult, error) {
	req := ReleaseTaskRequest(in)
	r, err := b.c.ReleaseTaskWithResponse(ctx, req.Id, &req.Params)
	if err := mtCheck(ctx, r, err, func(r *gen.ReleaseTaskResponse) *http.Response { return r.HTTPResponse }, func(r *gen.ReleaseTaskResponse) bool { return r.JSON200 != nil }); err != nil {
		return ab2bus.TaskUpdateResult{}, err
	}
	return FromGenTaskResult(*r.JSON200), nil
}

// ReleaseTaskRequest builds the request for Release.
func ReleaseTaskRequest(in ab2bus.TaskReleaseInput) gen.ReleaseTaskRequestObject {
	return gen.ReleaseTaskRequestObject{Id: in.ID, Params: gen.ReleaseTaskParams{IdempotencyKey: key(in.IdempotencyKey)}}
}
