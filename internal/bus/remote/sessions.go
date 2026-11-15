package remote

import (
	"context"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// Sessions, receive, watch and identities. Session ids go to the generated
// client as given (choice 17, Decision 80): the rules stay in the core, so an
// odd session id is judged by the server, never refused here; the one
// exception is Close's empty id (below).

// OpenSessionRequest builds the request for Open; Body is always set.
func OpenSessionRequest(in ab2bus.OpenSessionInput) gen.OpenSessionRequestObject {
	body := gen.OpenSessionJSONRequestBody{Hint: strPtr(in.Hint), ResumeToken: strPtr(in.ResumeToken), TrustNumber: in.TrustNumber}
	if len(in.Cursors) > 0 {
		cs := make([]gen.OfferedCursor, len(in.Cursors))
		for i, c := range in.Cursors {
			cs[i] = gen.OfferedCursor{Channel: c.Channel, Seq: c.Seq}
		}
		body.Cursors = &cs
	}
	return gen.OpenSessionRequestObject{Body: &body}
}

// FromGenSession converts a wire session to the domain type.
func FromGenSession(s gen.Session) ab2bus.Session {
	out := ab2bus.Session{
		ID: s.Id, Identity: s.Identity, DisplayName: s.DisplayName,
		ResumeToken: s.ResumeToken, Resumed: s.Resumed,
		TrustNumber: s.TrustNumber, Trust: fromGenTrust(s.Trust),
	}
	for _, c := range s.RejectedCursors {
		out.RejectedCursors = append(out.RejectedCursors, ab2bus.RejectedCursor{Channel: c.Channel, Reason: string(c.Reason)})
	}
	for _, p := range s.Pending {
		out.Pending = append(out.Pending, ab2bus.PendingChannel{Channel: p.Channel, Pending: p.Pending})
	}
	return out
}

func (b *Bus) Open(ctx context.Context, in ab2bus.OpenSessionInput) (ab2bus.Session, error) {
	r, err := b.c.OpenSessionWithResponse(ctx, *OpenSessionRequest(in).Body)
	if err != nil {
		return ab2bus.Session{}, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil); err != nil {
		return ab2bus.Session{}, err
	}
	if r.JSON201 == nil {
		return ab2bus.Session{}, unparsable(r.StatusCode())
	}
	return FromGenSession(*r.JSON201), nil
}

// Close judges the empty session id itself: core Close answers validation for
// it, while the wire's empty path segment is the router's 404 not_found, so the
// request is not sent (the plan's empty-name contingency, a Decision 80
// departure limited to the empty id; same as Send's empty channel).
// Decision (Eric, 2026-10-21): Milestone 4 item 6 (option A: keep the guard).
func (b *Bus) Close(ctx context.Context, in ab2bus.CloseSessionInput) error {
	if in.Session == "" {
		return ab2bus.Errorf(ab2bus.CodeValidation, false, "session is required")
	}
	req := CloseSessionRequest(in)
	r, err := b.c.CloseSessionWithResponse(ctx, req.Session, &req.Params)
	if err != nil {
		return errorOf(ctx, 0, nil, nil, err)
	}
	return errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil)
}

// CloseSessionRequest builds the request for Close.
func CloseSessionRequest(in ab2bus.CloseSessionInput) gen.CloseSessionRequestObject {
	return gen.CloseSessionRequestObject{Session: in.Session, Params: gen.CloseSessionParams{IdempotencyKey: key(in.IdempotencyKey)}}
}

// ReceiveRequest builds the request for Receive; Body is always set, and its
// optional members are absent for their zero values.
func ReceiveRequest(in ab2bus.ReceiveInput) gen.ReceiveRequestObject {
	body := gen.ReceiveJSONRequestBody{Ack: strPtr(in.Ack), Channels: slicePtr(in.Channels), TrustNumber: in.TrustNumber}
	if in.Count != 0 {
		body.Count = &in.Count
	}
	if in.IncludeOwn {
		body.IncludeOwn = ptr(true)
	}
	return gen.ReceiveRequestObject{Session: in.Session, Body: &body}
}

// FromGenReceiveResult converts a wire batch; a message with an unknown
// sender kind is an internal error.
func FromGenReceiveResult(w gen.ReceiveResult) (ab2bus.ReceiveResult, error) {
	out := ab2bus.ReceiveResult{
		Batch: w.Batch, Redelivered: w.Redelivered, AckIgnored: w.AckIgnored,
		Notice: deref(w.Notice), Instruction: deref(w.Instruction),
		TrustNumber: w.TrustNumber, Trust: fromGenTrust(w.Trust),
	}
	for _, m := range w.Messages {
		msg, err := FromGenMessage(m)
		if err != nil {
			return ab2bus.ReceiveResult{}, err
		}
		out.Messages = append(out.Messages, msg)
	}
	for _, g := range w.Gaps {
		out.Gaps = append(out.Gaps, ab2bus.Gap{Channel: g.Channel, From: g.From, To: g.To})
	}
	return out, nil
}

func (b *Bus) Receive(ctx context.Context, in ab2bus.ReceiveInput) (ab2bus.ReceiveResult, error) {
	req := ReceiveRequest(in)
	r, err := b.c.ReceiveWithResponse(ctx, req.Session, *req.Body)
	if err != nil {
		return ab2bus.ReceiveResult{}, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil); err != nil {
		return ab2bus.ReceiveResult{}, err
	}
	if r.JSON200 == nil {
		return ab2bus.ReceiveResult{}, unparsable(r.StatusCode())
	}
	return FromGenReceiveResult(*r.JSON200)
}

// WatchRequest builds the request for Watch; each parameter is absent for its
// zero value.
func WatchRequest(in ab2bus.WatchInput) gen.WatchRequestObject {
	params := gen.WatchParams{After: int64Ptr(in.After), Timeout: seconds(in.Timeout), TrustNumber: in.TrustNumber}
	if in.IncludeOwn {
		params.IncludeOwn = ptr(true)
	}
	return gen.WatchRequestObject{Session: in.Session, Params: params}
}

// FromGenWake converts a wake; a 200 is a wake, so Woke is true.
func FromGenWake(w gen.Wake) ab2bus.WatchResult {
	return ab2bus.WatchResult{Woke: true, Seq: w.Seq, Count: w.Count, Channels: w.Channels, TrustNumber: w.TrustNumber}
}

func (b *Bus) Watch(ctx context.Context, in ab2bus.WatchInput) (ab2bus.WatchResult, error) {
	req := WatchRequest(in)
	r, err := b.c.WatchWithResponse(ctx, req.Session, &req.Params)
	if err != nil {
		return ab2bus.WatchResult{}, errorOf(ctx, 0, nil, nil, err)
	}
	if r.StatusCode() == 204 {
		return ab2bus.WatchResult{Woke: false}, nil
	}
	if err := errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil); err != nil {
		return ab2bus.WatchResult{}, err
	}
	if r.JSON200 == nil {
		return ab2bus.WatchResult{}, unparsable(r.StatusCode())
	}
	return FromGenWake(*r.JSON200), nil
}

func (b *Bus) Identities(ctx context.Context) ([]ab2bus.IdentityInfo, error) {
	r, err := b.c.ListIdentitiesWithResponse(ctx)
	if err != nil {
		return nil, errorOf(ctx, 0, nil, nil, err)
	}
	if err := errorOf(ctx, r.StatusCode(), headerOf(r.HTTPResponse), r.Body, nil); err != nil {
		return nil, err
	}
	if r.JSON200 == nil {
		return nil, unparsable(r.StatusCode())
	}
	out := make([]ab2bus.IdentityInfo, 0, len(*r.JSON200))
	for _, i := range *r.JSON200 {
		info, err := FromGenIdentity(i)
		if err != nil {
			return nil, err
		}
		out = append(out, info)
	}
	return out, nil
}

// FromGenIdentity converts a wire identity; an unknown kind is an internal
// error.
func FromGenIdentity(i gen.Identity) (ab2bus.IdentityInfo, error) {
	kind, err := fromGenIdentityKind("kind", string(i.Kind))
	if err != nil {
		return ab2bus.IdentityInfo{}, err
	}
	info := ab2bus.IdentityInfo{Name: i.Name, Kind: kind, Admin: i.Admin}
	if i.Status != nil {
		st := FromGenAgentStatus(*i.Status)
		info.Status = &st
	}
	for _, s := range i.Sessions {
		info.Sessions = append(info.Sessions, ab2bus.SessionInfo{ID: s.Id, Identity: s.Identity, DisplayName: s.DisplayName, OpenedAt: s.OpenedAt})
	}
	return info, nil
}
