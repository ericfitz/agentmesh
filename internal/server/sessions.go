package server

import (
	"context"
	"math"
	"time"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// Sessions, receive, watch and identities (Decisions 15, 16, 40, 42, 45, 68,
// 83). Every failure is returned as nil, err; the strict server's response
// error hook writes the problem (choice 4). Watch passes ctx straight to the
// service: the strict wrapper gives it r.Context(), so a client that goes
// away releases the handler.

func (a *api) OpenSession(ctx context.Context, req gen.OpenSessionRequestObject) (gen.OpenSessionResponseObject, error) {
	s, err := a.sessions.Open(ctx, IdentityFrom(ctx), openSessionInput(req))
	if err != nil {
		return nil, err
	}
	return gen.OpenSession201JSONResponse(sessionToGen(s)), nil
}

// openSessionInput reads the optional body: no body is an empty input.
func openSessionInput(req gen.OpenSessionRequestObject) ab2bus.OpenSessionInput {
	var in ab2bus.OpenSessionInput
	if b := req.Body; b != nil {
		in.Hint = derefOr(b.Hint)
		in.ResumeToken = derefOr(b.ResumeToken)
		for _, c := range derefOr(b.Cursors) {
			in.Cursors = append(in.Cursors, ab2bus.OfferedCursor{Channel: c.Channel, Seq: c.Seq})
		}
	}
	return in
}

// sessionToGen is the wire form of a session; both arrays are [], never null.
func sessionToGen(s ab2bus.Session) gen.Session {
	out := gen.Session{
		DisplayName: s.DisplayName, Id: s.ID, Identity: s.Identity,
		ResumeToken: s.ResumeToken, Resumed: s.Resumed,
		Pending:         make([]gen.PendingChannel, 0, len(s.Pending)),
		RejectedCursors: make([]gen.RejectedCursor, 0, len(s.RejectedCursors)),
	}
	for _, p := range s.Pending {
		out.Pending = append(out.Pending, gen.PendingChannel{Channel: p.Channel, Pending: p.Pending})
	}
	for _, r := range s.RejectedCursors {
		out.RejectedCursors = append(out.RejectedCursors, gen.RejectedCursor{Channel: r.Channel, Reason: gen.RejectedCursorReason(r.Reason)})
	}
	return out
}

func (a *api) CloseSession(ctx context.Context, req gen.CloseSessionRequestObject) (gen.CloseSessionResponseObject, error) {
	if err := a.sessions.Close(ctx, IdentityFrom(ctx), closeSessionInput(req)); err != nil {
		return nil, err
	}
	return gen.CloseSession204Response{}, nil
}

func closeSessionInput(req gen.CloseSessionRequestObject) ab2bus.CloseSessionInput {
	return ab2bus.CloseSessionInput{Session: req.Session, IdempotencyKey: derefOr(req.Params.IdempotencyKey)}
}

func (a *api) Receive(ctx context.Context, req gen.ReceiveRequestObject) (gen.ReceiveResponseObject, error) {
	r, err := a.delivery.Receive(ctx, IdentityFrom(ctx), receiveInput(req))
	if err != nil {
		return nil, err
	}
	return gen.Receive200JSONResponse(receiveResultToGen(r)), nil
}

// receiveInput reads the optional body: no body is the defaults.
func receiveInput(req gen.ReceiveRequestObject) ab2bus.ReceiveInput {
	in := ab2bus.ReceiveInput{Session: req.Session}
	if b := req.Body; b != nil {
		in.Ack = derefOr(b.Ack)
		in.Count = derefOr(b.Count) // absent is 0; the core defaults it
		in.Channels = derefOr(b.Channels)
		in.IncludeOwn = derefOr(b.IncludeOwn)
	}
	return in
}

// receiveResultToGen is the wire form of a batch: gaps and messages are [],
// instruction and notice are absent when empty.
func receiveResultToGen(r ab2bus.ReceiveResult) gen.ReceiveResult {
	out := gen.ReceiveResult{
		AckIgnored: r.AckIgnored, Batch: r.Batch, Redelivered: r.Redelivered,
		Instruction: optStr(r.Instruction), Notice: optStr(r.Notice),
		Gaps:     make([]gen.Gap, 0, len(r.Gaps)),
		Messages: make([]gen.Message, 0, len(r.Messages)),
	}
	for _, g := range r.Gaps {
		out.Gaps = append(out.Gaps, gen.Gap{Channel: g.Channel, From: g.From, To: g.To})
	}
	for _, m := range r.Messages {
		out.Messages = append(out.Messages, toGenMessage(m))
	}
	return out
}

func (a *api) Watch(ctx context.Context, req gen.WatchRequestObject) (gen.WatchResponseObject, error) {
	in, err := watchInput(req)
	if err != nil {
		return nil, err
	}
	r, err := a.delivery.Watch(ctx, IdentityFrom(ctx), in)
	if err != nil {
		return nil, err // replaced is a *bus.Error: the hook writes the 409
	}
	if !r.Woke {
		return gen.Watch204Response{}, nil
	}
	return gen.Watch200JSONResponse(wakeToGen(r)), nil
}

// watchInput validates the timeout (watchTimeout) and builds the input.
func watchInput(req gen.WatchRequestObject) (ab2bus.WatchInput, error) {
	in := ab2bus.WatchInput{
		Session:    req.Session,
		After:      derefOr(req.Params.After),
		IncludeOwn: derefOr(req.Params.IncludeOwn),
	}
	if t := req.Params.Timeout; t != nil {
		d, err := watchTimeout(float64(*t))
		if err != nil {
			return ab2bus.WatchInput{}, err
		}
		in.Timeout = d
	}
	return in, nil
}

// wakeToGen is the wire form of a wake; channels is [], never null.
func wakeToGen(r ab2bus.WatchResult) gen.Wake {
	chans := r.Channels
	if chans == nil {
		chans = []string{}
	}
	return gen.Wake{Seq: r.Seq, Count: r.Count, Channels: chans}
}

func (a *api) ListIdentities(ctx context.Context, _ gen.ListIdentitiesRequestObject) (gen.ListIdentitiesResponseObject, error) {
	ids, err := a.sessions.Identities(ctx, IdentityFrom(ctx))
	if err != nil {
		return nil, err
	}
	out := make(gen.ListIdentities200JSONResponse, 0, len(ids))
	for _, i := range ids {
		out = append(out, identityToGen(i))
	}
	return out, nil
}

// identityToGen is the wire form of an identity; sessions is [], status is
// absent when the identity has none.
func identityToGen(i ab2bus.IdentityInfo) gen.Identity {
	g := gen.Identity{Name: i.Name, Kind: gen.IdentityKind(i.Kind), Admin: i.Admin, Sessions: make([]gen.SessionInfo, 0, len(i.Sessions))}
	for _, s := range i.Sessions {
		g.Sessions = append(g.Sessions, gen.SessionInfo{Id: s.ID, Identity: s.Identity, DisplayName: s.DisplayName, OpenedAt: s.OpenedAt})
	}
	if i.Status != nil {
		st := agentStatusToGen(*i.Status)
		g.Status = &st
	}
	return g
}

// watchTimeout converts the wire's fractional seconds to a Duration without
// leaving the range a float to int64 conversion defines: that conversion is
// implementation-defined out of range (arm64 saturates, amd64 gives
// math.MinInt64), so the same request would be a clamp on one platform and a
// "negative" validation on the other. NaN and the infinities are validation;
// anything a Duration cannot hold saturates at its end, where the core
// rejects the top as above its ceiling and the bottom as negative.
func watchTimeout(seconds float64) (time.Duration, error) {
	if math.IsNaN(seconds) || math.IsInf(seconds, 0) {
		return 0, ab2bus.Errorf(ab2bus.CodeValidation, false, "timeout must be a finite number of seconds")
	}
	ns := seconds * float64(time.Second)
	switch {
	case ns >= float64(math.MaxInt64):
		return time.Duration(math.MaxInt64), nil
	case ns <= float64(math.MinInt64):
		return time.Duration(math.MinInt64), nil
	}
	return time.Duration(ns), nil
}
