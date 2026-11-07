package server

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/bus/remote"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// TestRequestConvertersNilBody pins what the round-trip filler cannot see: an
// optional body that is absent, and zero inputs that must stay absent or
// false on the wire, never null or flipped.
func TestRequestConvertersNilBody(t *testing.T) {
	if got := receiveInput(gen.ReceiveRequestObject{Session: "s"}); got.Session != "s" || got.Ack != "" || got.Count != 0 || got.Channels != nil || got.IncludeOwn {
		t.Fatalf("receiveInput nil body = %+v", got)
	}
	if got := openSessionInput(gen.OpenSessionRequestObject{}); len(got.Cursors) != 0 || got.Hint != "" || got.ResumeToken != "" {
		t.Fatalf("openSessionInput nil body = %+v", got)
	}
	if got := setAgentStatusInput(gen.SetAgentStatusRequestObject{Session: "s"}); got.Session != "s" || got.Tag != "" || got.Text != "" || got.Problem != "" {
		t.Fatalf("setAgentStatusInput nil body = %+v", got)
	}
	g := sessionToGen(bus.Session{})
	if g.Pending == nil || g.RejectedCursors == nil {
		t.Fatal("sessionToGen: required arrays must be [] not null")
	}
	if g.Resumed {
		t.Fatal("sessionToGen: zero Resumed must stay false")
	}
	if raw := mustMarshal(t, g); !strings.Contains(raw, `"resumed":false`) || !strings.Contains(raw, `"pending":[]`) || !strings.Contains(raw, `"rejected_cursors":[]`) {
		t.Fatalf("sessionToGen zero wire form = %s", raw)
	}
	r := receiveResultToGen(bus.ReceiveResult{})
	if r.Messages == nil || r.Gaps == nil || r.Notice != nil || r.Instruction != nil {
		t.Fatalf("receiveResultToGen zero = %+v", r)
	}
	if w := wakeToGen(bus.WatchResult{Woke: true}); w.Channels == nil {
		t.Fatal("wakeToGen: channels must be [] not null")
	}
	if p := peekToGen(bus.PeekResult{}); p.Channels == nil {
		t.Fatal("peekToGen: channels must be [] not null")
	}
	if i := identityToGen(bus.IdentityInfo{}); i.Sessions == nil || i.Status != nil {
		t.Fatalf("identityToGen zero = %+v", i)
	}
	if raw := mustMarshal(t, agentStatusToGen(bus.AgentStatus{})); strings.Contains(raw, "problem") || strings.Contains(raw, "last_tag") {
		t.Fatalf("agentStatusToGen zero must omit problem and last_tag: %s", raw)
	}
	if got := createChannelInput(gen.CreateChannelRequestObject{}); got.Name != "" || got.ACL != nil || got.Scope != "" || got.Kind != "" {
		t.Fatalf("createChannelInput nil body = %+v", got)
	}
	if got := renameChannelInput(gen.RenameChannelRequestObject{Channel: "c"}); got.Name != "c" || got.NewName != "" {
		t.Fatalf("renameChannelInput nil body = %+v", got)
	}
	if got := setACLInput(gen.SetACLRequestObject{Channel: "c"}); got.Channel != "c" || got.Entries != nil {
		t.Fatalf("setACLInput nil body = %+v", got)
	}
	if got := subscribeInput(gen.SubscribeRequestObject{Channel: "c"}); got.Channel != "c" || got.From != "" {
		t.Fatalf("subscribeInput nil body = %+v", got)
	}
	if got := subscribeTagsInput(gen.SubscribeTagsRequestObject{}); got.Patterns != nil {
		t.Fatalf("subscribeTagsInput nil body = %+v", got)
	}
	if _, err := sendInput(gen.SendMessageRequestObject{Channel: "c"}); err == nil {
		t.Fatal("sendInput nil body must be a validation error")
	}
	if got := historyInput(gen.HistoryRequestObject{Channel: "c"}); got.Channel != "c" || got.Count != 0 || got.Tags != nil {
		t.Fatalf("historyInput zero params = %+v", got)
	}
	if got := searchInput(gen.SearchRequestObject{}); got.Query != "" || got.Mode != "" || got.Count != 0 || got.Tags != nil {
		t.Fatalf("searchInput zero params = %+v", got)
	}
	if raw := mustMarshal(t, searchResultToGen(bus.SearchResult{})); raw != `{"hits":[]}` {
		t.Fatalf("searchResultToGen zero must omit next and semantic_unavailable: %s", raw)
	}
	if raw := mustMarshal(t, sendResultToGen(bus.SendResult{Seq: 1})); raw != `{"seq":1}` {
		t.Fatalf("sendResultToGen zero must omit memory_id: %s", raw)
	}
	if c := channelToGen(bus.Channel{}); c.Capabilities == nil {
		t.Fatal("channelToGen: capabilities must be [] not null")
	}
	for name, err := range map[string]error{
		"createTaskInput": func() error { _, e := createTaskInput(gen.CreateTaskRequestObject{Channel: "c"}); return e }(),
		"updateTaskInput": func() error { _, e := updateTaskInput(gen.UpdateTaskRequestObject{Id: 1}); return e }(),
		"editMemoryInput": func() error { _, e := editMemoryInput(gen.EditMemoryRequestObject{Id: 1}); return e }(),
	} {
		var be *bus.Error
		if !errors.As(err, &be) || be.Code != bus.CodeValidation || be.Message != "the request body is required" {
			t.Fatalf("%s nil body = %v, want a validation error", name, err)
		}
	}
	em, err := editMemoryInput(gen.EditMemoryRequestObject{Id: 1, Body: &gen.EditMemoryRequest{}})
	if err != nil || em.Subject != nil || em.Content != nil || em.Type != nil || em.Metadata != nil || em.Tags != nil || em.IfRevision != 0 {
		t.Fatalf("editMemoryInput empty body = %+v, %v", em, err)
	}
	if got := claimTaskInput(gen.ClaimTaskRequestObject{Id: 3}); got.ID != 3 || got.LeasedUntil != 0 {
		t.Fatalf("claimTaskInput nil body = %+v", got)
	}
	if got := listTasksInput(gen.ListTasksRequestObject{Channel: "c"}); got.Channel != "c" || got.Status != "" || got.Owner != "" {
		t.Fatalf("listTasksInput zero params = %+v", got)
	}
	// Zero values stay absent or false on the wire, never null or flipped.
	if raw := mustMarshal(t, taskSummaryToGen(bus.TaskSummary{})); strings.Contains(raw, "has_details") {
		t.Fatalf("taskSummaryToGen zero must omit has_details: %s", raw)
	}
	if g := taskSummaryToGen(bus.TaskSummary{HasDetails: true}); g.HasDetails == nil || !*g.HasDetails {
		t.Fatalf("taskSummaryToGen HasDetails true = %+v", g.HasDetails)
	}
	if raw := mustMarshal(t, taskResultToGen(bus.TaskUpdateResult{})); strings.Contains(raw, `"deleted"`) || !strings.Contains(raw, `"replaced":0`) {
		t.Fatalf("taskResultToGen zero must omit deleted and keep replaced: %s", raw)
	}
	// Replaced and Deleted must not be swapped (the filler sets every bool true).
	if g := taskResultToGen(bus.TaskUpdateResult{Replaced: 7, Deleted: false}); g.Replaced != 7 || g.Deleted != nil {
		t.Fatalf("taskResultToGen replaced-only = %+v", g)
	}
	if g := taskResultToGen(bus.TaskUpdateResult{Replaced: 0, Deleted: true}); g.Replaced != 0 || g.Deleted == nil || !*g.Deleted {
		t.Fatalf("taskResultToGen deleted-only = %+v", g)
	}
	if b := remote.FromGenTaskResult(gen.TaskUpdateResult{Replaced: 7}); b.Replaced != 7 || b.Deleted {
		t.Fatalf("FromGenTaskResult replaced-only = %+v", b)
	}
	d := true
	if b := remote.FromGenTaskResult(gen.TaskUpdateResult{Deleted: &d}); b.Replaced != 0 || !b.Deleted {
		t.Fatalf("FromGenTaskResult deleted-only = %+v", b)
	}
	if raw := mustMarshal(t, remote.UpdateTaskRequest(bus.TaskPatch{ID: 1}).Body); raw != `{}` {
		t.Fatalf("UpdateTaskRequest zero patch must be {}: %s", raw)
	}
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
