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
	// Redelivered and AckIgnored are the one struct with two bools on the wire
	// (the filler sets every bool true, so a swap would go unseen).
	if g := receiveResultToGen(bus.ReceiveResult{Redelivered: true, AckIgnored: false}); !g.Redelivered || g.AckIgnored {
		t.Fatalf("receiveResultToGen redelivered-only = %+v", g)
	}
	if g := receiveResultToGen(bus.ReceiveResult{Redelivered: false, AckIgnored: true}); g.Redelivered || !g.AckIgnored {
		t.Fatalf("receiveResultToGen ack-ignored-only = %+v", g)
	}
	if b, err := remote.FromGenReceiveResult(gen.ReceiveResult{Redelivered: true, AckIgnored: false}); err != nil || !b.Redelivered || b.AckIgnored {
		t.Fatalf("FromGenReceiveResult redelivered-only = %+v, %v", b, err)
	}
	if b, err := remote.FromGenReceiveResult(gen.ReceiveResult{Redelivered: false, AckIgnored: true}); err != nil || b.Redelivered || !b.AckIgnored {
		t.Fatalf("FromGenReceiveResult ack-ignored-only = %+v, %v", b, err)
	}
	if raw := mustMarshal(t, remote.UpdateTaskRequest(bus.TaskPatch{ID: 1}).Body); raw != `{}` {
		t.Fatalf("UpdateTaskRequest zero patch must be {}: %s", raw)
	}
	// Zero inputs and the lists that must stay [] not null.
	if got := adminResetInput(gen.AdminResetRequestObject{}); got.Scope != bus.ResetData || got.IdempotencyKey != "" {
		t.Fatalf("adminResetInput zero params must default to data: %+v", got)
	}
	if p := remote.AdminResetRequest(bus.ResetInput{}).Params; p.Scope != nil || p.IdempotencyKey != nil {
		t.Fatalf("AdminResetRequest zero input must omit scope and key: %+v", p)
	}
	if got := rotateSigningKeyInput(gen.RotateSigningKeyRequestObject{}); got.IdempotencyKey != "" {
		t.Fatalf("rotateSigningKeyInput zero params = %+v", got)
	}
	if p := remote.RotateSigningKeyRequest(bus.RotateSigningKeyInput{}).Params; p.IdempotencyKey != nil {
		t.Fatalf("RotateSigningKeyRequest zero input must omit the key: %+v", p)
	}
	if got := createAgentIdentityInput(gen.CreateAgentIdentityRequestObject{Body: &gen.CreateAgentIdentityJSONRequestBody{Name: "n"}}); got.Name != "n" || got.Scope != "" {
		t.Fatalf("createAgentIdentityInput absent scope = %+v", got)
	}
	if raw := mustMarshal(t, agentIdentityToGen(bus.AgentIdentity{Identity: "i"})); strings.Contains(raw, `"scope"`) {
		t.Fatalf("agentIdentityToGen empty scope must be absent: %s", raw)
	}
	if got := createBridgeInput(gen.CreateBridgeRequestObject{Body: &gen.CreateBridgeJSONRequestBody{Channel: "c"}}); got.Channel != "c" || got.SlackName != "" {
		t.Fatalf("createBridgeInput absent slack_name = %+v", got)
	}
	if raw := mustMarshal(t, remote.CreateBridgeRequest(bus.CreateBridgeInput{Channel: "c"}).Body); raw != `{"channel":"c"}` {
		t.Fatalf("CreateBridgeRequest empty slack_name must be absent: %s", raw)
	}
	if raw := mustMarshal(t, bridgeCreatedToGen(bus.BridgeCreated{})); !strings.Contains(raw, `"not_invited":[]`) {
		t.Fatalf("bridgeCreatedToGen not_invited must be [] not null: %s", raw)
	}
	if raw := mustMarshal(t, scopeListToGen(nil)); raw != `{"scopes":[]}` {
		t.Fatalf("scopeListToGen zero = %s", raw)
	}
	if raw := mustMarshal(t, bridgeListToGen(nil)); raw != `{"bridges":[]}` {
		t.Fatalf("bridgeListToGen zero = %s", raw)
	}
	if raw := mustMarshal(t, signingKeyListToGen(bus.SigningKeyList{})); raw != `{"keys":[],"trust_number":0}` {
		t.Fatalf("signingKeyListToGen zero = %s", raw)
	}
	st := statusToGen(bus.Status{})
	if st.Sessions == nil || st.Channels == nil || st.Notices == nil || st.EmbeddingRejectedLast != nil || st.EmbeddingError != nil || st.EmbeddingErrorAt != nil {
		t.Fatalf("statusToGen zero = %+v", st)
	}
	if rot := signingKeyRotationToGen(bus.SigningKeyRotation{}); rot.Revoked == nil || len(rot.Revoked) != 0 {
		t.Fatalf("signingKeyRotationToGen zero must keep revoked as []: %+v", rot)
	}
	if rot := signingKeyRotationToGen(bus.SigningKeyRotation{Revoked: []bus.RevokedLeaf{{Thumbprint: "T"}}}); len(rot.Revoked) != 1 || rot.Revoked[0].Thumbprint != "T" {
		t.Fatalf("signingKeyRotationToGen one revoked = %+v", rot)
	}
	if rot, err := remote.FromGenSigningKeyRotation(gen.SigningKeyRotation{Current: gen.SigningKey{State: "current"}}); err != nil || rot.Revoked == nil || len(rot.Revoked) != 0 {
		t.Fatalf("FromGenSigningKeyRotation absent revoked must be []: %+v, %v", rot, err)
	}
	if got := remote.FromGenStatus(gen.Status{}); got.Sessions == nil || got.Channels == nil || got.Notices == nil {
		t.Fatalf("FromGenStatus zero must keep the lists non-nil: %+v", got)
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
