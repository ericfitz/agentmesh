package server

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/bus"
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
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
