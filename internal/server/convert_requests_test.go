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
}

func mustMarshal(t *testing.T, v any) string {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}
