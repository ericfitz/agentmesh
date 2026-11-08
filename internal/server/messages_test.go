package server

import (
	"context"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/channels"
	"github.com/ericfitz/agentmesh/internal/core/sessions"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// msgEnv has identity pat and channel dev, created through the core.
func msgEnv(t *testing.T, o envOptions) *env {
	t.Helper()
	e := newEnv(t, o)
	e.identity("pat", false)
	if _, err := (channels.Service{Core: e.core}).Create(context.Background(), "pat", bus.CreateChannelInput{Name: "dev"}); err != nil {
		t.Fatalf("create dev: %v", err)
	}
	return e
}

func send(t *testing.T, c *gen.ClientWithResponses, key *string, body gen.SendRequest) *gen.SendMessageResponse {
	t.Helper()
	resp, err := c.SendMessageWithResponse(context.Background(), "dev", &gen.SendMessageParams{IdempotencyKey: key}, body)
	if err != nil {
		t.Fatalf("send: %v", err)
	}
	return resp
}

func hist(t *testing.T, c *gen.ClientWithResponses, p *gen.HistoryParams) *gen.HistoryResponse {
	t.Helper()
	resp, err := c.HistoryWithResponse(context.Background(), "dev", p)
	if err != nil {
		t.Fatalf("history: %v", err)
	}
	return resp
}

func TestSendIdempotencyWire(t *testing.T) { // Decision (Eric, 2026-10-21): Milestone 4 item 1
	e := msgEnv(t, envOptions{})
	c := e.client("pat")
	k := "key-1"
	a := send(t, c, &k, gen.SendRequest{Content: "hello"})
	b := send(t, c, &k, gen.SendRequest{Content: "hello"})
	if a.JSON201 == nil || b.JSON201 == nil || a.JSON201.Seq != b.JSON201.Seq {
		t.Fatalf("replay: %d %s / %d %s", a.StatusCode(), a.Body, b.StatusCode(), b.Body)
	}
	if n := len(*hist(t, c, &gen.HistoryParams{}).JSON200); n != 1 {
		t.Fatalf("rows after replay = %d, want 1", n)
	}
	d := send(t, c, &k, gen.SendRequest{Content: "different"})
	if d.StatusCode() != 409 || len(d.Body) == 0 || problemOf(t, d.Body).Code != "conflict" {
		t.Fatalf("same key other content: %d %s", d.StatusCode(), d.Body)
	}
	// Absent header: two identical sends are two rows.
	send(t, c, nil, gen.SendRequest{Content: "twice"})
	send(t, c, nil, gen.SendRequest{Content: "twice"})
	// Empty header value behaves as absent.
	empty := ""
	send(t, c, &empty, gen.SendRequest{Content: "empty"})
	send(t, c, &empty, gen.SendRequest{Content: "empty"})
	if n := len(*hist(t, c, &gen.HistoryParams{}).JSON200); n != 5 {
		t.Fatalf("rows = %d, want 5 (1 keyed, 2 absent, 2 empty)", n)
	}
}

func TestSendSessionAttribution(t *testing.T) {
	e := msgEnv(t, envOptions{})
	e.identity("sam", false)
	ss := sessions.Service{Core: e.core}
	mine, err := ss.Open(context.Background(), "pat", bus.OpenSessionInput{Hint: "impl"})
	if err != nil {
		t.Fatal(err)
	}
	theirs, err := ss.Open(context.Background(), "sam", bus.OpenSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	c := e.client("pat")
	if r := send(t, c, nil, gen.SendRequest{Content: "x", Session: &mine.ID}); r.JSON201 == nil {
		t.Fatalf("own session: %d %s", r.StatusCode(), r.Body)
	}
	m := (*hist(t, c, &gen.HistoryParams{}).JSON200)[0]
	if m.Session == nil || *m.Session != mine.ID || m.Display != "pat/impl" {
		t.Fatalf("message session/display = %v %q", m.Session, m.Display)
	}
	r := send(t, c, nil, gen.SendRequest{Content: "y", Session: &theirs.ID})
	if r.StatusCode() != 404 || len(r.Body) == 0 || problemOf(t, r.Body).Code != "not_found" {
		t.Fatalf("other identity's session: %d %s", r.StatusCode(), r.Body)
	}
}

func TestHistoryWire(t *testing.T) {
	e := msgEnv(t, envOptions{})
	c := e.client("pat")
	for i, tags := range [][]string{{"env:a"}, {"env:b"}, {"other"}, {"env:c"}} {
		tg := tags
		if r := send(t, c, nil, gen.SendRequest{Content: "m" + string(rune('0'+i)), Tags: &tg}); r.JSON201 == nil {
			t.Fatalf("send %d: %s", i, r.Body)
		}
	}
	all := *hist(t, c, &gen.HistoryParams{}).JSON200
	if len(all) != 4 {
		t.Fatalf("all = %d", len(all))
	}
	one := 1
	if got := *hist(t, c, &gen.HistoryParams{Count: &one}).JSON200; len(got) != 1 {
		t.Fatalf("count=1 returned %d", len(got))
	}
	after := all[1].Seq
	got := *hist(t, c, &gen.HistoryParams{After: &after}).JSON200
	for _, m := range got {
		if m.Seq <= after {
			t.Fatalf("after=%d returned seq %d", after, m.Seq)
		}
	}
	if len(got) == 0 {
		t.Fatal("after returned nothing")
	}
	before := all[2].Seq
	got = *hist(t, c, &gen.HistoryParams{Before: &before}).JSON200
	if len(got) == 0 {
		t.Fatal("before returned nothing")
	}
	for _, m := range got {
		if m.Seq >= before {
			t.Fatalf("before=%d returned seq %d", before, m.Seq)
		}
	}
	pat := []string{"env*"}
	got = *hist(t, c, &gen.HistoryParams{Tags: &pat}).JSON200
	if len(got) != 3 {
		t.Fatalf("tags=env* returned %d, want 3", len(got))
	}
	for _, path := range []string{"count=-1", "count=abc"} {
		resp := e.raw("pat", newReq(t, "GET", "/v1/channels/dev/messages?"+path, nil))
		if resp.StatusCode != 400 {
			t.Fatalf("%s: status %d", path, resp.StatusCode)
		}
		if p := readProblem(t, resp); p.Code != "validation" {
			t.Fatalf("%s: code %q", path, p.Code)
		}
	}
}

func TestSearchWire(t *testing.T) {
	e := msgEnv(t, envOptions{})
	c := e.client("pat")
	for _, s := range []string{"alpha one", "alpha two", "alpha three"} {
		if r := send(t, c, nil, gen.SendRequest{Content: s}); r.JSON201 == nil {
			t.Fatalf("send: %s", r.Body)
		}
	}
	// q is optional in the document (required: false), so the validator lets a
	// missing q through and the 400 is the core's "query is required".
	resp := e.raw("pat", newReq(t, "GET", "/v1/search", nil))
	if resp.StatusCode != 400 {
		t.Fatalf("q missing: %d", resp.StatusCode)
	}
	if p := readProblem(t, resp); p.Code != "validation" {
		t.Fatalf("q missing code %q", p.Code)
	}

	resp = e.raw("pat", newReq(t, "GET", "/v1/search?q=alpha&mode=fuzzy", nil))
	if resp.StatusCode != 400 {
		t.Fatalf("mode=fuzzy: %d", resp.StatusCode)
	}
	if p := readProblem(t, resp); p.Code != "validation" {
		t.Fatalf("mode=fuzzy code %q", p.Code)
	}

	q, n := "alpha", 2
	r, err := c.SearchWithResponse(context.Background(), &gen.SearchParams{Q: q, Count: &n})
	if err != nil || r.JSON200 == nil {
		t.Fatalf("search: %v %d %s", err, r.StatusCode(), r.Body)
	}
	if len(r.JSON200.Hits) != 2 {
		t.Fatalf("hits = %d, want 2", len(r.JSON200.Hits))
	}
	h := r.JSON200.Hits[0]
	if h.Message.Seq == 0 || !strings.Contains(h.Message.Content, "alpha") {
		t.Fatalf("hit = %+v", h)
	}
	if r.JSON200.Next == nil || *r.JSON200.Next == "" {
		t.Fatalf("next absent with more remaining: %s", r.Body)
	}
	r2, err := c.SearchWithResponse(context.Background(), &gen.SearchParams{Q: q, Count: &n, Cursor: r.JSON200.Next})
	if err != nil || r2.JSON200 == nil || len(r2.JSON200.Hits) != 1 {
		t.Fatalf("page 2: %v %s", err, r2.Body)
	}
}

// TestSendMissingContentIsValidation: a body without the required content is
// rejected by the validator before the handler (the handler's nil-body guard is
// not reachable through the strict server).
func TestSendMissingContentIsValidation(t *testing.T) {
	e := msgEnv(t, envOptions{})
	resp := e.raw("pat", func() *http.Request {
		r := newReq(t, "POST", "/v1/channels/dev/messages", io.NopCloser(strings.NewReader(`{}`)))
		return r
	}())
	if resp.StatusCode != 400 {
		t.Fatalf("status %d", resp.StatusCode)
	}
	if p := readProblem(t, resp); p.Code != "validation" {
		t.Fatalf("code %q", p.Code)
	}
}

// TestSendRateLimitedRetryAfterIsTheLimitersWait pins the 429 Retry-After end
// to end (issue #33): the header carries the limiter's own wait rounded up,
// not the floor of 1 that WriteProblem applies to a 429 with no known wait.
// The byte bucket is the one that can be made to wait seconds: a 64 KiB/s
// rate with a 1024 KiB burst, and two 900 KiB messages, leave a deficit of
// about 780 KiB at the second send, a wait of about 12 s, with the clock fixed.
func TestSendRateLimitedRetryAfterIsTheLimitersWait(t *testing.T) {
	e := msgEnv(t, envOptions{cfg: func(c *core.Config) {
		c.MaxMessageKiB = 1024
		c.SendKiBPerSecond = 64
	}})
	c := e.client("pat")
	big := strings.Repeat("x", 900*1024)
	if r := send(t, c, nil, gen.SendRequest{Content: big}); r.JSON201 == nil {
		t.Fatalf("first send: %d %s", r.StatusCode(), r.Body)
	}
	r := send(t, c, nil, gen.SendRequest{Content: big})
	if r.StatusCode() != http.StatusTooManyRequests {
		t.Fatalf("second send: %d %s, want 429", r.StatusCode(), r.Body)
	}
	got := r.HTTPResponse.Header.Get("Retry-After")
	secs, err := strconv.Atoi(got)
	if err != nil {
		t.Fatalf("Retry-After = %q: %v", got, err)
	}
	if secs < 10 || secs > 16 {
		t.Errorf("Retry-After = %d, want the limiter's wait (about 12), not the floor of 1", secs)
	}
}
