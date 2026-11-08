//go:build !windows

package e2e_test

// TestRequestExamples (issue #35, plan Task 8) sends every request example of
// api/openapi.yaml to the e2e server and checks the answer against the
// documented response, so the examples cannot rot.
//
// The file name sorts last in the package (tests run in file-name order, the
// package doc): the adminReset row wipes the bus data of fixture 1 and the
// rotateSigningKey row needs the fixture's 1 s signing-key cooldown to have
// passed behind TestArazzoWorkflows' rotation (ruling 10).
//
// The rows are a slice in replay order, one per (operation, example name)
// with coverage checked both ways. A request is built from every parameter's
// documented example plus the effective request example; the values a server
// assigns (ids, tokens, sequence numbers, timestamps, signed material, and
// the few names a row cannot take from a shared example) are substituted by
// JSON pointer (/body/<pointer>, /path/<name>, /query/<name>,
// /header/<name>). A pointer whose target is absent from the documented
// example fails. The answer must have the row's documented status, pass the
// validating proxy (runMain's final checks) and have the shape of the
// effective response example: every member of the live body is in the
// example with the same JSON kind (the reverse is not required), and an
// array the example fills is not empty unless the row lists it in emptyOK.
//
// The test runs once per process: the fixtures are process-wide, so -count=2
// fails at register.

import (
	"bytes"
	"crypto"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/getkin/kin-openapi/openapi3"

	"github.com/ericfitz/agentmesh/internal/auth/assertion"
	"github.com/ericfitz/agentmesh/internal/server"
	"github.com/ericfitz/agentmesh/internal/slackapi"
)

// exTarget is one fixture's server.
type exTarget struct {
	url, sqlite, home string
	bearer            string
}

// replay is the state the rows share.
type replay struct {
	t         *testing.T
	one, two  *exTarget // fixture 1 (fx) and fixture 2 (slackFx)
	tg        *exTarget // the row's fixture
	key       crypto.Signer
	kid       string
	jwk       map[string]any
	enroll    string
	sessionID string
	resume    string
	ack       string
	reply     int64 // the plain message the sendMessage example replies to
	sent      int64 // the sendMessage example's own seq
	memory    int64
	revision  int64
	blocker   int64
	task      int64
}

type liveFn func(c *replay) any

// exRow is one replayed example.
type exRow struct {
	op, example string
	slack       bool
	status      int
	noBearer    bool
	// emptyOK lists JSON pointers into the answer whose array may be empty
	// although the example's is not; each needs a reason in the row's comment.
	emptyOK []string
	live    map[string]liveFn
	setup   func(c *replay)
	after   func(c *replay, body any)
}

func lit(v any) liveFn { return func(*replay) any { return v } }

const (
	tasksChannel = "release-tasks" // a kind-tasks channel: ChannelParam's example is an ordinary one
	archiveName  = "release-train-archive"
	bridgedName  = "acme-ops"
	replayName   = "acme-coder-1"
)

// call is a by-hand request of a setup (no Idempotency-Key); it answers the
// status and the decoded body.
func (c *replay) call(method, path string, body any) (int, any) {
	c.t.Helper()
	var rd io.Reader
	if body != nil {
		b, err := json.Marshal(body)
		if err != nil {
			c.t.Fatal(err)
		}
		rd = bytes.NewReader(b)
	}
	req, err := http.NewRequest(method, c.tg.url+path, rd)
	if err != nil {
		c.t.Fatal(err)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	if c.tg.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+c.tg.bearer)
	}
	status, out := exchange(c.t, req)
	return status, out
}

func (c *replay) must(method, path string, body any, want int) any {
	c.t.Helper()
	status, out := c.call(method, path, body)
	if status != want {
		c.t.Fatalf("setup %s %s: status %d, want %d: %v", method, path, status, want, out)
	}
	return out
}

// exchange sends req and decodes a JSON answer (nil for an empty body).
func exchange(t testing.TB, req *http.Request) (int, any) {
	t.Helper()
	resp, err := (&http.Client{Timeout: 60 * time.Second}).Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", req.Method, req.URL, err)
	}
	defer func() { _ = resp.Body.Close() }()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return resp.StatusCode, nil
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		t.Fatalf("%s %s: status %d, body is not JSON: %q", req.Method, req.URL, resp.StatusCode, b)
	}
	return resp.StatusCode, out
}

func member(t testing.TB, v any, name string) any {
	t.Helper()
	m, ok := v.(map[string]any)
	if !ok {
		t.Fatalf("answer %v is not an object", v)
	}
	x, ok := m[name]
	if !ok {
		t.Fatalf("answer %v has no member %s", v, name)
	}
	return x
}

func memberInt(t testing.TB, v any, name string) int64 {
	t.Helper()
	f, ok := member(t, v, name).(float64)
	if !ok {
		t.Fatalf("member %s of %v is not a number", name, v)
	}
	return int64(f)
}

func memberStr(t testing.TB, v any, name string) string {
	t.Helper()
	s, ok := member(t, v, name).(string)
	if !ok || s == "" {
		t.Fatalf("member %s of %v is not a non-empty string", name, v)
	}
	return s
}

func (c *replay) enrollmentToken(tg *exTarget) string {
	c.t.Helper()
	r := mustRun(c.t, tg.home, "server", "admin", "-sqlite", tg.sqlite, "enrollment", "create")
	m := tokenRE.FindStringSubmatch(r.stdout)
	if m == nil {
		c.t.Fatalf("enrollment create printed %q", r.stdout)
	}
	return m[1]
}

func (c *replay) signAssertion(key crypto.Signer, kid, identity, audience string) string {
	c.t.Helper()
	ca, err := assertion.Sign(assertion.Input{Identity: identity, Audience: audience, Key: key, KID: kid, Now: time.Now()})
	if err != nil {
		c.t.Fatal(err)
	}
	return ca
}

func (c *replay) makeAdmin(tg *exTarget, identity string) {
	c.t.Helper()
	mustRun(c.t, tg.home, "server", "admin", "-sqlite", tg.sqlite, "admins", "add", "-identity", identity)
}

// registerAndLogin registers identity on tg by hand (a fresh key, a fresh
// enrollment token) and stores its bearer.
func (c *replay) registerAndLogin(tg *exTarget, identity string) {
	c.t.Helper()
	key, kid, jwk := freshKeyJWK(c.t)
	saved := c.tg
	c.tg = tg
	defer func() { c.tg = saved }()
	c.must(http.MethodPost, "/v1/auth/register", map[string]any{
		"identity": identity, "public_key_jwk": jwk, "enrollment_token": c.enrollmentToken(tg)}, http.StatusCreated)
	form := url.Values{"grant_type": {"client_credentials"},
		"client_assertion_type": {"urn:ietf:params:oauth:client-assertion-type:jwt-bearer"},
		"client_assertion":      {c.signAssertion(key, kid, identity, tg.url)}}
	req, err := http.NewRequest(http.MethodPost, tg.url+"/v1/auth/token", strings.NewReader(form.Encode()))
	if err != nil {
		c.t.Fatal(err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	status, out := exchange(c.t, req)
	if status != http.StatusOK {
		c.t.Fatalf("token for %s: status %d: %v", identity, status, out)
	}
	tg.bearer = memberStr(c.t, out, "access_token")
}

// exampleRows is the replay table, in replay order (58 rows).
func exampleRows() []exRow {
	sessionPath := map[string]liveFn{"/path/session": func(c *replay) any { return c.sessionID }}
	idPath := func(get func(c *replay) int64) map[string]liveFn {
		return map[string]liveFn{"/path/id": func(c *replay) any { return get(c) }}
	}
	memoryID := func(c *replay) int64 { return c.memory }
	taskID := func(c *replay) int64 { return c.task }
	with := func(m map[string]liveFn, kv ...any) map[string]liveFn {
		out := map[string]liveFn{}
		for k, v := range m {
			out[k] = v
		}
		for i := 0; i < len(kv); i += 2 {
			out[kv[i].(string)] = kv[i+1].(func(*replay) any)
		}
		return out
	}
	return []exRow{
		{op: "wellKnown", status: 200},
		{op: "authorizationServerMetadata", status: 200},
		{op: "openidConfiguration", status: 200},
		{op: "discover", status: 200},
		{op: "jwks", status: 200},
		{op: "health", status: 200, noBearer: true}, // the probe tier
		{op: "register", status: 201,
			setup: func(c *replay) {
				c.key, c.kid, c.jwk = freshKeyJWK(c.t)
				c.enroll = c.enrollmentToken(c.tg)
			},
			live: map[string]liveFn{
				"/body/public_key_jwk":   func(c *replay) any { return c.jwk },
				"/body/enrollment_token": func(c *replay) any { return c.enroll },
			}},
		{op: "token", status: 200,
			live: map[string]liveFn{"/body/client_assertion": func(c *replay) any {
				return c.signAssertion(c.key, c.kid, replayName, c.tg.url)
			}},
			after: func(c *replay, body any) {
				c.tg.bearer = memberStr(c.t, body, "access_token")
				c.makeAdmin(c.tg, replayName)
			}},
		{op: "createScope", status: 200},
		{op: "createAgentIdentity", status: 200},
		{op: "listScopes", status: 200},
		{op: "getScope", status: 200,
			setup: func(c *replay) {
				c.must(http.MethodPost, "/v1/channels", map[string]any{"name": "acme-plans", "scope": "acme"}, http.StatusCreated)
			}},
		{op: "createIdentityByEmail", status: 200},
		// The example names acme-builder: the identity row exists (the
		// createAgentIdentity row made it) and holds no key, so the reset
		// answers 200 with keys_removed 0. The replay identity
		// acme-coder-1 is never reset (it would lose its key).
		{op: "resetCredential", status: 200},
		{op: "createChannel", status: 201, emptyOK: []string{"/capabilities"}}, // capabilities appear only on a bridged channel
		{op: "listChannels", status: 200},
		{op: "setACL", status: 204},
		{op: "getACL", status: 200},
		{op: "subscribe", status: 204},
		{op: "subscribeTags", status: 204},
		{op: "listTagSubscriptions", status: 200},
		{op: "openSession", example: "default", status: 201,
			after: func(c *replay, body any) {
				c.sessionID = memberStr(c.t, body, "id")
				c.resume = memberStr(c.t, body, "resume_token")
			}},
		{op: "openSession", example: "resume", status: 201,
			emptyOK: []string{"/rejected_cursors"}, // a resume sends no cursors, so none is rejected
			live:    map[string]liveFn{"/body/resume_token": func(c *replay) any { return c.resume }},
			after: func(c *replay, body any) {
				c.sessionID = memberStr(c.t, body, "id")
				c.resume = memberStr(c.t, body, "resume_token")
			}},
		{op: "sendMessage", status: 201,
			setup: func(c *replay) {
				out := c.must(http.MethodPost, "/v1/channels/release-train/messages",
					map[string]any{"content": "Build 41 is green on main.", "session": c.sessionID}, http.StatusCreated)
				c.reply = memberInt(c.t, out, "seq")
			},
			live: map[string]liveFn{
				"/body/reply_to": func(c *replay) any { return c.reply },
				"/body/session":  func(c *replay) any { return c.sessionID },
			},
			after: func(c *replay, body any) { c.sent = memberInt(c.t, body, "seq") }},
		{op: "peek", status: 200, live: sessionPath},
		// Two messages the session itself sent are pending and include_own is
		// true (ruling 15), so the wake comes at once, after the merge window (Decision 45, 2 s).
		{op: "watch", status: 200,
			live: with(sessionPath, "/query/after", func(c *replay) any { return c.reply - 1 })},
		{op: "receive", status: 200,
			emptyOK: []string{"/gaps"}, // gaps appear only after budget eviction deletes unread messages
			setup: func(c *replay) {
				path := "/v1/sessions/" + c.sessionID + "/receive"
				out := c.must(http.MethodPost, path, map[string]any{"include_own": true}, http.StatusOK)
				c.ack = memberStr(c.t, out, "batch")
				// One more message, so the example's receive delivers one.
				c.must(http.MethodPost, "/v1/channels/release-train/messages",
					map[string]any{"content": "Build 43 is green on main.", "session": c.sessionID}, http.StatusCreated)
			},
			live: with(sessionPath, "/body/ack", func(c *replay) any { return c.ack })},
		{op: "setAgentStatus", status: 200, live: sessionPath},
		{op: "listAgentStatuses", status: 200},
		{op: "agentStatusHistory", status: 200},
		{op: "listIdentities", status: 200},
		// after and before are live too: the server's one sequence counter is
		// far past the examples' 40 and 50, and the answer must not be empty.
		{op: "history", status: 200, live: map[string]liveFn{
			"/query/thread": func(c *replay) any { return c.reply },
			"/query/after":  func(c *replay) any { return c.reply - 1 },
			"/query/before": func(c *replay) any { return c.sent + 1 },
		}},
		{op: "search", status: 200, live: map[string]liveFn{
			"/query/thread": func(c *replay) any { return c.reply },
			// The example cursor is an offset that skips every hit here; 0 starts at the first.
			"/query/cursor": lit("0"),
			// A fixed until in the example would pass in 2027 and stop matching.
			"/query/until": func(c *replay) any { return time.Now().Add(24 * time.Hour).UnixMilli() },
		}},
		{op: "getMemory", status: 200,
			setup: func(c *replay) {
				c.must(http.MethodPost, "/v1/channels", map[string]any{"name": "release-notes", "kind": "memory"}, http.StatusCreated)
				out := c.must(http.MethodPost, "/v1/channels/release-notes/messages",
					map[string]any{"subject": "Release notes 2026.11", "content": "Release notes for 2026.11: build 42 is green on main."}, http.StatusCreated)
				c.memory = memberInt(c.t, out, "memory_id")
			},
			live:  idPath(memoryID),
			after: func(c *replay, body any) { c.revision = memberInt(c.t, body, "revision") }},
		{op: "editMemory", status: 201,
			live: with(idPath(memoryID), "/body/if_revision", func(c *replay) any { return c.revision })},
		{op: "listMemoryRevisions", status: 200, live: idPath(memoryID)},
		{op: "deleteMemory", status: 204, live: idPath(memoryID)},
		{op: "createTask", status: 201,
			setup: func(c *replay) {
				c.must(http.MethodPost, "/v1/channels", map[string]any{"name": tasksChannel, "kind": "tasks"}, http.StatusCreated)
				out := c.must(http.MethodPost, "/v1/channels/"+tasksChannel+"/tasks", map[string]any{"subject": "Tag the release candidate"}, http.StatusCreated)
				c.blocker = memberInt(c.t, out, "id")
				id := strconv.FormatInt(c.blocker, 10)
				c.must(http.MethodPost, "/v1/tasks/"+id+"/claim", map[string]any{}, http.StatusOK)
				c.must(http.MethodPatch, "/v1/tasks/"+id, map[string]any{"status": "completed"}, http.StatusOK)
			},
			live: map[string]liveFn{
				"/path/channel":      lit(tasksChannel),
				"/body/blocked_by/0": func(c *replay) any { return c.blocker },
				"/body/parent":       func(c *replay) any { return c.blocker },
			},
			after: func(c *replay, body any) { c.task = memberInt(c.t, body, "id") }},
		{op: "claimTask", status: 200,
			live: with(idPath(taskID), "/body/leased_until", func(c *replay) any { return time.Now().Add(time.Hour).UnixMilli() })},
		{op: "listTasks", status: 200, live: map[string]liveFn{"/path/channel": lit(tasksChannel)}},
		{op: "getTask", status: 200, live: idPath(taskID)},
		{op: "releaseTask", status: 200, live: idPath(taskID)},
		{op: "updateTask", status: 200,
			setup: func(c *replay) {
				c.must(http.MethodPost, "/v1/tasks/"+strconv.FormatInt(c.task, 10)+"/claim", map[string]any{}, http.StatusOK)
			},
			live: idPath(taskID)},
		{op: "unsubscribeTags", status: 204},
		{op: "unsubscribe", status: 204},
		{op: "renameChannel", status: 204},
		// ChannelParam's example is release-train, renamed by the row before.
		{op: "deleteChannel", status: 204, live: map[string]liveFn{"/path/channel": lit(archiveName)}},
		{op: "closeSession", status: 204, live: sessionPath},
		{op: "adminStatus", status: 200,
			// The replay session is closed by now; keep another open.
			setup: func(c *replay) {
				c.must(http.MethodPost, "/v1/sessions", map[string]any{"hint": "status"}, http.StatusCreated)
			},
			// notices are capacity warnings (the replay never fills the store);
			// capabilities appear only on a bridged channel (the bridge is on fixture 2).
			emptyOK: []string{"/notices", "/channels/0/capabilities"}},
		{op: "adminUsage", status: 200},
		{op: "listSigningKeys", status: 200},
		// The fixture's cooldown is 1 s from the key's creation; revoke_previous
		// is false in the example, so the bearer stays valid.
		{op: "rotateSigningKey", status: 200, setup: func(*replay) { time.Sleep(1100 * time.Millisecond) }},
		{op: "doneScope", status: 200},
		{op: "createBridge", slack: true, status: 200,
			emptyOK: []string{"/not_invited"}, // the replay registers dana in the Slack fake, so every invite succeeds
			setup: func(c *replay) {
				c.registerAndLogin(c.tg, replayName)
				c.makeAdmin(c.tg, replayName)
				c.must(http.MethodPost, "/v1/admin/scopes", map[string]any{"name": "acme"}, http.StatusOK)
				out := c.must(http.MethodPost, "/v1/admin/identities/by-email", map[string]any{"email": "dana@example.com"}, http.StatusOK)
				human := memberStr(c.t, out, "identity")
				slackFx.fake.AddUser(slackapi.User{ID: "U0EXAMPLE1", TeamID: "T1", Email: "dana@example.com", DisplayName: "Dana"})
				// Neither read nor write has an administrator-flag bypass on a
				// bridged channel, so the ACL names both identities.
				c.must(http.MethodPost, "/v1/channels", map[string]any{"name": bridgedName, "scope": "acme",
					"acl": []any{
						map[string]any{"identity": replayName, "permissions": []string{"read", "write"}},
						map[string]any{"identity": human, "permissions": []string{"read", "write"}},
					}}, http.StatusCreated)
			}},
		{op: "listBridges", slack: true, status: 200},
		// ChannelParam's example is release-train.
		{op: "getBridge", slack: true, status: 200, live: map[string]liveFn{"/path/channel": lit(bridgedName)}},
		{op: "removeBridge", slack: true, status: 204, live: map[string]liveFn{"/path/channel": lit(bridgedName)}},
		{op: "adminReset", status: 204},
	}
}

func rowKey(op, example string) string {
	if example == "" {
		return op
	}
	return op + "/" + example
}

// specOp is one operation of the document with the request media type and
// the example names it needs rows for.
type specOp struct {
	id, method, path string
	item             *openapi3.PathItem
	op               *openapi3.Operation
}

func specOps(doc *openapi3.T) map[string]specOp {
	out := map[string]specOp{}
	for path, item := range doc.Paths.Map() {
		for method, op := range item.Operations() {
			// The embedded document's operationIds start upper case (the
			// generator's transform); the document's own start lower case.
			id := strings.ToLower(op.OperationID[:1]) + op.OperationID[1:]
			out[id] = specOp{id, method, path, item, op}
		}
	}
	return out
}

// requestMedia is the operation's request media type (nil without a body).
func requestMedia(t testing.TB, op *openapi3.Operation) (string, *openapi3.MediaType) {
	if op.RequestBody == nil || op.RequestBody.Value == nil {
		return "", nil
	}
	names := make([]string, 0, len(op.RequestBody.Value.Content))
	for n := range op.RequestBody.Value.Content {
		names = append(names, n)
	}
	sort.Strings(names)
	if len(names) == 0 {
		return "", nil
	}
	if len(names) > 1 {
		t.Fatalf("%s has %d request media types; the replay sends one", op.OperationID, len(names))
	}
	return names[0], op.RequestBody.Value.Content[names[0]]
}

// coverageKeys are the row keys the document requires: one per named request
// example, else one per operation.
func coverageKeys(t testing.TB, doc *openapi3.T) []string {
	var keys []string
	for id, s := range specOps(doc) {
		_, mt := requestMedia(t, s.op)
		if mt != nil && len(mt.Examples) > 0 {
			for name := range mt.Examples {
				keys = append(keys, rowKey(id, name))
			}
			continue
		}
		keys = append(keys, id)
	}
	sort.Strings(keys)
	return keys
}

// effectiveExample is the media type's example for name: the named example,
// else its singular example, else the first of its examples (default, else by
// name), else the referenced schema's example. It is a deep copy normalized
// through JSON.
func effectiveExample(mt *openapi3.MediaType, name string) any {
	var v any
	switch {
	case name != "" && mt.Examples[name] != nil && mt.Examples[name].Value != nil:
		v = mt.Examples[name].Value.Value
	case mt.Example != nil:
		v = mt.Example
	case len(mt.Examples) > 0:
		names := make([]string, 0, len(mt.Examples))
		for n := range mt.Examples {
			names = append(names, n)
		}
		sort.Strings(names)
		pick := names[0]
		if mt.Examples["default"] != nil {
			pick = "default"
		}
		v = mt.Examples[pick].Value.Value
	case mt.Schema != nil && mt.Schema.Value != nil:
		v = mt.Schema.Value.Example
	}
	if v == nil {
		return nil
	}
	b, err := json.Marshal(v)
	if err != nil {
		return nil
	}
	var out any
	if err := json.Unmarshal(b, &out); err != nil {
		return nil
	}
	return out
}

func kindOf(v any) string {
	switch v.(type) {
	case nil:
		return "null"
	case bool:
		return "boolean"
	case string:
		return "string"
	case map[string]any:
		return "object"
	case []any:
		return "array"
	default:
		return "number"
	}
}

// shapeCheck is ruling 9: every member of live (recursively; the first
// element of a non-empty array against the first element of the example's)
// is in example with the same JSON kind. Values are not compared. An empty
// live array where the example's is not fails unless its JSON pointer is in
// emptyOK: an empty answer checks nothing, so it must be a decision.
func shapeCheck(t testing.TB, live, example any, path, ptr string, emptyOK map[string]bool) {
	t.Helper()
	if kindOf(live) != kindOf(example) {
		t.Errorf("member %s is %s in the live body and %s in the example", path, kindOf(live), kindOf(example))
		return
	}
	switch l := live.(type) {
	case map[string]any:
		e := example.(map[string]any)
		keys := make([]string, 0, len(l))
		for k := range l {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			name := k
			if path != "" {
				name = path + "." + k
			}
			ev, ok := e[k]
			if !ok {
				t.Errorf("member %s of the live body is not in the example", name)
				continue
			}
			shapeCheck(t, l[k], ev, name, ptr+"/"+k, emptyOK)
		}
	case []any:
		e := example.([]any)
		if len(l) == 0 {
			if len(e) > 0 && !emptyOK[ptr] {
				t.Errorf("member %s is an empty array in the live body and the example's is not (%s is not in the row's emptyOK)", path, ptr)
			}
			return
		}
		if len(e) == 0 {
			t.Errorf("member %s is a non-empty array in the live body and an empty one in the example", path)
			return
		}
		shapeCheck(t, l[0], e[0], path+"[0]", ptr+"/0", emptyOK)
	}
}

// scalarString serializes a parameter value (a number as a plain decimal).
func scalarString(t testing.TB, v any) string {
	t.Helper()
	switch x := v.(type) {
	case string:
		return x
	case bool:
		return strconv.FormatBool(x)
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(x, 10)
	case int:
		return strconv.Itoa(x)
	}
	t.Fatalf("parameter value %v (%T) is not a scalar", v, v)
	return ""
}

// setPointer replaces the value at segs below root, reporting whether the
// target existed.
func setPointer(root any, segs []string, v any) (any, bool) {
	if len(segs) == 0 {
		return v, true
	}
	switch r := root.(type) {
	case map[string]any:
		child, ok := r[segs[0]]
		if !ok {
			return root, false
		}
		nv, ok := setPointer(child, segs[1:], v)
		if !ok {
			return root, false
		}
		r[segs[0]] = nv
		return r, true
	case []any:
		i, err := strconv.Atoi(segs[0])
		if err != nil || i < 0 || i >= len(r) {
			return root, false
		}
		nv, ok := setPointer(r[i], segs[1:], v)
		if !ok {
			return root, false
		}
		r[i] = nv
		return r, true
	}
	return root, false
}

// buildRequest assembles the request of row number n from the documented
// examples and applies the live pointers.
func (c *replay) buildRequest(s specOp, row exRow, n int) *http.Request {
	t := c.t
	t.Helper()
	path := map[string]any{}
	query := map[string]any{}
	header := map[string]string{}
	var qorder []string
	comma := map[string]bool{}
	params := append(append(openapi3.Parameters{}, s.item.Parameters...), s.op.Parameters...)
	for _, pr := range params {
		p := pr.Value
		if p.Example == nil {
			t.Fatalf("parameter %s of %s has no example", p.Name, s.id)
		}
		switch p.In {
		case "path":
			path[p.Name] = p.Example
		case "query":
			if p.Style != "" && p.Style != "form" {
				t.Fatalf("parameter %s of %s: style %s is not replayed", p.Name, s.id, p.Style)
			}
			query[p.Name] = p.Example
			qorder = append(qorder, p.Name)
			comma[p.Name] = p.Explode != nil && !*p.Explode // form, explode false: one comma-separated value
		case "header":
			header[p.Name] = scalarString(t, p.Example)
		default:
			t.Fatalf("parameter %s of %s is in %s", p.Name, s.id, p.In)
		}
	}
	if _, ok := header["Idempotency-Key"]; ok {
		header["Idempotency-Key"] += "-" + strconv.Itoa(n)
	}
	var body any
	mediaType, mt := requestMedia(t, s.op)
	if mt != nil {
		body = effectiveExample(mt, row.example)
		if body == nil {
			t.Fatalf("%s has no request example", s.id)
		}
	}
	pointers := make([]string, 0, len(row.live))
	for p := range row.live {
		pointers = append(pointers, p)
	}
	sort.Strings(pointers)
	for _, ptr := range pointers {
		v := row.live[ptr](c)
		segs := strings.Split(strings.TrimPrefix(ptr, "/"), "/")
		missing := func() { t.Fatalf("live pointer %s is not in the example of %s", ptr, s.id) }
		if len(segs) < 2 {
			missing()
		}
		switch segs[0] {
		case "path":
			if _, ok := path[segs[1]]; !ok || len(segs) != 2 {
				missing()
			}
			path[segs[1]] = v
		case "query":
			if _, ok := query[segs[1]]; !ok || len(segs) != 2 {
				missing()
			}
			query[segs[1]] = v
		case "header":
			if _, ok := header[segs[1]]; !ok || len(segs) != 2 {
				missing()
			}
			header[segs[1]] = scalarString(t, v)
		case "body":
			nb, ok := setPointer(body, segs[1:], v)
			if !ok || body == nil {
				missing()
			}
			body = nb
		default:
			t.Fatalf("live pointer %s: unknown part %s", ptr, segs[0])
		}
	}
	target := s.path
	for name, v := range path {
		target = strings.ReplaceAll(target, "{"+name+"}", url.PathEscape(scalarString(t, v)))
	}
	if strings.Contains(target, "{") {
		t.Fatalf("path %s of %s has a parameter without an example", s.path, s.id)
	}
	q := url.Values{}
	for _, name := range qorder {
		switch x := query[name].(type) {
		case []any:
			if comma[name] {
				parts := make([]string, len(x))
				for i, e := range x {
					parts[i] = scalarString(t, e)
				}
				q.Set(name, strings.Join(parts, ","))
				break
			}
			for _, e := range x {
				q.Add(name, scalarString(t, e))
			}
		default:
			q.Set(name, scalarString(t, x))
		}
	}
	full := c.tg.url + target
	if len(q) > 0 {
		full += "?" + q.Encode()
	}
	var rd io.Reader
	contentType := ""
	if body != nil {
		switch mediaType {
		case "application/json":
			b, err := json.Marshal(body)
			if err != nil {
				t.Fatal(err)
			}
			rd, contentType = bytes.NewReader(b), mediaType
		case "application/x-www-form-urlencoded":
			m, ok := body.(map[string]any)
			if !ok {
				t.Fatalf("form body of %s is not an object", s.id)
			}
			f := url.Values{}
			for k, v := range m {
				f.Set(k, scalarString(t, v))
			}
			rd, contentType = strings.NewReader(f.Encode()), mediaType
		default:
			t.Fatalf("request media type %s of %s is not replayed", mediaType, s.id)
		}
	}
	req, err := http.NewRequest(strings.ToUpper(s.method), full, rd)
	if err != nil {
		t.Fatal(err)
	}
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	for k, v := range header {
		req.Header.Set(k, v)
	}
	open := s.op.Security != nil && len(*s.op.Security) == 0
	if !open && !row.noBearer {
		if c.tg.bearer == "" {
			t.Fatalf("%s needs a bearer and the replay has none", s.id)
		}
		req.Header.Set("Authorization", "Bearer "+c.tg.bearer)
	}
	return req
}

// responseExample is the effective example of the operation's response of
// the given status (the JSON media type, else the first).
func responseExample(t testing.TB, s specOp, status int) any {
	t.Helper()
	r := s.op.Responses.Status(status)
	if r == nil || r.Value == nil {
		t.Fatalf("%s declares no %d response", s.id, status)
	}
	if len(r.Value.Content) == 0 {
		t.Fatalf("the %d response of %s has no content", status, s.id)
	}
	mt := r.Value.Content.Get("application/json")
	if mt == nil {
		names := make([]string, 0, len(r.Value.Content))
		for n := range r.Value.Content {
			names = append(names, n)
		}
		sort.Strings(names)
		mt = r.Value.Content[names[0]]
	}
	ex := effectiveExample(mt, "")
	if ex == nil {
		t.Fatalf("the %d response of %s has no example", status, s.id)
	}
	return ex
}

func TestRequestExamples(t *testing.T) {
	doc := server.Spec()
	ops := specOps(doc)
	rows := exampleRows()

	if !t.Run("coverage", func(t *testing.T) {
		have := map[string]int{}
		for _, r := range rows {
			have[rowKey(r.op, r.example)]++
		}
		want := coverageKeys(t, doc)
		wantSet := map[string]bool{}
		for _, k := range want {
			wantSet[k] = true
			if have[k] == 0 {
				op, _, _ := strings.Cut(k, "/")
				t.Errorf("no row for %s (operation %s)", k, op)
			}
		}
		var extra []string
		for k, n := range have {
			if !wantSet[k] {
				extra = append(extra, k)
			}
			if n > 1 {
				t.Errorf("%d rows for %s", n, k)
			}
		}
		sort.Strings(extra)
		for _, k := range extra {
			t.Errorf("row %s names no operation or request example of the document", k)
		}
	}) {
		t.FailNow()
	}

	c := &replay{
		one: &exTarget{url: fx.serverURL(), sqlite: fx.sqlite, home: fx.homeA},
		two: &exTarget{url: slackFx.serverURL(), sqlite: slackFx.sqlite, home: slackFx.home},
	}
	for i, row := range rows {
		s := ops[row.op]
		n := i + 1
		ok := t.Run(rowKey(row.op, row.example), func(t *testing.T) {
			c.t = t
			c.tg = c.one
			if row.slack {
				c.tg = c.two
			}
			if row.setup != nil {
				row.setup(c)
			}
			req := c.buildRequest(s, row, n)
			status, body := exchange(t, req)
			if status != row.status {
				t.Fatalf("%s %s: status %d, want %d: %v", req.Method, req.URL.Path, status, row.status, body)
			}
			if row.status == http.StatusNoContent {
				if s.op.Responses.Status(row.status) == nil {
					t.Fatalf("%s documents no 204 response", s.id)
				}
				if body != nil {
					t.Fatalf("a 204 answer has a body: %v", body)
				}
			} else {
				ok := map[string]bool{}
				for _, p := range row.emptyOK {
					ok[p] = true
				}
				shapeCheck(t, body, responseExample(t, s, row.status), "", "", ok)
				if t.Failed() {
					t.FailNow()
				}
			}
			if row.after != nil {
				row.after(c, body)
			}
		})
		if !ok {
			t.FailNow() // later rows depend on earlier state
		}
	}
}
