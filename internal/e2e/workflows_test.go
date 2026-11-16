//go:build !windows

package e2e_test

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/arazzotest"
	"github.com/ericfitz/agentmesh/internal/auth/assertion"
	"github.com/ericfitz/agentmesh/internal/auth/keys"
	"github.com/ericfitz/agentmesh/internal/slackapi"
)

// The file name sorts after mcponly_test.go and slack_test.go: the package
// runs its tests in file-name order and TestSection24Sequence must run before
// anything has opened a session (the package doc).

// inboundText is the literal of api/arazzo.yaml's bridges-inbound-remove
// history criterion; outboundText the one of bridges' send-outbound content.
const (
	outboundText = "hello slack from arazzo"
	inboundText  = "hello bus from slack"
)

// wfRunner runs workflows of the repository document against one server, one
// Runner per fixture (bearers do not cross fixtures and dependsOn is checked
// per Runner).
type wfRunner struct {
	r        *arazzotest.Runner
	audience string
	prefix   string // "" or "slack:"
	ran      map[string]bool
}

// run runs one workflow as a subtest named name; a failure ends the sequence,
// since later workflows depend on earlier outputs.
func (w *wfRunner) run(t *testing.T, name, id string, in map[string]any) map[string]any {
	t.Helper()
	var out map[string]any
	if w.ran == nil {
		w.ran = map[string]bool{}
	}
	w.ran[id] = true
	ok := t.Run(w.prefix+name, func(t *testing.T) {
		res, err := w.r.Run(context.Background(), id, in)
		if err != nil {
			t.Fatalf("workflow %s: %v", id, err)
		}
		out = res.Outputs
	})
	if !ok {
		t.FailNow()
	}
	return out
}

// freshKeyJWK generates an EdDSA key and returns it with its key id and the
// public JWK as the server emits it (keys.ToJWK), decoded to a JSON object.
func freshKeyJWK(t testing.TB) (crypto.Signer, string, map[string]any) {
	t.Helper()
	key, err := keys.Generate(keys.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	kid, err := keys.KID(key.Public())
	if err != nil {
		t.Fatal(err)
	}
	jwk, err := keys.ToJWK(key.Public(), kid)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := json.Marshal(jwk)
	if err != nil {
		t.Fatal(err)
	}
	var pub map[string]any
	if err := json.Unmarshal(raw, &pub); err != nil {
		t.Fatal(err)
	}
	return key, kid, pub
}

// register runs register-and-login for a new identity with a fresh enrollment
// token and returns its access token.
func (w *wfRunner) register(t *testing.T, identity, enrollmentToken string) string {
	t.Helper()
	tok, _, _ := w.registerWithKey(t, identity, enrollmentToken)
	return tok
}

// registerWithKey is register that also returns the identity's key and kid, so
// a test can sign a further assertion for it.
func (w *wfRunner) registerWithKey(t *testing.T, identity, enrollmentToken string) (string, crypto.Signer, string) {
	t.Helper()
	key, kid, pub := freshKeyJWK(t)
	ca, err := assertion.Sign(assertion.Input{Identity: identity, Audience: w.audience, Key: key, KID: kid, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	out := w.run(t, "register-and-login/"+identity, "register-and-login", map[string]any{
		"identity": identity, "public_key_jwk": pub, "enrollment_token": enrollmentToken, "client_assertion": ca,
	})
	tok, _ := out["access_token"].(string)
	if tok == "" {
		t.Fatalf("register-and-login %s: no access_token in %v", identity, out)
	}
	return tok, key, kid
}

func str(t *testing.T, out map[string]any, name string) string {
	t.Helper()
	s, ok := out[name].(string)
	if !ok || s == "" {
		t.Fatalf("output %s = %v, want a non-empty string", name, out[name])
	}
	return s
}

// TestArazzoWorkflows runs the workflows of api/arazzo.yaml (the six
// journeys of docs/journeys.md as twelve workflows) against both e2e fixtures:
// the binary's server (no Slack) and the in-process server with the Slack fake.
// Every request crosses the validating proxy, so runMain's violation and
// Skipped checks cover these responses too.
func TestArazzoWorkflows(t *testing.T) {
	doc, err := arazzotest.Load(filepath.Join("..", "..", "api", "arazzo.yaml"))
	if err != nil {
		t.Fatalf("Load(api/arazzo.yaml): %v", err)
	}
	one := &wfRunner{r: &arazzotest.Runner{Doc: doc, BaseURL: fx.serverURL(), Log: t.Logf}, audience: fx.serverURL()}
	token := func() string {
		r := mustRun(t, fx.homeA, "server", "admin", "-sqlite", fx.sqlite, "enrollment", "create")
		m := tokenRE.FindStringSubmatch(r.stdout)
		if m == nil {
			t.Fatalf("enrollment create printed %q", r.stdout)
		}
		return m[1]
	}

	// Fixture 1: the binary's server.
	ann := one.register(t, "arazzo-ann", token())
	bob := one.register(t, "arazzo-bob", token())
	root, rootKey, rootKID := one.registerWithKey(t, "arazzo-root", token())
	mustRun(t, fx.homeA, "server", "admin", "-sqlite", fx.sqlite, "admins", "add", "-identity", "arazzo-root")

	one.run(t, "send-receive-ack", "send-receive-ack", map[string]any{"bearer": ann, "peer_bearer": bob, "channel": "arazzo-inbox"})
	one.run(t, "memories", "memories", map[string]any{"bearer": ann, "channel": "arazzo-memories"})
	one.run(t, "task-claim-complete", "task-claim-complete", map[string]any{"bearer": ann, "channel": "arazzo-tasks"})
	one.run(t, "task-list-maintain", "task-list-maintain", map[string]any{"bearer": ann, "channel": "arazzo-plan", "identity": "arazzo-ann"})
	one.run(t, "admin-bootstrap", "admin-bootstrap", map[string]any{
		"admin_bearer": root, "scope": "arazzo-fx", "agent_name": "arazzo-fx-coder", "human_email": "arazzo-human@example.test"})
	one.run(t, "search-history", "search-history", map[string]any{"bearer": ann, "channel": "arazzo-search"})
	one.run(t, "agent-status", "agent-status", map[string]any{"bearer": ann, "identity": "arazzo-ann"})
	one.run(t, "channel-access", "channel-access", map[string]any{
		"bearer": ann, "identity": "arazzo-ann", "peer_bearer": bob, "peer_identity": "arazzo-bob",
		"channel": "arazzo-acl", "new_name": "arazzo-acl-renamed"})
	// The rotation revokes the key that signed root's bearer (Ruling 6), so the
	// workflow exchanges again; an assertion is single-use, hence a second one.
	exchange, err := assertion.Sign(assertion.Input{Identity: "arazzo-root", Audience: one.audience, Key: rootKey, KID: rootKID, Now: time.Now()})
	if err != nil {
		t.Fatal(err)
	}
	one.run(t, "signing-key-rotation", "signing-key-rotation", map[string]any{"admin_bearer": root, "exchange_assertion": exchange})

	// Fixture 2: the in-process server with the Slack fake.
	two := &wfRunner{r: &arazzotest.Runner{Doc: doc, BaseURL: slackFx.serverURL(), Log: t.Logf}, audience: slackFx.serverURL(), prefix: "slack:"}
	jroot := two.register(t, "arazzo-j9-root", slackFx.token(t))
	mustRun(t, slackFx.home, "server", "admin", "-sqlite", slackFx.sqlite, "admins", "add", "-identity", "arazzo-j9-root")
	boot := two.run(t, "admin-bootstrap", "admin-bootstrap", map[string]any{
		"admin_bearer": jroot, "scope": "j9wf", "agent_name": "j9wf-coder", "human_email": "j9@example.test"})
	human := str(t, boot, "human_identity")
	slackFx.fake.AddUser(slackapi.User{ID: "U2", TeamID: "T1", Email: "j9@example.test", DisplayName: "J9"})
	br := two.run(t, "bridges", "bridges", map[string]any{
		"admin_bearer": jroot, "admin_identity": "arazzo-j9-root", "scope": str(t, boot, "scope"),
		"channel": "j9wf-room", "slack_name": "j9wf-room", "human_identity": human})
	slackID := str(t, br, "slack_channel_id")
	seq := br["seq"]

	// Between the two halves: the outbound text reaches Slack, then the Slack
	// user answers and the bridge appends the answer as the human's.
	waitFor(t, func() string { return "an outbound post containing " + outboundText }, 20*time.Second, 100*time.Millisecond, func() bool {
		ch, _ := slackFx.fake.Channel(slackID)
		for _, p := range ch.Posts {
			if strings.Contains(p.Fallback+"\n"+p.Section, outboundText) {
				return true
			}
		}
		return false
	})
	slackFx.fake.Say(slackID, "U2", inboundText, "")
	waitFor(t, func() string { return "the inbound message in history" }, 20*time.Second, 200*time.Millisecond, func() bool {
		req, err := http.NewRequest(http.MethodGet, fmt.Sprintf("%s/v1/channels/j9wf-room/messages?after=%v", slackFx.serverURL(), seq), nil)
		if err != nil {
			t.Fatal(err)
		}
		req.Header.Set("Authorization", "Bearer "+jroot)
		resp, err := (&http.Client{Timeout: 5 * time.Second}).Do(req)
		if err != nil {
			return false
		}
		defer func() { _ = resp.Body.Close() }()
		b, _ := io.ReadAll(resp.Body)
		var ms []struct {
			Sender     string `json:"sender"`
			SenderKind string `json:"sender_kind"`
			Content    string `json:"content"`
		}
		if resp.StatusCode != http.StatusOK || json.Unmarshal(b, &ms) != nil {
			return false
		}
		for _, m := range ms {
			if m.Content == inboundText && m.Sender == human && m.SenderKind == "human" {
				return true
			}
		}
		return false
	})
	two.run(t, "bridges-inbound-remove", "bridges-inbound-remove", map[string]any{
		"admin_bearer": jroot, "channel": "j9wf-room", "after": seq})

	// Every workflow of the document ran against one server or the other.
	for _, wf := range doc.Workflows {
		if !one.ran[wf.ID] && !two.ran[wf.ID] {
			t.Errorf("workflow %s of api/arazzo.yaml was run against neither fixture", wf.ID)
		}
	}
}
