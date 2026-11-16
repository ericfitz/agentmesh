//go:build !windows

package e2e_test

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/respcheck"
	"github.com/ericfitz/agentmesh/internal/server/cmd"
	"github.com/ericfitz/agentmesh/internal/slackapi"
	"github.com/ericfitz/agentmesh/internal/slackapi/slackfake"
	"github.com/ericfitz/agentmesh/internal/testkit"
)

// slackFx is fixture 2 (issue #32, Eric's decision 4): the server wiring runs
// in this process through cmd.RunWith with the Slack fake in Config.Slack, so
// the bridges journey runs against a live bridge. The binary's main calls
// cmd.Run; nothing but Go code selects the fake. Its requests cross the same
// validating proxy as fixture 1's (one checker, one violation tally). The
// slackFx variable is declared beside fx in e2e_test.go.
type slackFixture struct {
	root, sqlite, home string
	fake               *slackfake.Fake
	proxy              *httptest.Server
	proxyH             atomic.Pointer[http.Handler]
	cancel             context.CancelFunc
	done               chan struct{}
	code               int
	out, errb          *testkit.LockedBuffer
}

func (f *slackFixture) serverURL() string { return f.proxy.URL }

func startSlackFixture(root string, check *respcheck.Checker, add func(error)) (*slackFixture, error) {
	f := &slackFixture{root: root, sqlite: filepath.Join(root, "slack.sqlite"), home: filepath.Join(root, "home-slack"),
		fake: slackfake.New(slackapi.Self{TeamID: "T1", UserID: "UBOT", BotID: "B1"}), // the team id: an empty one makes every user another workspace's
		done: make(chan struct{}), out: &testkit.LockedBuffer{}, errb: &testkit.LockedBuffer{}}
	if err := os.MkdirAll(f.home, 0o700); err != nil {
		return nil, err
	}
	f.proxy = httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := f.proxyH.Load()
		if h == nil {
			http.Error(w, "the server is not listening yet", http.StatusServiceUnavailable)
			return
		}
		(*h).ServeHTTP(w, r)
	}))
	f.proxy.Start()
	ctx, cancel := context.WithCancel(context.Background())
	f.cancel = cancel
	ready := make(chan net.Addr, 1)
	trust, err := bootstrapCA(f.home, filepath.Join(root, "slack-trust"), f.sqlite)
	if err != nil {
		cancel()
		return f, err
	}
	go func() {
		f.code = cmd.RunWith(ctx, append([]string{"-listen", "127.0.0.1:0", "-registration", "enrollment", "-sqlite", f.sqlite,
			"-set", "session_retention_hours=1", "-set", "issuer=" + f.proxy.URL}, trust...), nil, f.out, f.errb,
			func(ctx context.Context, c cmd.Config) error {
				c.Slack = f.fake
				c.SlackCfg.PostInterval = 100 * time.Millisecond
				orig := c.Ready
				c.Ready = func(a net.Addr) {
					ready <- a
					if orig != nil {
						orig(a)
					}
				}
				return cmd.Serve(ctx, c)
			})
		close(f.done)
	}()
	select {
	case a := <-ready:
		h := check.Proxy(&url.URL{Scheme: "http", Host: a.String()}, add)
		f.proxyH.Store(&h)
	case <-f.done:
		return f, fmt.Errorf("the in-process server exited %d before listening: %s", f.code, f.errb.String())
	case <-time.After(30 * time.Second):
		return f, errors.New("the in-process server was not listening within 30 s")
	}
	return f, nil
}

// token creates an enrollment token with the host command (a separate process
// over the same SQLite file).
func (f *slackFixture) token(t testing.TB) string {
	t.Helper()
	r := mustRun(t, f.home, "server", "admin", "-sqlite", f.sqlite, "enrollment", "create")
	m := tokenRE.FindStringSubmatch(r.stdout)
	if m == nil {
		t.Fatalf("enrollment create printed %q", r.stdout)
	}
	return m[1]
}

// stop cancels the server and returns Run's exit code (-1: it did not return
// in 70 s; Serve's shutdown is bounded at 60 s). It is safe to call twice.
func (f *slackFixture) stop() int {
	defer f.proxy.Close()
	f.cancel()
	select {
	case <-f.done:
		return f.code
	case <-time.After(70 * time.Second):
		return -1
	}
}

func waitFor(t testing.TB, what func() string, d, every time.Duration, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(d)
	for !ok() {
		if time.Now().After(deadline) {
			t.Fatalf("%s: not within %s", what(), d)
		}
		time.Sleep(every)
	}
}

// TestSlackBridgeFixture proves fixture 2 without an Arazzo document: a bridge
// goes live over the fake, a message crosses each way, removal archives the
// Slack channel, and fixture 1 (no Slack) still answers unavailable.
func TestSlackBridgeFixture(t *testing.T) {
	f := slackFx
	ctx := context.Background()
	cli := func(args ...string) result {
		return run(f.home, append(args, "-profile", "lab", "-identity", "root")...)
	}
	mustCli := func(args ...string) result {
		t.Helper()
		r := cli(args...)
		if r.code != 0 {
			t.Fatalf("agentmesh %s: exit %d, stdout %q, stderr %q", strings.Join(args, " "), r.code, r.stdout, r.err)
		}
		return r
	}

	// 1. Register an administrator and create the human.
	mustRun(t, f.home, "register", "-profile", "lab", "-identity", "root", "-server", f.serverURL(), "-enrollment-token", f.token(t))
	mustRun(t, f.home, "server", "admin", "-sqlite", f.sqlite, "admins", "add", "-identity", "root")
	hr := mustRun(t, f.home, "server", "admin", "-sqlite", f.sqlite, "create-human", "ann@example.test")
	human, ok := strings.CutSuffix(strings.TrimSpace(hr.stdout), " created")
	if !ok || human == "" {
		t.Fatalf("create-human printed %q", hr.stdout)
	}

	// 2. An open scope and a channel in it with a named-only ACL.
	mustCli("scopes", "create", "j9fx")
	acl := fmt.Sprintf(`[{"identity":"root","permissions":["read","write"]},{"identity":%q,"permissions":["read","write"]}]`, human)
	mustCli("channels", "create", "-scope", "j9fx", "-acl", acl, "j9fx-room")

	// 3. The Slack user the invite finds.
	f.fake.AddUser(slackapi.User{ID: "U1", TeamID: "T1", Email: "ann@example.test", DisplayName: "Ann"})

	// 4. Create the bridge.
	var created struct {
		State          string `json:"state"`
		SlackChannelID string `json:"slack_channel_id"`
		NotInvited     []any  `json:"not_invited"`
	}
	decode(t, mustCli("bridges", "create", "-slack-name", "j9fx-room", "j9fx-room").stdout, &created)
	info, err := f.fake.FindPrivateChannel(ctx, "j9fx-room")
	if err != nil {
		t.Fatalf("FindPrivateChannel: %v", err)
	}
	id := created.SlackChannelID
	if created.State != "live" || id == "" || id != info.ID || len(created.NotInvited) != 0 {
		t.Fatalf("bridges create = %+v, fake channel %q", created, info.ID)
	}
	if n := f.fake.Calls("CreatePrivateChannel"); n != 1 {
		t.Errorf("CreatePrivateChannel calls = %d, want 1", n)
	}
	if ch, _ := f.fake.Channel(id); !slices.Contains(ch.Members, "U1") {
		t.Errorf("channel members %v lack U1", ch.Members)
	}

	// 5. List and get.
	var list []struct {
		Channel string `json:"channel"`
	}
	decode(t, mustCli("bridges", "list").stdout, &list)
	if len(list) != 1 || list[0].Channel != "j9fx-room" {
		t.Fatalf("bridges list = %+v", list)
	}
	var got struct {
		State string `json:"state"`
	}
	decode(t, mustCli("bridges", "get", "j9fx-room").stdout, &got)
	if got.State != "live" {
		t.Fatalf("bridges get state = %q, want live", got.State)
	}

	// 6. Outbound: the bridge decorates the text, so Contains.
	mustCli("send", "j9fx-room", "hello slack")
	waitFor(t, func() string {
		return fmt.Sprintf("an outbound post containing 'hello slack' (fake Calls: Post=%d, Members=%d)", f.fake.Calls("Post"), f.fake.Calls("Members"))
	}, 20*time.Second, 100*time.Millisecond, func() bool {
		ch, _ := f.fake.Channel(id)
		for _, p := range ch.Posts {
			if strings.Contains(p.Fallback+"\n"+p.Section, "hello slack") {
				return true
			}
		}
		return false
	})

	// 7. Inbound: the Slack user's message lands as the human's.
	f.fake.Say(id, "U1", "hello bus", "")
	type msg struct {
		Sender     string `json:"sender"`
		SenderKind string `json:"sender_kind"`
		Content    string `json:"content"`
	}
	waitFor(t, func() string {
		return fmt.Sprintf("an inbound message from the human in history (fake Calls: RunSocket=%d, UserInfo=%d, History=%d)", f.fake.Calls("RunSocket"), f.fake.Calls("UserInfo"), f.fake.Calls("History"))
	}, 20*time.Second, 200*time.Millisecond, func() bool {
		r := cli("history", "j9fx-room")
		if r.code != 0 {
			return false
		}
		var ms []msg
		decode(t, r.stdout, &ms)
		return slices.ContainsFunc(ms, func(m msg) bool {
			return m.Sender == human && m.SenderKind == "human" && m.Content == "hello bus"
		})
	})

	// 8. Remove: the Slack channel is archived and the row is deleted
	// (archive.go Remove: "deletes the bridge row"), so get is not_found.
	mustCli("bridges", "remove", "j9fx-room")
	if ch, _ := f.fake.Channel(id); !ch.Archived {
		t.Errorf("the Slack channel is not archived after bridges remove")
	}
	if r := cli("bridges", "get", "j9fx-room"); r.code != 1 || !strings.Contains(r.err, "agentmesh: not_found:") || !strings.Contains(r.err, "has no bridge") {
		t.Errorf("bridges get after remove: exit %d, stderr %q; want exit 1, not_found, 'has no bridge'", r.code, r.err)
	}

	// 9. The control: fixture 1 has no Slack, so the same call is unavailable.
	r := run(fx.homeA, "bridges", "list", "-profile", "lab", "-identity", "pat")
	if r.code != 1 || !strings.Contains(r.err, "agentmesh: unavailable:") || !strings.Contains(r.err, "the Slack bridge is not configured") {
		t.Errorf("fixture 1 bridges list: exit %d, stderr %q; want exit 1, unavailable, 'the Slack bridge is not configured'", r.code, r.err)
	}
	if n := f.fake.Calls("AuthTest"); n < 1 {
		t.Errorf("AuthTest calls = %d, want at least 1 (the bridge started over the fake)", n)
	}
}
