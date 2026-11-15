package cli

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/auth/keys"
	"github.com/ericfitz/agentmesh/internal/client"
	"github.com/ericfitz/agentmesh/internal/credential"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/profile"
	"github.com/ericfitz/agentmesh/internal/testkit"
	"github.com/ericfitz/agentmesh/internal/trust"
)

// pathCounter counts the requests that pass through it, by path.
type pathCounter struct {
	mu    sync.Mutex
	paths map[string]int
}

func (c *pathCounter) RoundTrip(r *http.Request) (*http.Response, error) {
	c.mu.Lock()
	if c.paths == nil {
		c.paths = map[string]int{}
	}
	c.paths[r.URL.Path]++
	c.mu.Unlock()
	return http.DefaultTransport.RoundTrip(r)
}

func (c *pathCounter) count(path string) int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.paths[path]
}

// TestOneShotCallsDiscoverOnce: a one-shot command opens one Bus, which is one
// discover request (Ruling 24).
func TestOneShotCallsDiscoverOnce(t *testing.T) {
	ctx := context.Background()
	e := newTestEnv(t)
	base := startServer(t, filepath.Join(t.TempDir(), "srv.sqlite"))
	var out, errb testkit.LockedBuffer
	if code := RunRegister(ctx, []string{"-profile", "lab", "-server", base, "-identity", "pat"}, e.Environ, nil, &out, &errb); code != 0 {
		t.Fatalf("register: %d %q", code, errb.String())
	}
	rt := &pathCounter{}
	prev := testClientOptions
	testClientOptions = func(o *client.Options) { prev(o); o.HTTP = &http.Client{Transport: rt} }
	t.Cleanup(func() { testClientOptions = prev })

	var out2, err2 testkit.LockedBuffer
	if code := RunChannels(ctx, []string{"list", "-profile", "lab", "-identity", "pat"}, e.Environ, strings.NewReader(""), &out2, &err2); code != 0 {
		t.Fatalf("channels list: %d %q", code, err2.String())
	}
	if n := rt.count("/v1/discover"); n != 1 {
		t.Fatalf("%d discover requests, want 1", n)
	}
	if err2.String() != "" {
		t.Fatalf("stderr %q: the pin was made by register, so a later command says nothing", err2.String())
	}
}

// wakeServer is a server whose watch answers a trust wake at once while the
// trust number the client sends differs from its own, and otherwise holds the
// watch until the client gives up. It serves discover with the trust bundle,
// the token exchange and nothing else.
type wakeServer struct {
	*httptest.Server
	number  atomic.Int64
	watches atomic.Int32
	// discovers counts discover requests; mode 1 answers them 503, mode 2 with
	// another root (a renewal under a different root).
	discovers atomic.Int32
	mode      atomic.Int32
}

func newWakeServer(t *testing.T) *wakeServer {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	root, err := pki.NewRoot(k, "test root", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	k2, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherRoot, err := pki.NewRoot(k2, "other root", now.Add(-time.Hour), now.Add(24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	w := &wakeServer{}
	w.number.Store(1)
	var srv *httptest.Server
	srv = httptest.NewServer(http.HandlerFunc(func(rw http.ResponseWriter, r *http.Request) {
		rw.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/v1/discover":
			w.discovers.Add(1)
			der := root.Raw
			switch w.mode.Load() {
			case 1:
				rw.WriteHeader(http.StatusServiceUnavailable)
				return
			case 2:
				der = otherRoot.Raw
			}
			_ = json.NewEncoder(rw).Encode(map[string]any{"protocol_version": "1.0.0", "trust": map[string]any{
				"trust_number": w.number.Load(), "intermediates": []string{}, "leaf_crls": []string{},
				"root": der, "installation": "test-installation"}})
		case r.URL.Path == "/.well-known/oauth-authorization-server":
			_ = json.NewEncoder(rw).Encode(map[string]string{"issuer": srv.URL, "token_endpoint": srv.URL + "/v1/auth/token", "jwks_uri": srv.URL + "/jwks"})
		case r.URL.Path == "/v1/auth/token":
			_ = json.NewEncoder(rw).Encode(map[string]any{"access_token": "t", "token_type": "Bearer", "expires_in": 3600})
		case strings.HasSuffix(r.URL.Path, "/watch"):
			w.watches.Add(1)
			held, err := strconv.ParseInt(r.URL.Query().Get("trust_number"), 10, 64)
			if err != nil || held != w.number.Load() {
				_ = json.NewEncoder(rw).Encode(map[string]any{"seq": 0, "count": 0, "channels": []string{}, "trust_number": w.number.Load()})
				return
			}
			<-r.Context().Done()
		default:
			rw.WriteHeader(http.StatusNotFound)
		}
	}))
	t.Cleanup(srv.Close)
	w.Server = srv
	return w
}

// wakeConn opens a server profile on w with the trust pinned at number 1, then
// moves the server to number 2.
func wakeConn(t *testing.T, e *testEnv, w *wakeServer) *client.Conn {
	t.Helper()
	e.writeProfile(t, profile.Profile{Name: "lab", Mode: profile.ModeServer, Server: w.URL})
	key, err := keys.Generate(keys.EdDSA)
	if err != nil {
		t.Fatal(err)
	}
	if err := (credential.Store{Dir: profile.CredentialDir(e.ConfigDir, "lab")}).Save("pat", key); err != nil {
		t.Fatal(err)
	}
	c := e.conn(t, "pat", func(o *client.Options) { o.Profile = "lab" })
	w.number.Store(2)
	return c
}

func heldNumber(t *testing.T, e *testEnv) int64 {
	t.Helper()
	n, ok, err := trust.Store{Dir: trust.Dir(e.ConfigDir, "lab")}.TrustNumber()
	if err != nil || !ok {
		t.Fatalf("no trust number held: %v %v", ok, err)
	}
	return n
}

// TestTrustWakeDoesNotSpinParkedWait: a parked wait drops every wake and
// re-arms; the layer brings the bundle on the first trust wake, so the next
// Watch carries the new number and the server holds it.
func TestTrustWakeDoesNotSpinParkedWait(t *testing.T) {
	e := newTestEnv(t)
	w := newWakeServer(t)
	c := wakeConn(t, e, w)
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	mf := &wakeFilter{parked: func() bool { return true }}
	var out testkit.LockedBuffer
	err := waitOnce(ctx, c.Bus, mf, "s1", false, 0, &out)
	if err == nil || out.String() != "" {
		t.Fatalf("waitOnce: %v, stdout %q", err, out.String())
	}
	if n := w.watches.Load(); n > 2 {
		t.Fatalf("%d watch calls, want at most 2", n)
	}
	if got := heldNumber(t, e); got != 2 {
		t.Fatalf("held number %d, want 2", got)
	}
}

func TestTrustWakeDoesNotSpinWatchLoop(t *testing.T) {
	e := newTestEnv(t)
	w := newWakeServer(t)
	c := wakeConn(t, e, w)
	ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
	defer cancel()
	var out testkit.LockedBuffer
	if _, err := watchLoop(ctx, c.Bus, &wakeFilter{}, "s1", "pat", 0, false, &out); err == nil {
		t.Fatal("watchLoop returned nil")
	}
	if n := w.watches.Load(); n > 2 {
		t.Fatalf("%d watch calls, want at most 2", n)
	}
	if got := heldNumber(t, e); got != 2 {
		t.Fatalf("held number %d, want 2", got)
	}
}

func TestGatedNotice(t *testing.T) {
	var b bytes.Buffer
	notice, up := gatedNotice(&b)
	notice("before")
	up()
	notice("after")
	if got := b.String(); got != "agentmesh: before\n" {
		t.Fatalf("stderr %q", got)
	}
}

// A refusal of the trust step leaves no pending credential file behind.
func TestRegisterRefusalLeavesNoPendingKey(t *testing.T) {
	ctx := context.Background()
	e := newTestEnv(t)
	base := startServer(t, filepath.Join(t.TempDir(), "srv.sqlite"))
	var out, errb testkit.LockedBuffer
	code := RunRegister(ctx, []string{"-profile", "lab", "-server", base, "-identity", "pat", "-root-thumbprint", strings.Repeat("A", 43)}, e.Environ, nil, &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "expects root") {
		t.Fatalf("register: %d %q", code, errb.String())
	}
	cs := credential.Store{Dir: profile.CredentialDir(e.ConfigDir, "lab")}
	if _, _, ok, err := cs.LoadPending("pat"); err != nil || ok {
		t.Fatalf("pending key left: %v %v", ok, err)
	}
	if cs.Exists("pat") {
		t.Fatal("credential left")
	}
}

func trustLogLines(t *testing.T, e *testEnv) int {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(e.DataDir, "logs", "trust.log"))
	if err != nil {
		return 0
	}
	return strings.Count(string(b), "\n")
}

// A refresh that fails after a trust wake (discover answers 503, or answers
// another root) must not become a request loop: the next watch sends the
// wake's number in memory, the failure is said once, and the stored number
// does not change.
func TestFailedRefreshDoesNotSpin(t *testing.T) {
	for _, tc := range []struct {
		name string
		mode int32
	}{{"discover fails", 1}, {"another root", 2}} {
		for _, loop := range []string{"parked wait", "watch loop"} {
			t.Run(tc.name+"/"+loop, func(t *testing.T) {
				e := newTestEnv(t)
				w := newWakeServer(t)
				c := wakeConn(t, e, w)
				w.mode.Store(tc.mode)
				base := w.discovers.Load()
				ctx, cancel := context.WithTimeout(context.Background(), 600*time.Millisecond)
				defer cancel()
				var out testkit.LockedBuffer
				var err error
				if loop == "parked wait" {
					err = waitOnce(ctx, c.Bus, &wakeFilter{parked: func() bool { return true }}, "s1", false, 0, &out)
				} else {
					_, err = watchLoop(ctx, c.Bus, &wakeFilter{}, "s1", "pat", 0, false, &out)
				}
				if err == nil {
					t.Fatal("returned nil")
				}
				if n := w.watches.Load(); n > 3 {
					t.Fatalf("%d watch calls, want a bounded number", n)
				}
				if n := w.discovers.Load() - base; n > 1 {
					t.Fatalf("%d discover calls after the wake, want at most 1", n)
				}
				if n := trustLogLines(t, e); n != 1 {
					t.Fatalf("%d trust.log lines, want 1", n)
				}
				if got := heldNumber(t, e); got != 1 {
					t.Fatalf("stored number %d, want 1 (unchanged)", got)
				}
			})
		}
	}
}
