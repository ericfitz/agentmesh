package cli

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/auth/keys"
	"github.com/ericfitz/agentmesh/internal/credential"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/profile"
	"github.com/ericfitz/agentmesh/internal/testkit"
	"github.com/ericfitz/agentmesh/internal/trust"
)

// rootServer answers discover with a trust bundle for the current root and
// counts every other request (answered 503). swap moves it to the other root.
type rootServer struct {
	*httptest.Server
	mu     sync.Mutex
	thumbs [2]string
	ders   [2][]byte
	cur    int
	others int
}

func newRootServer(t *testing.T) *rootServer {
	t.Helper()
	s := &rootServer{}
	for i := range s.ders {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatal(err)
		}
		now := time.Now()
		c, err := pki.NewRoot(k, "root "+string(rune('A'+i)), now.Add(-time.Hour), now.Add(24*time.Hour))
		if err != nil {
			t.Fatal(err)
		}
		s.ders[i], s.thumbs[i] = c.Raw, pki.Thumbprint(c.Raw)
	}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.mu.Lock()
		defer s.mu.Unlock()
		if r.URL.Path != "/v1/discover" {
			s.others++
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{"protocol_version": "1.0.0", "server_version": "test", "trust": map[string]any{
			"trust_number": 1, "intermediates": []string{}, "leaf_crls": []string{},
			"root": s.ders[s.cur], "installation": "test-installation"}})
	}))
	t.Cleanup(s.Close)
	return s
}

func (s *rootServer) swap() {
	s.mu.Lock()
	s.cur = 1
	s.mu.Unlock()
}

func (s *rootServer) otherRequests() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.others
}

func pinnedThumb(t *testing.T, e *testEnv) string {
	t.Helper()
	p, ok, err := trust.Store{Dir: trust.Dir(e.ConfigDir, "lab")}.Pinned()
	if err != nil || !ok {
		t.Fatalf("no pin: %v %v", ok, err)
	}
	return p.Thumbprint
}

// TestRegisterPinsBeforeRegistering: first contact says what it pinned, and a
// server whose root is not the pinned one is refused before any registration
// request leaves.
func TestRegisterPinsBeforeRegistering(t *testing.T) {
	ctx := context.Background()
	e := newTestEnv(t)
	s := newRootServer(t)
	args := []string{"-profile", "lab", "-server", s.URL, "-identity", "pat"}
	var out, errb testkit.LockedBuffer
	RunRegister(ctx, args, e.Environ, nil, &out, &errb) // pins root A; the registration itself gets a 503
	want := "pinned root " + s.thumbs[0] + ", installation test-installation, for profile lab (" + s.URL + ")"
	if !strings.Contains(errb.String(), want) {
		t.Fatalf("first contact stderr %q lacks %q", errb.String(), want)
	}
	if out.String() != "" {
		t.Fatalf("stdout %q", out.String())
	}
	s.swap()
	before := s.otherRequests()
	var out2, err2 testkit.LockedBuffer
	code := RunRegister(ctx, args, e.Environ, nil, &out2, &err2)
	if code != 2 || !strings.Contains(err2.String(), s.thumbs[0]) || !strings.Contains(err2.String(), s.thumbs[1]) {
		t.Fatalf("register: %d %q, want exit 2 naming both thumbprints", code, err2.String())
	}
	if got := s.otherRequests(); got != before {
		t.Fatalf("%d registration requests reached the server after the refusal", got-before)
	}
}

// TestAcceptNewRootFlag: each command that takes the flag replaces the pin and
// prints the old and the new root; without it each is exit 2 and the pin stays.
func TestAcceptNewRootFlag(t *testing.T) {
	ctx := context.Background()
	cases := map[string]struct {
		setup func(t *testing.T, e *testEnv, s *rootServer)
		run   func(e *testEnv, s *rootServer, extra ...string) (int, string, string)
	}{
		"register": {
			run: func(e *testEnv, s *rootServer, extra ...string) (int, string, string) {
				var out, errb testkit.LockedBuffer
				a := append([]string{"-profile", "lab", "-server", s.URL, "-identity", "pat"}, extra...)
				return RunRegister(ctx, a, e.Environ, nil, &out, &errb), out.String(), errb.String()
			},
		},
		"login": {
			setup: func(t *testing.T, e *testEnv, s *rootServer) {
				e.writeProfile(t, profile.Profile{Name: "lab", Mode: profile.ModeServer, Server: s.URL, Identity: "pat"})
				key, err := keys.Generate(keys.EdDSA)
				if err != nil {
					t.Fatal(err)
				}
				if err := (credential.Store{Dir: profile.CredentialDir(e.ConfigDir, "lab")}).Save("pat", key); err != nil {
					t.Fatal(err)
				}
			},
			run: func(e *testEnv, s *rootServer, extra ...string) (int, string, string) {
				var out, errb testkit.LockedBuffer
				a := append([]string{"-profile", "lab"}, extra...)
				return RunLogin(ctx, a, e.Environ, nil, &out, &errb), out.String(), errb.String()
			},
		},
		"login -human": {
			setup: func(t *testing.T, e *testEnv, s *rootServer) {
				e.writeProfile(t, profile.Profile{Name: "lab", Mode: profile.ModeServer, Server: s.URL,
					OIDC: &profile.OIDC{Issuer: "http://127.0.0.1:1", ClientID: "cid", RedirectPort: 1, Scopes: []string{"openid"}}})
			},
			run: func(e *testEnv, s *rootServer, extra ...string) (int, string, string) {
				var out, errb testkit.LockedBuffer
				a := append([]string{"-human", "-profile", "lab"}, extra...)
				return RunLogin(ctx, a, e.Environ, nil, &out, &errb), out.String(), errb.String()
			},
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			e := newTestEnv(t)
			s := newRootServer(t)
			if tc.setup != nil {
				tc.setup(t, e, s)
			}
			if code, _, errs := tc.run(e, s); code == 2 {
				t.Fatalf("first contact: exit 2, %q", errs)
			}
			if got := pinnedThumb(t, e); got != s.thumbs[0] {
				t.Fatalf("pin %s, want %s", got, s.thumbs[0])
			}
			s.swap()
			code, out, errs := tc.run(e, s)
			if code != 2 || out != "" || !strings.Contains(errs, s.thumbs[0]) || !strings.Contains(errs, s.thumbs[1]) || !strings.Contains(errs, "-accept-new-root") {
				t.Fatalf("without the flag: %d, stdout %q, stderr %q", code, out, errs)
			}
			if got := pinnedThumb(t, e); got != s.thumbs[0] {
				t.Fatalf("the pin changed without the flag: %s", got)
			}
			code, out, errs = tc.run(e, s, "-accept-new-root")
			if code == 2 || strings.Contains(out, "replaced") || !strings.Contains(errs, "replaced pinned root "+s.thumbs[0]) || !strings.Contains(errs, "with root "+s.thumbs[1]) {
				t.Fatalf("with the flag: %d, stdout %q, stderr %q", code, out, errs)
			}
			if got := pinnedThumb(t, e); got != s.thumbs[1] {
				t.Fatalf("pin %s after the flag, want %s", got, s.thumbs[1])
			}
		})
	}
}

// TestAcceptNewRootElsewhere: no other command takes the flag.
func TestAcceptNewRootElsewhere(t *testing.T) {
	e := newTestEnv(t)
	var out, errb testkit.LockedBuffer
	code := RunHistory(context.Background(), []string{"-accept-new-root", "general"}, e.Environ, strings.NewReader(""), &out, &errb)
	if code != 2 || !strings.Contains(errb.String(), "accept-new-root") {
		t.Fatalf("history: %d %q", code, errb.String())
	}
}
