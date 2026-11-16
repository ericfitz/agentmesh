package mcpcli

import (
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

	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/trust"
)

// rootServer answers discover (and health) with a trust bundle for the
// current root and counts every other request (answered 503). swap moves it to
// the other root.
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
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/v1/discover":
			_ = json.NewEncoder(w).Encode(map[string]any{"protocol_version": "1.0.0", "server_version": "test", "trust": map[string]any{
				"trust_number": 1, "intermediates": []string{}, "leaf_crls": []string{},
				"root": s.ders[s.cur], "installation": "test-installation"}})
		case "/v1/health":
			_ = json.NewEncoder(w).Encode(map[string]any{"status": "ok", "tier": "probe", "protocol_version": "1.0.0"})
		default:
			s.others++
			w.WriteHeader(http.StatusServiceUnavailable)
		}
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

func pinnedThumb(t *testing.T, configDir string) string {
	t.Helper()
	p, ok, err := trust.Store{Dir: trust.Dir(configDir, "lab")}.Pinned()
	if err != nil || !ok {
		t.Fatalf("no pin: %v %v", ok, err)
	}
	return p.Thumbprint
}

// TestRegisterPinsFirst: first contact says what it pinned (standard error),
// and a changed root is refused before any registration request leaves.
func TestRegisterPinsFirst(t *testing.T) {
	t.Chdir(t.TempDir())
	environ, configDir := testEnviron(t)
	s := newRootServer(t)
	args := []string{"register", "-profile", "lab", "-server", s.URL, "-identity", "pat"}
	code, out, errs := run(args, environ) // the registration itself gets a 503
	want := "pinned root " + s.thumbs[0] + ", installation test-installation, for profile lab (" + s.URL + ")"
	if code == 0 || out != "" || !strings.Contains(errs, want) {
		t.Fatalf("first contact: %d, stdout %q, stderr %q, want %q", code, out, errs, want)
	}
	s.swap()
	before := s.otherRequests()
	code, out, errs = run(args, environ)
	if code != 2 || out != "" || !strings.Contains(errs, s.thumbs[0]) || !strings.Contains(errs, s.thumbs[1]) || !strings.Contains(errs, "-accept-new-root") {
		t.Fatalf("changed root: %d, stdout %q, stderr %q", code, out, errs)
	}
	if got := s.otherRequests(); got != before {
		t.Fatalf("%d registration requests reached the server after the refusal", got-before)
	}
	if got := pinnedThumb(t, configDir); got != s.thumbs[0] {
		t.Fatalf("pin %s changed without the flag", got)
	}
}

// TestAcceptNewRootFlag: register and check replace the pin and print the old
// and the new root; without the flag each refuses.
func TestAcceptNewRootFlag(t *testing.T) {
	for _, cmd := range []string{"register", "check"} {
		t.Run(cmd, func(t *testing.T) {
			t.Chdir(t.TempDir())
			environ, configDir := testEnviron(t)
			s := newRootServer(t)
			args := []string{cmd, "-profile", "lab", "-server", s.URL}
			if cmd == "register" {
				args = append(args, "-identity", "pat")
			}
			run(args, environ) // first contact pins root A
			if got := pinnedThumb(t, configDir); got != s.thumbs[0] {
				t.Fatalf("pin %s, want %s", got, s.thumbs[0])
			}
			s.swap()
			code, _, errs := run(args, environ)
			if cmd == "register" && code != 2 {
				t.Fatalf("without the flag: %d %q", code, errs)
			}
			if got := pinnedThumb(t, configDir); got != s.thumbs[0] {
				t.Fatalf("the pin changed without the flag: %s", got)
			}
			code, out, errs := run(append(args, "-accept-new-root"), environ)
			if code == 2 || strings.Contains(out, "replaced") || !strings.Contains(errs, "replaced pinned root "+s.thumbs[0]) || !strings.Contains(errs, "with root "+s.thumbs[1]) {
				t.Fatalf("with the flag: %d, stdout %q, stderr %q", code, out, errs)
			}
			if got := pinnedThumb(t, configDir); got != s.thumbs[1] {
				t.Fatalf("pin %s after the flag, want %s", got, s.thumbs[1])
			}
		})
	}
}

// TestAcceptNewRootElsewhere: serve and config do not take the flag.
func TestAcceptNewRootElsewhere(t *testing.T) {
	environ, _ := testEnviron(t)
	for _, cmd := range []string{"serve", "config"} {
		code, _, errs := run([]string{cmd, "-accept-new-root"}, environ)
		if code != 2 || !strings.Contains(errs, "accept-new-root") {
			t.Errorf("%s: %d %q", cmd, code, errs)
		}
	}
}

// TestCheckReportsMismatch: a root that is not the pinned one is a FAIL of the
// reach step, and its fix line names the flag.
func TestCheckReportsMismatch(t *testing.T) {
	t.Chdir(t.TempDir())
	environ, _ := testEnviron(t)
	s := newRootServer(t)
	args := []string{"check", "-profile", "lab", "-server", s.URL}
	if code, out, errs := run(args, environ); code != 0 || !strings.Contains(errs, "pinned root "+s.thumbs[0]) || !strings.HasPrefix(out, "ok   reach: ") {
		t.Fatalf("first contact: %d, stdout %q, stderr %q", code, out, errs)
	}
	s.swap()
	code, out, errs := run(args, environ)
	got := lines(out)
	if code != 1 || len(got) != 1 || !strings.HasPrefix(got[0], "FAIL reach: ") || !strings.Contains(got[0], s.thumbs[0]) || !strings.Contains(got[0], s.thumbs[1]) ||
		!strings.Contains(got[0], "fix: ") || !strings.Contains(got[0][strings.Index(got[0], "fix: "):], "check -profile lab -server "+s.URL+" -accept-new-root") ||
		!strings.Contains(errs, "check: reach failed") {
		t.Fatalf("mismatch: %d, stdout %q, stderr %q", code, out, errs)
	}
}
