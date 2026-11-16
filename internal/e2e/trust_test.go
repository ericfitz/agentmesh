//go:build !windows

package e2e_test

// The certificate hierarchy end to end (ADR 0019 section 7), through the built
// binary and servers of their own: first contact and a changed root, and a
// forced renewal followed by a list in one home. They are not part of the
// section 2.4 sequence, so its pinned counts do not move.

import (
	"encoding/json"
	"fmt"
	"net"
	"path/filepath"
	"regexp"
	"strings"
	"syscall"
	"testing"
	"time"
)

// trustServer is a server over its own SQLite file and root, listening on a
// loopback address (so registration is open).
type trustServer struct {
	url    string
	sqlite string
	home   string
	p      *proc
}

// freePort returns a loopback port nothing listens on now.
func freePort(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	_, port, err := net.SplitHostPort(l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	return port
}

// startTrustServer builds a CA with the binary's own commands (bootstrapCA),
// starts `agentmesh server` on 127.0.0.1:port and waits for its listening line.
func startTrustServer(t *testing.T, port string) *trustServer {
	t.Helper()
	dir := t.TempDir()
	s := &trustServer{sqlite: filepath.Join(dir, "server.sqlite"), home: filepath.Join(dir, "home"), url: "http://127.0.0.1:" + port}
	sets, err := bootstrapCA(s.home, filepath.Join(dir, "trust"), s.sqlite)
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"server", "-listen", "127.0.0.1:" + port, "-sqlite", s.sqlite, "-set", "maintenance_interval_seconds=3600"}, sets...)
	s.p = startProc(t, s.home, args...)
	deadline := time.Now().Add(30 * time.Second)
	for !listeningRE.MatchString(s.p.out.String()) {
		if code, done := s.p.exited(20 * time.Millisecond); done {
			t.Fatalf("the server exited %d before listening: %s", code, s.p.errb.String())
		}
		if time.Now().After(deadline) {
			t.Fatalf("no listening line within 30 s: %s", s.p.errb.String())
		}
	}
	return s
}

func (s *trustServer) stop(t *testing.T) {
	t.Helper()
	s.p.signal(syscall.SIGTERM)
	if code, ok := s.p.exited(30 * time.Second); !ok || code != 0 {
		t.Fatalf("the server did not stop cleanly: exit %d, stopped %v, stderr %s", code, ok, s.p.errb.String())
	}
}

var pinRE = regexp.MustCompile(`pinned root (\S+), installation (\S+), for profile lab \((\S+)\)`)

// TestFirstContactEndToEnd: register on a fresh home prints what it pinned on
// standard error; the same profile against a server of another root is refused
// (exit 2, both thumbprints, -accept-new-root) before anything is registered; and
// register -accept-new-root replaces the pin and says so.
func TestFirstContactEndToEnd(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	port := freePort(t)
	a := startTrustServer(t, port)

	r := run(home, "register", "-profile", "lab", "-identity", "pin-pat", "-server", a.url)
	if r.code != 0 {
		t.Fatalf("first contact: exit %d, stdout %q, stderr %q", r.code, r.stdout, r.err)
	}
	m := pinRE.FindStringSubmatch(r.err)
	if m == nil || m[2] != "e2e-installation" || m[3] != a.url {
		t.Fatalf("stderr %q does not say what was pinned", r.err)
	}
	thumbA := m[1]
	if strings.Contains(r.stdout, thumbA) {
		t.Fatalf("the pin went to standard output: %q", r.stdout)
	}
	// A second call on the same root pins nothing new and says nothing about it.
	if r2 := run(home, "login", "-profile", "lab", "-identity", "pin-pat"); r2.code != 0 || strings.Contains(r2.err, "pinned root") {
		t.Fatalf("login on the pinned root: exit %d, stderr %q", r2.code, r2.err)
	}
	a.stop(t)

	// Another server, another root, the same address.
	b := startTrustServer(t, port)
	r = run(home, "register", "-profile", "lab", "-identity", "pin-pat", "-server", b.url)
	if r.code != 2 || r.stdout != "" || !strings.Contains(r.err, thumbA) || !strings.Contains(r.err, "-accept-new-root") {
		t.Fatalf("a changed root: exit %d, stdout %q, stderr %q, want exit 2 naming %s and -accept-new-root", r.code, r.stdout, r.err, thumbA)
	}
	if got := run(home, "login", "-profile", "lab", "-identity", "pin-pat"); got.code != 2 {
		t.Fatalf("login against the changed root: exit %d, stderr %q, want 2", got.code, got.err)
	}

	r = run(home, "register", "-profile", "lab", "-identity", "pin-pat", "-server", b.url, "-accept-new-root")
	if r.code != 0 || !strings.Contains(r.err, "replaced pinned root "+thumbA+", ") || !strings.Contains(r.err, ", with root ") {
		t.Fatalf("-accept-new-root: exit %d, stdout %q, stderr %q", r.code, r.stdout, r.err)
	}
	if got := run(home, "login", "-profile", "lab", "-identity", "pin-pat"); got.code != 0 {
		t.Fatalf("login after accepting the new root: exit %d, stderr %q", got.code, got.err)
	}
}

// TestRotateThenList is Review Focus 1: a forced renewal revokes the caller's
// own former leaf, so the bearer the home cached is signed by a leaf that is now
// revoked; the list that follows in the same home must still succeed and show
// the leaf the rotation made current.
func TestRotateThenList(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	s := startTrustServer(t, freePort(t))
	mustRun(t, home, "register", "-profile", "lab", "-identity", "rot-admin", "-server", s.url)
	mustRun(t, s.home, "server", "admin", "-sqlite", s.sqlite, "admins", "add", "-identity", "rot-admin")
	mustRun(t, home, "login", "-profile", "lab", "-identity", "rot-admin")

	type key struct {
		Thumbprint string `json:"thumbprint"`
		State      string `json:"state"`
	}
	var rot struct {
		Current key `json:"current"`
		Revoked []struct {
			Thumbprint string `json:"thumbprint"`
		} `json:"revoked"`
	}
	r := mustRun(t, home, "signing-keys", "rotate", "-profile", "lab", "-identity", "rot-admin")
	if err := json.Unmarshal([]byte(r.stdout), &rot); err != nil || rot.Current.Thumbprint == "" || len(rot.Revoked) != 1 {
		t.Fatalf("rotate output %q (%v), want a current leaf and the one former leaf revoked", r.stdout, err)
	}
	if rot.Revoked[0].Thumbprint == rot.Current.Thumbprint {
		t.Fatal("the rotation revoked its own new leaf")
	}

	r = mustRun(t, home, "signing-keys", "list", "-profile", "lab", "-identity", "rot-admin")
	var list struct {
		Keys []key `json:"keys"`
	}
	if err := json.Unmarshal([]byte(r.stdout), &list); err != nil || len(list.Keys) == 0 {
		t.Fatalf("list output %q (%v)", r.stdout, err)
	}
	if list.Keys[0].Thumbprint != rot.Current.Thumbprint {
		t.Fatalf("the list's first leaf %s is not the rotation's current %s", list.Keys[0].Thumbprint, rot.Current.Thumbprint)
	}
	for _, k := range list.Keys[1:] {
		if k.Thumbprint == rot.Current.Thumbprint {
			t.Fatalf("the current leaf is listed twice: %s", fmt.Sprint(list.Keys))
		}
	}
}
