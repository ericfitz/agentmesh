package client

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/pki"
	"github.com/ericfitz/agentmesh/internal/profile"
	"github.com/ericfitz/agentmesh/internal/testkit"
	"github.com/ericfitz/agentmesh/internal/trust"
)

// notices records Options.Notice lines.
type notices struct {
	mu    sync.Mutex
	lines []string
}

func (n *notices) add(l string) {
	n.mu.Lock()
	n.lines = append(n.lines, l)
	n.mu.Unlock()
}

func (n *notices) all() []string {
	n.mu.Lock()
	defer n.mu.Unlock()
	return append([]string(nil), n.lines...)
}

// testRoot is a root made through internal/pki, never a committed file.
type testRoot struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newTestRoot(t *testing.T, name string) testRoot {
	t.Helper()
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	c, err := pki.NewRoot(k, name, now.Add(-time.Hour), now.Add(10*365*24*time.Hour))
	if err != nil {
		t.Fatal(err)
	}
	return testRoot{c, k}
}

func (r testRoot) thumb() string { return pki.Thumbprint(r.cert.Raw) }

func (r testRoot) crl(t *testing.T, number int64) []byte {
	t.Helper()
	der, err := pki.CreateCRL(r.cert, r.key, number, time.Now(), nil)
	if err != nil {
		t.Fatal(err)
	}
	return der
}

// fakeDiscover answers GET /v1/discover from fields a test changes; every other
// path is counted and answered 503.
type fakeDiscover struct {
	*httptest.Server
	mu      sync.Mutex
	root    testRoot
	install string
	number  int64
	noTrust bool
	paths   map[string]int
}

func newFakeDiscover(t *testing.T, root testRoot, install string) *fakeDiscover {
	t.Helper()
	f := &fakeDiscover{root: root, install: install, number: 1, paths: map[string]int{}}
	f.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		f.paths[r.URL.Path]++
		root, install, number, noTrust := f.root, f.install, f.number, f.noTrust
		f.mu.Unlock()
		if r.URL.Path != "/v1/discover" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		doc := map[string]any{"protocol_version": "1.0.0", "server_version": "test"}
		if !noTrust {
			doc["trust"] = map[string]any{
				"trust_number": number, "intermediates": []string{}, "leaf_crls": []string{},
				"root": base64.StdEncoding.EncodeToString(root.cert.Raw), "installation": install,
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(doc)
	}))
	t.Cleanup(f.Close)
	return f
}

func (f *fakeDiscover) set(fn func(f *fakeDiscover)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	fn(f)
}

func (f *fakeDiscover) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.paths[path]
}

func (f *fakeDiscover) otherThanDiscover() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for p, c := range f.paths {
		if p != "/v1/discover" {
			n += c
		}
	}
	return n
}

// trustEnv is a profile "lab" at server with a credential for pat.
func trustEnv(t *testing.T, server string, mod func(*profile.Profile)) *testkit.ProfileEnv {
	t.Helper()
	e := testkit.NewProfileEnv(t)
	p := profile.Profile{Name: "lab", Mode: profile.ModeServer, Server: server}
	if mod != nil {
		mod(&p)
	}
	e.Save(t, profile.Profile{Name: "default", Mode: profile.ModeLocal}, p)
	saveCredential(t, e, "lab", "pat")
	return e
}

func openLab(e *testkit.ProfileEnv, n *notices, mod func(*Options)) (*Conn, error) {
	o := Options{Environ: e.Environ, Cwd: filepath.Join(e.Home, "cwd"), Profile: "lab", Notice: n.add}
	if mod != nil {
		mod(&o)
	}
	return Open(context.Background(), o)
}

func mustOpen(t *testing.T, e *testkit.ProfileEnv, n *notices, mod func(*Options)) *Conn {
	t.Helper()
	c, err := openLab(e, n, mod)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = c.Close() })
	return c
}

func trustStore(e *testkit.ProfileEnv) trust.Store {
	return trust.Store{Dir: trust.Dir(e.Config, "lab")}
}

// snapshot is every file under dir with its bytes, to prove nothing changed.
func snapshot(t *testing.T, dir string) map[string]string {
	t.Helper()
	out := map[string]string{}
	_ = filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil || fi.IsDir() || fi.Name() == ".lock" {
			return nil
		}
		b, _ := os.ReadFile(p)
		out[p] = string(b)
		return nil
	})
	return out
}

func sameSnapshot(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if b[k] != v {
			return false
		}
	}
	return true
}

func isResolveError(err error) bool {
	var re *ResolveError
	return errors.As(err, &re)
}

func TestFirstContactPinsAndSaysSo(t *testing.T) {
	base := startServer(t)
	e := trustEnv(t, base, nil)
	registerServerProfile(t, e, base, "pat")
	var n notices
	mustOpen(t, e, &n, nil)
	pin, ok, err := trustStore(e).Pinned()
	if err != nil || !ok {
		t.Fatalf("no pin after first contact: %v %v", ok, err)
	}
	want := fmt.Sprintf("pinned root %s, installation %s, for profile lab (%s)", pin.Thumbprint, pin.Installation, base)
	if got := n.all(); len(got) != 1 || got[0] != want {
		t.Fatalf("notices %q, want [%q]", got, want)
	}
	if _, ok, _ := trustStore(e).TrustNumber(); !ok {
		t.Fatal("the discover bundle was not applied")
	}
	n2 := &notices{}
	mustOpen(t, e, n2, nil)
	if got := n2.all(); len(got) != 0 {
		t.Fatalf("second Open said %q", got)
	}
}

func TestDifferentRootStops(t *testing.T) {
	rootA, rootB := newTestRoot(t, "root a"), newTestRoot(t, "root b")
	f := newFakeDiscover(t, rootA, "inst-one")
	e := trustEnv(t, f.URL, nil)
	var n notices
	mustOpen(t, e, &n, nil)
	before := snapshot(t, trustStore(e).Dir)

	f.set(func(f *fakeDiscover) { f.root = rootB })
	var n2 notices
	_, err := openLab(e, &n2, nil)
	if err == nil || !isResolveError(err) {
		t.Fatalf("Open under another root: %v", err)
	}
	for _, want := range []string{rootA.thumb(), rootB.thumb(), "-accept-new-root"} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("error %q lacks %q", err, want)
		}
	}
	if !sameSnapshot(before, snapshot(t, trustStore(e).Dir)) {
		t.Fatal("the trust directory changed")
	}

	var n3 notices
	mustOpen(t, e, &n3, func(o *Options) { o.AcceptNewRoot = true })
	got := n3.all()
	if len(got) != 1 || !strings.Contains(got[0], rootA.thumb()) || !strings.Contains(got[0], rootB.thumb()) || !strings.Contains(got[0], "inst-one") {
		t.Fatalf("notices %q: want the old and new thumbprints and names", got)
	}
	if pin, _, _ := trustStore(e).Pinned(); pin.Thumbprint != rootB.thumb() {
		t.Fatalf("pin %s, want %s", pin.Thumbprint, rootB.thumb())
	}
}

func TestDifferentInstallationStops(t *testing.T) {
	root := newTestRoot(t, "root")
	f := newFakeDiscover(t, root, "inst-one")
	e := trustEnv(t, f.URL, nil)
	var n notices
	mustOpen(t, e, &n, nil)
	before := snapshot(t, trustStore(e).Dir)

	f.set(func(f *fakeDiscover) { f.install = "inst-two" })
	_, err := openLab(e, &n, nil)
	if err == nil || !isResolveError(err) || !strings.Contains(err.Error(), "inst-one") || !strings.Contains(err.Error(), "inst-two") || !strings.Contains(err.Error(), "-accept-new-root") {
		t.Fatalf("Open under another installation name: %v", err)
	}
	if !sameSnapshot(before, snapshot(t, trustStore(e).Dir)) {
		t.Fatal("the trust directory changed")
	}
	var n2 notices
	mustOpen(t, e, &n2, func(o *Options) { o.AcceptNewRoot = true })
	if pin, _, _ := trustStore(e).Pinned(); pin.Installation != "inst-two" {
		t.Fatalf("installation %q after -accept-new-root", pin.Installation)
	}
}

func TestExpectedValues(t *testing.T) {
	root := newTestRoot(t, "root")
	other := newTestRoot(t, "other")
	f := newFakeDiscover(t, root, "inst-one")
	for _, tc := range []struct {
		name   string
		mod    func(*profile.Profile)
		accept bool
		ok     bool
	}{
		{"root matches", func(p *profile.Profile) { p.RootThumbprint = root.thumb() }, false, true},
		{"root differs", func(p *profile.Profile) { p.RootThumbprint = other.thumb() }, false, false},
		{"root differs with -accept-new-root", func(p *profile.Profile) { p.RootThumbprint = other.thumb() }, true, false},
		{"installation matches", func(p *profile.Profile) { p.Installation = "inst-one" }, false, true},
		{"installation differs", func(p *profile.Profile) { p.Installation = "inst-two" }, false, false},
		{"installation differs with -accept-new-root", func(p *profile.Profile) { p.Installation = "inst-two" }, true, false},
		{"both match", func(p *profile.Profile) { p.RootThumbprint = root.thumb(); p.Installation = "inst-one" }, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := trustEnv(t, f.URL, tc.mod)
			var n notices
			_, err := openLab(e, &n, func(o *Options) { o.AcceptNewRoot = tc.accept })
			_, pinned, _ := trustStore(e).Pinned()
			switch {
			case tc.ok && (err != nil || !pinned):
				t.Fatalf("err %v, pinned %v", err, pinned)
			case !tc.ok && (err == nil || !isResolveError(err) || pinned):
				t.Fatalf("err %v, pinned %v: want a resolve error and no pin", err, pinned)
			}
		})
	}

	t.Run("a held pin of another root is replaced when the profile expects the new one", func(t *testing.T) {
		e := trustEnv(t, f.URL, nil)
		var n notices
		mustOpen(t, e, &n, nil)
		// The operator now expects the other root, which the server serves.
		e.Save(t, profile.Profile{Name: "default", Mode: profile.ModeLocal},
			profile.Profile{Name: "lab", Mode: profile.ModeServer, Server: f.URL, RootThumbprint: other.thumb()})
		f.set(func(x *fakeDiscover) { x.root = other })
		if _, err := openLab(e, &n, nil); err == nil || !strings.Contains(err.Error(), "expects root") {
			t.Fatalf("held pin disagrees with the profile: %v", err)
		}
		mustOpen(t, e, &n, func(o *Options) { o.AcceptNewRoot = true })
		if pin, _, _ := trustStore(e).Pinned(); pin.Thumbprint != other.thumb() {
			t.Fatalf("pin %s", pin.Thumbprint)
		}
		f.set(func(x *fakeDiscover) { x.root = root })
	})
}

func TestDiscoverWithoutTrust(t *testing.T) {
	root := newTestRoot(t, "root")
	f := newFakeDiscover(t, root, "inst-one")
	f.set(func(f *fakeDiscover) { f.noTrust = true })
	e := trustEnv(t, f.URL, nil)
	var n notices
	_, err := openLab(e, &n, nil)
	want := "the server at " + f.URL + " sent no trust material"
	if err == nil || !isResolveError(err) || !strings.Contains(err.Error(), want) {
		t.Fatalf("no pin: %v, want %q", err, want)
	}

	// With a pin: the same error.
	f.set(func(f *fakeDiscover) { f.noTrust = false })
	mustOpen(t, e, &n, nil)
	f.set(func(f *fakeDiscover) { f.noTrust = true })
	if _, err := openLab(e, &n, nil); err == nil || !isResolveError(err) || !strings.Contains(err.Error(), want) {
		t.Fatalf("with a pin: %v, want %q", err, want)
	}
}

func TestDiscoverUnreachable(t *testing.T) {
	root := newTestRoot(t, "root")
	f := newFakeDiscover(t, root, "inst-one")
	e := trustEnv(t, f.URL, nil)
	var n notices
	mustOpen(t, e, &n, nil)
	f.Close()

	var n2 notices
	c := mustOpen(t, e, &n2, nil)
	if got := n2.all(); len(got) != 1 || !strings.Contains(got[0], "going on with the trust held") {
		t.Fatalf("notices %q", got)
	}
	if _, ok := c.Bus.(*trustBus); !ok {
		t.Fatalf("Bus is %T, want the trust layer", c.Bus)
	}

	// No pin: the error of a call to that server.
	e2 := trustEnv(t, f.URL, nil)
	var n3 notices
	if _, err := openLab(e2, &n3, nil); err == nil || isResolveError(err) || !strings.Contains(err.Error(), "discover") {
		t.Fatalf("no pin: %v", err)
	}
}

func TestInsecureHTTPNotice(t *testing.T) {
	for _, tc := range []struct {
		name, server string
		insecure     bool
		want         bool
	}{
		{"http to a non-loopback host", "http://example.invalid:8420", true, true},
		{"https with the setting on", "https://example.invalid:8420", true, false},
		{"loopback http", "http://127.0.0.1:8420", true, false},
		{"https with the setting off", "https://example.invalid:8420", false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := trustEnv(t, tc.server, func(p *profile.Profile) { p.InsecureHTTP = tc.insecure })
			var n notices
			mustOpen(t, e, &n, func(o *Options) { o.NoDiscover = true })
			want := "profile lab: insecure_http is on; the connection to " + tc.server + " is not protected"
			got := n.all()
			switch {
			case tc.want && (len(got) != 1 || got[0] != want):
				t.Fatalf("notices %q, want [%q]", got, want)
			case !tc.want && len(got) != 0:
				t.Fatalf("notices %q, want none", got)
			}
		})
	}
}

func TestUnwritableTrustDirectory(t *testing.T) {
	root := newTestRoot(t, "root")
	f := newFakeDiscover(t, root, "inst-one")
	e := trustEnv(t, f.URL, nil)
	// A file where the directory "trust" must be: nothing can be created below.
	if err := os.WriteFile(filepath.Join(e.Config, "trust"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	var n notices
	_, err := openLab(e, &n, nil)
	if err == nil || !isResolveError(err) || !strings.Contains(err.Error(), filepath.Join(e.Config, "trust")) {
		t.Fatalf("Open: %v, want an error naming the trust directory", err)
	}
	if c := f.otherThanDiscover(); c != 0 {
		t.Fatalf("%d calls besides discover", c)
	}
}

// capturingRT records the body or query of the trust-carrying requests.
type capturingRT struct {
	mu   sync.Mutex
	open []string
	recv []string
	wtch []string
}

func (c *capturingRT) RoundTrip(r *http.Request) (*http.Response, error) {
	var body []byte
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		r.Body = io.NopCloser(strings.NewReader(string(body)))
	}
	c.mu.Lock()
	switch {
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/sessions"):
		c.open = append(c.open, string(body))
	case r.Method == http.MethodPost && strings.HasSuffix(r.URL.Path, "/receive"):
		c.recv = append(c.recv, string(body))
	case strings.HasSuffix(r.URL.Path, "/watch"):
		c.wtch = append(c.wtch, r.URL.RawQuery)
	}
	c.mu.Unlock()
	return http.DefaultTransport.RoundTrip(r)
}

func TestInBandNumbers(t *testing.T) {
	ctx := context.Background()
	base := startServer(t)
	e := trustEnv(t, base, nil)
	registerServerProfile(t, e, base, "pat")
	rt := &capturingRT{}
	var n notices
	c := mustOpen(t, e, &n, func(o *Options) { o.HTTP = &http.Client{Transport: rt} })
	held, ok, err := trustStore(e).TrustNumber()
	if err != nil || !ok {
		t.Fatalf("no held number after Open: %v %v", ok, err)
	}
	s, err := c.Bus.Open(ctx, bus.OpenSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Bus.Receive(ctx, bus.ReceiveInput{Session: s.ID}); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Bus.Watch(ctx, bus.WatchInput{Session: s.ID, Timeout: time.Second}); err != nil {
		t.Fatal(err)
	}
	want := fmt.Sprintf(`"trust_number":%d`, held)
	rt.mu.Lock()
	defer rt.mu.Unlock()
	if len(rt.open) != 1 || !strings.Contains(rt.open[0], want) {
		t.Fatalf("open bodies %q, want %s", rt.open, want)
	}
	if len(rt.recv) != 1 || !strings.Contains(rt.recv[0], want) {
		t.Fatalf("receive bodies %q, want %s", rt.recv, want)
	}
	if len(rt.wtch) != 1 || !strings.Contains(rt.wtch[0], fmt.Sprintf("trust_number=%d", held)) {
		t.Fatalf("watch queries %q, want trust_number=%d", rt.wtch, held)
	}
	if s.Trust != nil {
		t.Fatalf("the server sent a bundle for a number it holds: %+v", s.Trust)
	}
}

// numberBus is a Bus whose three trust-aware methods behave as a server's do:
// a bundle when the number sent is absent or differs, a wake on a difference.
type numberBus struct {
	bus.Bus
	mu     sync.Mutex
	server int64
	bundle func(n int64) *bus.TrustBundle
	sent   []string // "open 3", "receive none", "watch 3"
}

func (b *numberBus) record(kind string, n *int64) {
	if n == nil {
		b.sent = append(b.sent, kind+" none")
		return
	}
	b.sent = append(b.sent, fmt.Sprintf("%s %d", kind, *n))
}

func (b *numberBus) differs(n *int64) bool { return n == nil || *n != b.server }

func (b *numberBus) Open(_ context.Context, in bus.OpenSessionInput) (bus.Session, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.record("open", in.TrustNumber)
	s := bus.Session{ID: "s1", TrustNumber: &b.server}
	if b.differs(in.TrustNumber) {
		s.Trust = b.bundle(b.server)
	}
	return s, nil
}

func (b *numberBus) Receive(_ context.Context, in bus.ReceiveInput) (bus.ReceiveResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.record("receive", in.TrustNumber)
	r := bus.ReceiveResult{TrustNumber: &b.server}
	if b.differs(in.TrustNumber) {
		r.Trust = b.bundle(b.server)
	}
	return r, nil
}

func (b *numberBus) Watch(_ context.Context, in bus.WatchInput) (bus.WatchResult, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.record("watch", in.TrustNumber)
	if b.differs(in.TrustNumber) {
		return bus.WatchResult{Woke: true, Count: 0, TrustNumber: &b.server}, nil
	}
	return bus.WatchResult{}, nil
}

// pinnedLayer is a trustBus over a numberBus, with a real store pinned to root
// (the discover bundle applied at trust number 1).
func pinnedLayer(t *testing.T, root testRoot, n *notices) (*trustBus, *numberBus, *testkit.ProfileEnv) {
	t.Helper()
	e := testkit.NewProfileEnv(t)
	r := Resolved{Profile: profile.Profile{Name: "lab", Mode: profile.ModeServer, Server: "http://127.0.0.1:1"}, ConfigDir: e.Config, DataDir: e.Data}
	st := trust.Store{Dir: trust.Dir(e.Config, "lab")}
	b := trust.Bundle{TrustNumber: 1, Root: root.cert.Raw, Installation: "inst-one"}
	if _, err := st.Accept(b, trust.Expect{Server: r.Profile.Server}, false); err != nil {
		t.Fatal(err)
	}
	if _, err := st.Apply(b); err != nil {
		t.Fatal(err)
	}
	nb := &numberBus{server: 1, bundle: func(n int64) *bus.TrustBundle { return &bus.TrustBundle{TrustNumber: n} }}
	return &trustBus{Bus: nb, store: st, o: Options{Notice: n.add}, r: r}, nb, e
}

// After a renewal the server's number is new: a waiting watch wakes once, the
// next receive stores the bundle, and the following watch does not wake at once
// (Task 29 reviewer follow-up: never send a stale number after a trust wake).
func TestForcedRenewalWakesOnce(t *testing.T) {
	ctx := context.Background()
	var n notices
	l, nb, _ := pinnedLayer(t, newTestRoot(t, "root"), &n)
	if r, err := l.Watch(ctx, bus.WatchInput{Session: "s1"}); err != nil || r.Woke {
		t.Fatalf("watch before the renewal: %+v %v", r, err)
	}
	nb.mu.Lock()
	nb.server = 2
	nb.mu.Unlock()
	r, err := l.Watch(ctx, bus.WatchInput{Session: "s1"})
	if err != nil || !r.Woke || r.Count != 0 {
		t.Fatalf("watch after the renewal: %+v %v", r, err)
	}
	if got, _, _ := l.store.TrustNumber(); got != 1 {
		t.Fatalf("a watch stored a number: %d", got)
	}
	if _, err := l.Receive(ctx, bus.ReceiveInput{Session: "s1"}); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := l.store.TrustNumber(); got != 2 {
		t.Fatalf("held number %d after the receive, want 2", got)
	}
	if r, err := l.Watch(ctx, bus.WatchInput{Session: "s1"}); err != nil || r.Woke {
		t.Fatalf("the watch after the bundle woke again: %+v %v", r, err)
	}
	want := []string{"watch 1", "watch 1", "receive 1", "watch 2"}
	if strings.Join(nb.sent, ",") != strings.Join(want, ",") {
		t.Fatalf("numbers sent %q, want %q", nb.sent, want)
	}
	// An Open stores a bundle too.
	nb.mu.Lock()
	nb.server = 3
	nb.mu.Unlock()
	if _, err := l.Open(ctx, bus.OpenSessionInput{}); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := l.store.TrustNumber(); got != 3 {
		t.Fatalf("held number %d after open, want 3", got)
	}
}

func TestRefusedCRLIsLogged(t *testing.T) {
	ctx := context.Background()
	root := newTestRoot(t, "root")
	var n notices
	l, nb, e := pinnedLayer(t, root, &n)
	crls := map[int64][]byte{7: root.crl(t, 7), 3: root.crl(t, 3)}
	nb.bundle = func(num int64) *bus.TrustBundle {
		return &bus.TrustBundle{TrustNumber: num, RootCRL: crls[map[int64]int64{2: 7, 3: 3}[num]]}
	}
	nb.server = 2
	if _, err := l.Receive(ctx, bus.ReceiveInput{Session: "s1"}); err != nil {
		t.Fatal(err)
	}
	if len(n.all()) != 0 {
		t.Fatalf("notices %q", n.all())
	}
	heldCRL, err := os.ReadFile(filepath.Join(l.store.Dir, "root.crl"))
	if err != nil {
		t.Fatal(err)
	}

	nb.server = 3 // its root CRL has number 3, below the held 7
	if _, err := l.Receive(ctx, bus.ReceiveInput{Session: "s1"}); err != nil {
		t.Fatal(err)
	}
	got := n.all()
	wantNotice := "profile lab: the server's root CRL number 3 is below the held number 7; it was refused"
	if len(got) != 1 || got[0] != wantNotice {
		t.Fatalf("notices %q", got)
	}
	log, err := os.ReadFile(filepath.Join(e.Data, "logs", "trust.log"))
	if err != nil || strings.Count(string(log), "\n") != 1 || !strings.Contains(string(log), "number 3 is below the held number 7") {
		t.Fatalf("trust.log %q, %v", log, err)
	}
	if after, _ := os.ReadFile(filepath.Join(l.store.Dir, "root.crl")); string(after) != string(heldCRL) {
		t.Fatal("the held CRL changed")
	}
	if num, _, _ := l.store.TrustNumber(); num != 3 {
		t.Fatalf("trust number %d, want 3 recorded", num)
	}
}

// With NoDiscover and no pin the layer sends no number and applies nothing.
func TestNoDiscoverWithoutPinHasNoLayer(t *testing.T) {
	root := newTestRoot(t, "root")
	f := newFakeDiscover(t, root, "inst-one")
	e := trustEnv(t, f.URL, nil)
	var n notices
	c := mustOpen(t, e, &n, func(o *Options) { o.NoDiscover = true })
	if _, ok := c.Bus.(*trustBus); ok {
		t.Fatal("the layer is on a Bus with no pin")
	}
	if c := f.count("/v1/discover"); c != 0 {
		t.Fatalf("%d discover calls with NoDiscover", c)
	}
	if _, err := os.Stat(trustStore(e).Dir); err == nil {
		t.Fatal("NoDiscover created the trust directory")
	}
}

func TestServerURLChangeNeedsAcceptNewRoot(t *testing.T) {
	root := newTestRoot(t, "root")
	a := newFakeDiscover(t, root, "inst-one")
	b := newFakeDiscover(t, root, "inst-one")
	e := trustEnv(t, a.URL, nil)
	var n notices
	mustOpen(t, e, &n, nil)
	before := snapshot(t, trustStore(e).Dir)

	e.Save(t, profile.Profile{Name: "default", Mode: profile.ModeLocal}, profile.Profile{Name: "lab", Mode: profile.ModeServer, Server: b.URL})
	_, err := openLab(e, &n, nil)
	if err == nil || !isResolveError(err) || !strings.Contains(err.Error(), a.URL) || !strings.Contains(err.Error(), b.URL) || !strings.Contains(err.Error(), "-accept-new-root") {
		t.Fatalf("Open at another URL: %v", err)
	}
	if !sameSnapshot(before, snapshot(t, trustStore(e).Dir)) {
		t.Fatal("the trust directory changed")
	}
	if b.count("/v1/discover") != 0 {
		t.Fatal("discover was called before the check stopped")
	}
	var n2 notices
	mustOpen(t, e, &n2, func(o *Options) { o.AcceptNewRoot = true })
	pin, _, _ := trustStore(e).Pinned()
	if pin.Server != b.URL {
		t.Fatalf("pin server %s, want %s", pin.Server, b.URL)
	}
	if got := n2.all(); len(got) != 1 || !strings.Contains(got[0], a.URL) || !strings.Contains(got[0], b.URL) {
		t.Fatalf("notices %q: want old and new server", got)
	}
}

// A 200 whose body is not a discovery document fails like a missing trust
// (Decision 33), with or without a pin.
func TestDiscoverGarbled(t *testing.T) {
	root := newTestRoot(t, "root")
	f := newFakeDiscover(t, root, "inst-one")
	e := trustEnv(t, f.URL, nil)
	var n notices
	mustOpen(t, e, &n, nil) // a pin
	garbled := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("<html>not json"))
	}))
	t.Cleanup(garbled.Close)
	for _, tc := range []struct {
		name string
		env  func() *testkit.ProfileEnv
	}{
		{"no pin", func() *testkit.ProfileEnv { return trustEnv(t, garbled.URL, nil) }},
		{"pin", func() *testkit.ProfileEnv {
			// The pin of the good server, moved to the garbled one's URL.
			e2 := trustEnv(t, garbled.URL, nil)
			st := trustStore(e2)
			b := trust.Bundle{TrustNumber: 1, Root: root.cert.Raw, Installation: "inst-one"}
			if _, err := st.Accept(b, trust.Expect{Server: garbled.URL}, false); err != nil {
				t.Fatal(err)
			}
			return e2
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := openLab(tc.env(), &n, nil)
			if err == nil || !isResolveError(err) || !strings.Contains(err.Error(), "sent no trust material") {
				t.Fatalf("Open: %v", err)
			}
		})
	}
}
