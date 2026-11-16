package cli

import (
	"context"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/client"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/core/identities"
	"github.com/ericfitz/agentmesh/internal/store/sqlite"
	"github.com/ericfitz/agentmesh/internal/testkit"
)

// TestForcedRenewalWakesWatchOnce runs a forced renewal through a real server
// (spec section 5, "Client stores a bundle"): a waiting watch wakes once with
// the new number, the layer stores the bundle, and the next watch sends the new
// number and does not wake at once.
func TestForcedRenewalWakesWatchOnce(t *testing.T) {
	ctx := context.Background()
	e := newTestEnv(t)
	db := filepath.Join(t.TempDir(), "srv.sqlite")
	base := startServer(t, db)
	for _, p := range [][2]string{{"lab", "pat"}, {"adm", "adm"}} {
		var out, errb testkit.LockedBuffer
		if code := RunRegister(ctx, []string{"-profile", p[0], "-server", base, "-identity", p[1]}, e.Environ, nil, &out, &errb); code != 0 {
			t.Fatalf("register %s: %d %q", p[1], code, errb.String())
		}
	}
	st, err := sqlite.Open(ctx, db, sqlite.Options{})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	cr, err := core.New(st, core.Defaults(), core.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err := (identities.Service{Core: cr}).MakeAdmin(ctx, "adm", true); err != nil {
		t.Fatal(err)
	}

	rt := &pathCounter{}
	pat := e.conn(t, "pat", func(o *client.Options) { o.Profile = "lab"; o.HTTP = &http.Client{Transport: rt} })
	adm := e.conn(t, "adm", func(o *client.Options) { o.Profile = "adm" })
	s, err := pat.Bus.Open(ctx, bus.OpenSessionInput{})
	if err != nil {
		t.Fatal(err)
	}
	before := heldNumber(t, e)

	type answer struct {
		r   bus.WatchResult
		err error
	}
	got := make(chan answer, 1)
	go func() {
		r, err := pat.Bus.Watch(ctx, bus.WatchInput{Session: s.ID, Timeout: 20 * time.Second})
		got <- answer{r, err}
	}()
	select {
	case a := <-got:
		t.Fatalf("the watch answered before the renewal: %+v %v", a.r, a.err)
	case <-time.After(300 * time.Millisecond):
	}
	rot, err := adm.Bus.RotateSigningKey(ctx, bus.RotateSigningKeyInput{})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if rot.TrustNumber <= before {
		t.Fatalf("rotation number %d, held %d", rot.TrustNumber, before)
	}
	select {
	case a := <-got:
		if a.err != nil || !a.r.Woke || a.r.Count != 0 || a.r.TrustNumber == nil || *a.r.TrustNumber != rot.TrustNumber {
			t.Fatalf("wake: %+v %v, want count 0 and number %d", a.r, a.err, rot.TrustNumber)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the renewal did not wake the watch")
	}
	if held := heldNumber(t, e); held != rot.TrustNumber {
		t.Fatalf("held number %d after the wake, want %d", held, rot.TrustNumber)
	}
	discovers := rt.count("/v1/discover")

	start := time.Now()
	r, err := pat.Bus.Watch(ctx, bus.WatchInput{Session: s.ID, Timeout: time.Second})
	if err != nil || r.Woke || time.Since(start) < 800*time.Millisecond {
		t.Fatalf("second watch: %+v %v after %v, want a timeout", r, err, time.Since(start))
	}
	if n := rt.count("/v1/discover"); n != discovers {
		t.Fatalf("%d discover calls during the second watch", n-discovers)
	}
}
