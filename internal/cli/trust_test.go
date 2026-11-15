package cli

import (
	"context"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/ericfitz/agentmesh/internal/client"
	"github.com/ericfitz/agentmesh/internal/testkit"
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
