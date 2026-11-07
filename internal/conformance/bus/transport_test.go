package bus

import (
	"context"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/ericfitz/agentmesh/internal/bus/local"
	"github.com/ericfitz/agentmesh/internal/bus/remote"
	"github.com/ericfitz/agentmesh/internal/dbtest"
	"github.com/ericfitz/agentmesh/internal/gen"
	"github.com/ericfitz/agentmesh/internal/server"
)

const transportEnv = "AGENTMESH_BUS_TRANSPORT"

// transport is "local" or "inproc", set in TestMain before dbtest.Run.
var transport string

// countingHandler counts the requests that reach a harness's server.
type countingHandler struct {
	http.Handler
	n atomic.Int64
}

func (c *countingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	c.n.Add(1)
	c.Handler.ServeHTTP(w, r)
}

var (
	handlersMu sync.Mutex
	handlers   = map[*harness]*countingHandler{}
)

// countingFor returns the harness's counting handler: one server.New over
// h.core per harness (a sibling is another *harness), created on first use
// and dropped in h.t.Cleanup so the map never outgrows the live harnesses.
func countingFor(h *harness) *countingHandler {
	handlersMu.Lock()
	defer handlersMu.Unlock()
	if c, ok := handlers[h]; ok {
		return c
	}
	c := &countingHandler{Handler: server.New(h.core, server.Options{Auth: server.InProcess{}})}
	handlers[h] = c
	h.t.Cleanup(func() {
		handlersMu.Lock()
		defer handlersMu.Unlock()
		delete(handlers, h)
	})
	return c
}

func handlerFor(h *harness) http.Handler { return countingFor(h) }

func TestTransportInUse(t *testing.T) {
	if transport != "local" && transport != "inproc" {
		t.Fatalf("transport = %q, want local or inproc", transport)
	}
	dbtest.ForEachEngine(t, func(t *testing.T, e dbtest.Engine) {
		h := newHarness(t, e, harnessOptions{})
		b := h.as("pat")
		switch transport {
		case "local":
			if _, ok := b.(*local.Bus); !ok {
				t.Fatalf("newBus returned %T, want *local.Bus", b)
			}
			if _, err := b.ListChannels(context.Background()); err != nil {
				t.Fatalf("ListChannels: %v", err)
			}
			if n := countingFor(h).n.Load(); n != 0 {
				t.Fatalf("request counter = %d after a local ListChannels, want 0 (no wire)", n)
			}
		case "inproc":
			if _, ok := b.(*remote.Bus); !ok {
				t.Fatalf("newBus returned %T, want *remote.Bus", b)
			}
			// A call through newBus must reach the harness's server: the
			// counter is what separates "inproc" from a local Bus in disguise.
			if _, err := b.ListChannels(context.Background()); err != nil {
				t.Fatalf("ListChannels: %v", err)
			}
			if n := countingFor(h).n.Load(); n != 1 {
				t.Fatalf("request counter = %d after one ListChannels through newBus, want 1", n)
			}
			c, err := gen.NewClientWithResponses("http://inproc", gen.WithHTTPClient(&http.Client{Transport: inprocTransport(h, "pat")}))
			if err != nil {
				t.Fatal(err)
			}
			resp, err := c.DiscoverWithResponse(context.Background())
			if err != nil {
				t.Fatal(err)
			}
			if resp.StatusCode() != http.StatusOK {
				t.Fatalf("discover status = %d, want 200", resp.StatusCode())
			}
			if n := countingFor(h).n.Load(); n != 2 {
				t.Fatalf("request counter = %d, want 2", n)
			}
		}
	})
}

// TestInprocResponseCheckWired proves a call made through newBus crosses the
// response validator: the checker's count rises. Reverting newBus (or the
// inprocTransport helper) to the raw in-process transport fails it.
func TestInprocResponseCheckWired(t *testing.T) {
	if transport != "inproc" {
		return // the local transport has no wire (a Skip would trip the no-skip gate)
	}
	dbtest.ForEachEngine(t, func(t *testing.T, e dbtest.Engine) {
		h := newHarness(t, e, harnessOptions{})
		before := check.Checked()
		if _, err := h.as("pat").ListChannels(context.Background()); err != nil {
			t.Fatalf("ListChannels: %v", err)
		}
		if got := check.Checked() - before; got < 1 {
			t.Fatalf("a ListChannels through newBus was checked %d times, want at least 1: newBus bypasses the response validator", got)
		}
	})
}
