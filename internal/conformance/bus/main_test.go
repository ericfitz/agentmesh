package bus

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/bus/remote"
	"github.com/ericfitz/agentmesh/internal/dbtest"
	"github.com/ericfitz/agentmesh/internal/gen"
	"github.com/ericfitz/agentmesh/internal/respcheck"
	"github.com/ericfitz/agentmesh/internal/server"
)

// check validates every response of the wire paths against the embedded
// document (issue #33).
var check *respcheck.Checker

// emptySegment counts the requests sent with an empty path segment
// (/v1/sessions//receive, DELETE /v1/channels/): the suites probe an empty id on purpose, the
// document's router answers 404 to it, and it matches no operation. They are
// the only requests allowed to be unrouted.
var emptySegment atomic.Int64

// countEmptySegment counts requests whose path has an empty segment (an
// inner one or a trailing slash) before
// handing them to next.
type countEmptySegment struct{ next http.RoundTripper }

func (c countEmptySegment) RoundTrip(req *http.Request) (*http.Response, error) {
	if strings.Contains(req.URL.Path, "//") || strings.HasSuffix(req.URL.Path, "/") {
		emptySegment.Add(1)
	}
	return c.next.RoundTrip(req)
}

// inprocTransport is the in-process transport for identity, behind the
// response validator: a violation fails the harness's test.
func inprocTransport(h *harness, identity string) http.RoundTripper {
	return check.Transport(countEmptySegment{server.InProcessTransport(handlerFor(h), identity)}, func(err error) { h.t.Errorf("response validation: %v", err) })
}

func TestMain(m *testing.M) {
	var err error
	if check, err = respcheck.New(server.Spec()); err != nil {
		fmt.Fprintf(os.Stderr, "respcheck.New: %v\n", err)
		os.Exit(2)
	}
	transport = os.Getenv(transportEnv)
	if transport == "" {
		transport = "local"
	}
	switch transport {
	case "local":
	case "inproc":
		newBus = func(h *harness, identity string) ab2bus.Bus {
			c, err := gen.NewClientWithResponses("http://inproc", gen.WithHTTPClient(&http.Client{Transport: inprocTransport(h, identity)}))
			if err != nil {
				h.t.Fatalf("gen.NewClientWithResponses: %v", err)
			}
			return remote.New(c)
		}
	default:
		fmt.Fprintf(os.Stderr, "AGENTMESH_BUS_TRANSPORT must be local or inproc, got %q\n", transport)
		os.Exit(2)
	}
	code := dbtest.Run(m)
	// A mistyped path is ErrNoRoute, counted and never reported: the only
	// unrouted requests are the empty-segment probes, so the two counts match.
	if n, want := check.Skipped(), emptySegment.Load(); code == 0 && n != want {
		fmt.Fprintf(os.Stderr, "response validation: %d responses matched no operation, want %d (the empty-segment probes)\n", n, want)
		code = 1
	}
	os.Exit(code)
}
