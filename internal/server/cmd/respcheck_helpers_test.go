package cmd

import (
	"net/http"
	"sync"
	"testing"

	"github.com/ericfitz/agentmesh/internal/respcheck"
	"github.com/ericfitz/agentmesh/internal/server"
)

var (
	specCheckOnce sync.Once
	specChecker   *respcheck.Checker
	specCheckErr  error
)

// checkedClient is hc (nil: the default client's transport) behind the
// response validator, over the embedded document (issue #33): violations fail
// t at its cleanup (never from a goroutine that outlives it), and a response
// to a request that matches no operation fails it too (a mistyped path).
func checkedClient(t testing.TB, hc *http.Client) *http.Client {
	t.Helper()
	c, tr := checkedClientCounting(t, hc)
	t.Cleanup(func() {
		if n := tr.Skipped(); n != 0 {
			t.Errorf("%d responses matched no operation of the document, want 0 (a mistyped path?)", n)
		}
	})
	return c
}

func checkedClientCounting(t testing.TB, hc *http.Client) (*http.Client, *respcheck.Transport) {
	t.Helper()
	specCheckOnce.Do(func() { specChecker, specCheckErr = respcheck.New(server.Spec()) })
	if specCheckErr != nil {
		t.Fatalf("respcheck.New: %v", specCheckErr)
	}
	next := http.DefaultTransport
	out := http.Client{}
	if hc != nil {
		out = *hc
		if hc.Transport != nil {
			next = hc.Transport
		}
	}
	tr := specChecker.Transport(next, respcheck.Report(t))
	out.Transport = tr
	return &out, tr
}
