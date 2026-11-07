package server

import (
	"encoding/json"
	"net/http"
	"testing"

	"github.com/ericfitz/agentmesh/internal/gen"
	"github.com/ericfitz/agentmesh/internal/respcheck"
)

// checkedTransport wraps next so every response is validated against the
// embedded document; a violation fails t. A request that matches no operation
// is counted, never reported (ErrNoRoute), so the route-guard tests, which
// send such requests on purpose, are fine; any other test must not send one:
// checkedTransport asserts at cleanup that none was routed nowhere. A test that
// does uses checkedTransportAllowUnrouted.
func checkedTransport(t testing.TB, next http.RoundTripper) http.RoundTripper {
	t.Helper()
	rt, c := checkedTransportCounting(t, next)
	t.Cleanup(func() {
		if n := c.Skipped(); n != 0 {
			t.Errorf("%d responses matched no operation of the document, want 0 (a mistyped path?)", n)
		}
	})
	return rt
}

// checkedTransportAllowUnrouted is checkedTransport for a test that sends
// requests no operation matches (ruling 8): the route guards.
func checkedTransportAllowUnrouted(t testing.TB, next http.RoundTripper) http.RoundTripper {
	t.Helper()
	rt, _ := checkedTransportCounting(t, next)
	return rt
}

func checkedTransportCounting(t testing.TB, next http.RoundTripper) (http.RoundTripper, *respcheck.Checker) {
	t.Helper()
	// One router per transport: the checker's skip counter is per transport,
	// so a test's assertion is its own.
	c, err := respcheck.New(Spec())
	if err != nil {
		t.Fatalf("respcheck.New: %v", err)
	}
	return c.Transport(next, func(err error) { t.Errorf("response validation: %v", err) }), c
}

// problemOf decodes an application/problem+json body and fails the test when
// the body is empty or is not a problem document.
func problemOf(t testing.TB, body []byte) gen.Problem {
	t.Helper()
	var p gen.Problem
	if len(body) == 0 {
		t.Fatalf("empty body, want a problem document")
	}
	if err := json.Unmarshal(body, &p); err != nil {
		t.Fatalf("body %q is not a problem document: %v", body, err)
	}
	return p
}
