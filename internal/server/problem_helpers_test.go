package server

import (
	"encoding/json"
	"net/http"
	"sync"
	"testing"

	"github.com/ericfitz/agentmesh/internal/gen"
	"github.com/ericfitz/agentmesh/internal/respcheck"
)

var (
	specCheckOnce sync.Once
	specChecker   *respcheck.Checker
	specCheckErr  error
)

// specCheck is the package's one Checker over the embedded document (one
// router for every test; skip counts are per transport).
func specCheck(t testing.TB) *respcheck.Checker {
	t.Helper()
	specCheckOnce.Do(func() { specChecker, specCheckErr = respcheck.New(Spec()) })
	if specCheckErr != nil {
		t.Fatalf("respcheck.New: %v", specCheckErr)
	}
	return specChecker
}

// checkedTransport wraps next so every response is validated against the
// embedded document; violations fail t at its cleanup. A request that matches
// no operation is counted, never reported (ErrNoRoute): checkedTransport
// asserts at cleanup that none was, so a mistyped path fails. A test that
// sends such requests on purpose uses checkedTransportAllowUnrouted.
func checkedTransport(t testing.TB, next http.RoundTripper) http.RoundTripper {
	t.Helper()
	tr := specCheck(t).Transport(next, respcheck.Report(t))
	t.Cleanup(func() {
		if n := tr.Skipped(); n != 0 {
			t.Errorf("%d responses matched no operation of the document, want 0 (a mistyped path?)", n)
		}
	})
	return tr
}

// checkedTransportAllowUnrouted is checkedTransport for a test that sends
// requests no operation matches (ruling 8): the route guards, the framework
// errors, the empty ids.
func checkedTransportAllowUnrouted(t testing.TB, next http.RoundTripper) http.RoundTripper {
	t.Helper()
	return specCheck(t).Transport(next, respcheck.Report(t))
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
