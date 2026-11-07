package server

import (
	"encoding/json"
	"testing"

	"github.com/ericfitz/agentmesh/internal/gen"
)

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
