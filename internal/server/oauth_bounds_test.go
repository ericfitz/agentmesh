package server

import (
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/auth/assertion"
	"github.com/ericfitz/agentmesh/internal/gen"
	"github.com/ericfitz/agentmesh/internal/store"
)

// TestCheckTokenFormBounds calls the handler's own size check, which the
// spec validator hides on the wire: every field over its bound is named, and
// every field exactly at it passes.
func TestCheckTokenFormBounds(t *testing.T) {
	set := map[string]func(*gen.TokenRequest, string){
		"actor_token":           func(b *gen.TokenRequest, v string) { b.ActorToken = &v },
		"actor_token_type":      func(b *gen.TokenRequest, v string) { b.ActorTokenType = &v },
		"audience":              func(b *gen.TokenRequest, v string) { b.Audience = &v },
		"client_assertion":      func(b *gen.TokenRequest, v string) { b.ClientAssertion = &v },
		"client_assertion_type": func(b *gen.TokenRequest, v string) { b.ClientAssertionType = &v },
		"client_id":             func(b *gen.TokenRequest, v string) { b.ClientId = &v },
		"grant_type":            func(b *gen.TokenRequest, v string) { b.GrantType = v },
		"requested_token_type":  func(b *gen.TokenRequest, v string) { b.RequestedTokenType = &v },
		"resource":              func(b *gen.TokenRequest, v string) { b.Resource = &v },
		"scope":                 func(b *gen.TokenRequest, v string) { b.Scope = &v },
		"subject_token":         func(b *gen.TokenRequest, v string) { b.SubjectToken = &v },
		"subject_token_type":    func(b *gen.TokenRequest, v string) { b.SubjectTokenType = &v },
	}
	limits := map[string]int{
		"actor_token": assertion.MaxTokenBytes, "client_assertion": assertion.MaxTokenBytes, "subject_token": assertion.MaxTokenBytes,
		"client_id":        store.MaxNameBytes,
		"actor_token_type": MaxOAuthFieldBytes, "audience": MaxOAuthFieldBytes, "client_assertion_type": MaxOAuthFieldBytes,
		"grant_type": MaxOAuthFieldBytes, "requested_token_type": MaxOAuthFieldBytes, "resource": MaxOAuthFieldBytes,
		"scope": MaxOAuthFieldBytes, "subject_token_type": MaxOAuthFieldBytes,
	}
	if len(limits) != len(set) {
		t.Fatalf("%d limits for %d fields", len(limits), len(set))
	}
	for name, setter := range set {
		limit, ok := limits[name]
		if !ok {
			t.Fatalf("no limit for %s", name)
		}
		t.Run(name, func(t *testing.T) {
			var at gen.TokenRequest
			setter(&at, strings.Repeat("a", limit))
			if msg, over := checkTokenFormBounds(&at); over {
				t.Errorf("at the bound: refused: %s", msg)
			}
			var above gen.TokenRequest
			setter(&above, strings.Repeat("a", limit+1))
			msg, over := checkTokenFormBounds(&above)
			if !over || !strings.HasPrefix(msg, name+" exceeds ") {
				t.Errorf("over the bound: over=%v msg=%q", over, msg)
			}
		})
	}
}
