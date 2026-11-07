package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/ericfitz/agentmesh/internal/auth/assertion"
	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
	"github.com/ericfitz/agentmesh/internal/store"
)

// tokenPath is the one endpoint that answers RFC 6749 section 5.2 error
// bodies instead of problem+json (spec 8.1, Decision 46).
const tokenPath = "/v1/auth/token"

// exchangeDeniedCode is the code of a token exchange refused by the gate (a
// `users` miss): RFC 8693 section 2.2.2 gives a failed exchange
// invalid_request (spec Decision 13, Eric).
const exchangeDeniedCode = "invalid_request"

// MaxOAuthFieldBytes bounds every token request field that is neither a JWT
// (assertion.MaxTokenBytes) nor the client_id (store.MaxNameBytes): issue #34,
// Eric's decision of 2026-11-06 for opaque tokens, in bytes.
const MaxOAuthFieldBytes = 1024

// checkTokenFormBounds names the first field of b over its bound, as the
// description of an invalid_request refusal ("<field> exceeds <n> bytes"); the
// value itself is never echoed. over is false when every field is within bounds.
func checkTokenFormBounds(b *gen.TokenRequest) (msg string, over bool) {
	for _, f := range tokenFormFields(b) {
		if len(f.value) > f.limit {
			return fmt.Sprintf("%s exceeds %d bytes", f.name, f.limit), true
		}
	}
	return "", false
}

// tokenFormField is one string member of a token request with its bound.
type tokenFormField struct {
	name  string
	value string
	limit int
}

// tokenFormFields lists every string member of the request (TestTokenFormFieldsComplete
// fails when gen.TokenRequest gains one this table lacks).
func tokenFormFields(b *gen.TokenRequest) []tokenFormField {
	return []tokenFormField{
		{"actor_token", deref(b.ActorToken), assertion.MaxTokenBytes},
		{"actor_token_type", deref(b.ActorTokenType), MaxOAuthFieldBytes},
		{"audience", deref(b.Audience), MaxOAuthFieldBytes},
		{"client_assertion", deref(b.ClientAssertion), assertion.MaxTokenBytes},
		{"client_assertion_type", deref(b.ClientAssertionType), MaxOAuthFieldBytes},
		{"client_id", deref(b.ClientId), store.MaxNameBytes},
		{"grant_type", b.GrantType, MaxOAuthFieldBytes},
		{"requested_token_type", deref(b.RequestedTokenType), MaxOAuthFieldBytes},
		{"resource", deref(b.Resource), MaxOAuthFieldBytes},
		{"scope", deref(b.Scope), MaxOAuthFieldBytes},
		{"subject_token", deref(b.SubjectToken), assertion.MaxTokenBytes},
		{"subject_token_type", deref(b.SubjectTokenType), MaxOAuthFieldBytes},
	}
}

func deref(p *string) string {
	if p == nil {
		return ""
	}
	return *p
}

// oauthError is a refused token request. It is a gen.TokenResponseObject, so a
// handler returns it as the response rather than as an error (an error would
// reach the problem+json handler).
type oauthError struct {
	Status      int
	Code        string
	Description string
}

// VisitTokenResponse writes the RFC 6749 section 5.2 body.
func (e oauthError) VisitTokenResponse(w http.ResponseWriter) error {
	writeOAuthError(w, e)
	return nil
}

// oauthFail builds an oauthError with a formatted description.
func oauthFail(status int, code, format string, args ...any) oauthError {
	return oauthError{Status: status, Code: code, Description: fmt.Sprintf(format, args...)}
}

// oauthFromBus maps an error from the core to the token endpoint's refusal.
// exchange selects the RFC 8693 table; client_credentials has no forbidden
// case. Anything unrecognized is a 500 server_error whose description never
// carries the underlying text.
func oauthFromBus(err error, exchange bool) oauthError {
	var msg string
	var be *bus.Error
	if errors.As(err, &be) {
		msg = be.Message
	}
	switch bus.CodeOf(err) {
	case bus.CodeUnavailable:
		return oauthError{http.StatusServiceUnavailable, "temporarily_unavailable", msg}
	case bus.CodeUnauthenticated:
		if exchange {
			return oauthError{http.StatusBadRequest, "invalid_request", msg}
		}
		return oauthError{http.StatusUnauthorized, "invalid_client", msg}
	case bus.CodeValidation:
		return oauthError{http.StatusBadRequest, "invalid_request", msg}
	case bus.CodeForbidden:
		if exchange {
			return oauthError{http.StatusBadRequest, exchangeDeniedCode, msg}
		}
	case bus.CodeConflict:
		if exchange {
			return oauthError{http.StatusBadRequest, "invalid_request", msg}
		}
	}
	return oauthError{http.StatusInternalServerError, "server_error", "internal error"}
}

// writeOAuthError writes one application/json response with the RFC 6749
// section 5.1 cache headers.
func writeOAuthError(w http.ResponseWriter, e oauthError) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.WriteHeader(e.Status)
	body := gen.OAuthError{Error: e.Code}
	if e.Description != "" {
		d := e.Description
		body.ErrorDescription = &d
	}
	_ = json.NewEncoder(w).Encode(body)
}
