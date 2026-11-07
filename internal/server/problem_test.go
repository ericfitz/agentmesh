package server

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/core"
	"github.com/ericfitz/agentmesh/internal/gen"
)

func TestStatusForEveryCode(t *testing.T) {
	want := map[bus.Code]int{
		bus.CodeValidation: 400, bus.CodeUnauthenticated: 401, bus.CodeForbidden: 403,
		bus.CodeNotRegistered: 403, bus.CodeNotFound: 404, bus.CodeConflict: 409,
		bus.CodeReplaced: 409, bus.CodeSessionLapsed: 410, bus.CodeSessionClosed: 410,
		bus.CodeRateLimited: 429, bus.CodeUnavailable: 503, bus.CodeInternal: 500,
		bus.CodeInspectionRejected: 422, bus.CodePayloadTooLarge: 413,
	}
	if len(want) != 14 {
		t.Fatalf("table has %d codes, want 14", len(want))
	}
	for code, status := range want {
		if got := StatusFor(code); got != status {
			t.Errorf("StatusFor(%s) = %d, want %d", code, got, status)
		}
	}
	if got := StatusFor("bogus"); got != 500 {
		t.Errorf("StatusFor(unknown) = %d, want 500", got)
	}
}

func TestValidatorCode(t *testing.T) {
	for status, want := range map[int]bus.Code{
		400: bus.CodeValidation, 422: bus.CodeValidation, 401: bus.CodeUnauthenticated,
		404: bus.CodeNotFound, 500: bus.CodeInternal, 413: bus.CodeInternal, 418: bus.CodeInternal,
	} {
		if got := validatorCode(status); got != want {
			t.Errorf("validatorCode(%d) = %s, want %s", status, got, want)
		}
	}
}

func TestProblemForMapsBusErrors(t *testing.T) {
	status, p, write := ProblemFor(&bus.Error{Code: bus.CodeRateLimited, Message: "slow", Retryable: true})
	if !write || status != 429 || p.Code != gen.ProblemCode("rate_limited") || p.Detail == nil || *p.Detail != "slow" || !p.Retryable {
		t.Fatalf("got %d %+v write=%v", status, p, write)
	}
	status, p, write = ProblemFor(errors.New("disk"))
	if !write || status != 500 || p.Code != gen.ProblemCode("internal") || !p.Retryable || *p.Detail != "disk" {
		t.Fatalf("got %d %+v write=%v", status, p, write)
	}
}

func TestProblemForContextErrorsWriteNothing(t *testing.T) {
	for _, err := range []error{context.Canceled, context.DeadlineExceeded, errors.Join(errors.New("x"), context.Canceled)} {
		if _, _, write := ProblemFor(err); write {
			t.Errorf("ProblemFor(%v) write = true", err)
		}
	}
}

func TestWriteProblemShape(t *testing.T) {
	detail := strings.Repeat("d", 2000)
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "/v1/things", nil)
	WriteProblem(rec, r, 409, bus.CodeConflict, detail, false)
	if rec.Code != 409 {
		t.Fatalf("status %d", rec.Code)
	}
	if ct := rec.Header().Get("Content-Type"); ct != "application/problem+json" {
		t.Fatalf("content type %q", ct)
	}
	var m map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"type": "urn:agentmesh:problem:conflict", "title": "Conflict", "status": float64(409),
		"detail": detail, "instance": "/v1/things", "code": "conflict", "retryable": false,
	}
	for k, v := range want {
		if m[k] != v {
			t.Errorf("member %s = %v, want %v", k, m[k], v)
		}
	}
}

func TestRateLimitedRetryAfterHeader(t *testing.T) {
	for _, tc := range []struct {
		err  error
		want string
	}{
		{core.RateLimited(1500*time.Millisecond, "x"), "2"},
		{core.RateLimited(0, "x"), "1"},
		{core.E(bus.CodeConflict, "x"), ""},
	} {
		rec := httptest.NewRecorder()
		responseError(rec, httptest.NewRequest("GET", "/v1/x", nil), tc.err)
		if got := rec.Header().Get("Retry-After"); got != tc.want {
			t.Errorf("%v: Retry-After = %q, want %q", tc.err, got, tc.want)
		}
		if _, has := rec.Header()["Retry-After"]; has != (tc.want != "") {
			t.Errorf("%v: Retry-After presence = %v", tc.err, has)
		}
	}
	rec := httptest.NewRecorder()
	responseError(rec, httptest.NewRequest("GET", "/v1/x", nil), core.RateLimited(time.Second, "x"))
	if rec.Code != 429 {
		t.Errorf("status = %d, want 429", rec.Code)
	}
}

func TestWriteProblemStatusMatches(t *testing.T) {
	for _, code := range []bus.Code{
		bus.CodeValidation, bus.CodeUnauthenticated, bus.CodeForbidden, bus.CodeNotRegistered,
		bus.CodeNotFound, bus.CodeConflict, bus.CodeReplaced, bus.CodeSessionLapsed,
		bus.CodeSessionClosed, bus.CodeRateLimited, bus.CodeUnavailable, bus.CodeInternal,
		bus.CodeInspectionRejected,
	} {
		r := httptest.NewRequest("GET", "/v1/x", nil)
		for name, write := range map[string]func(*httptest.ResponseRecorder){
			"WriteProblem":  func(w *httptest.ResponseRecorder) { WriteProblem(w, r, StatusFor(code), code, "x", false) },
			"responseError": func(w *httptest.ResponseRecorder) { responseError(w, r, core.E(code, "x")) },
		} {
			rec := httptest.NewRecorder()
			write(rec)
			var p gen.Problem
			if err := json.Unmarshal(rec.Body.Bytes(), &p); err != nil {
				t.Fatalf("%s %s: %v", name, code, err)
			}
			if rec.Code != StatusFor(code) || int(p.Status) != rec.Code {
				t.Errorf("%s %s: recorder %d, body status %d, want %d", name, code, rec.Code, p.Status, StatusFor(code))
			}
		}
	}
}

func TestRetryAfterSeconds(t *testing.T) {
	for d, want := range map[time.Duration]int{0: 1, 1: 1, time.Second: 1, 1001 * time.Millisecond: 2} {
		if got := retryAfterSeconds(d); got != want {
			t.Errorf("retryAfterSeconds(%v) = %d, want %d", d, got, want)
		}
	}
}

func TestWriteProblem429CarriesRetryAfter(t *testing.T) {
	r := httptest.NewRequest("GET", "/v1/x", nil)
	rec := httptest.NewRecorder()
	WriteProblem(rec, r, 429, bus.CodeRateLimited, "slow", true)
	if got := rec.Header().Get("Retry-After"); got != "1" {
		t.Errorf("WriteProblem 429 Retry-After = %q, want 1", got)
	}
	rec = httptest.NewRecorder()
	WriteProblem(rec, r, 409, bus.CodeConflict, "x", false)
	if _, has := rec.Header()["Retry-After"]; has {
		t.Error("a 409 carries Retry-After")
	}
	// responseError's own value is not overwritten by the floor.
	rec = httptest.NewRecorder()
	responseError(rec, r, core.RateLimited(5*time.Second, "x"))
	if got := rec.Header().Get("Retry-After"); got != "5" {
		t.Errorf("responseError Retry-After = %q, want 5", got)
	}
}
