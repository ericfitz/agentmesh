package server

import (
	"context"
	"encoding/json"
	"errors"
	"math"
	"net/http"
	"strconv"
	"time"

	"github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// ProblemTypePrefix prefixes the code in a problem's type member (a URN,
// because no domain is claimed; RFC 9457 requires only a URI reference).
const ProblemTypePrefix = "urn:agentmesh:problem:"

// StatusFor is the HTTP status of an error code (Milestone 4 choice 3). An
// unknown code is 500.
func StatusFor(code bus.Code) int {
	switch code {
	case bus.CodeValidation:
		return http.StatusBadRequest
	case bus.CodeUnauthenticated:
		return http.StatusUnauthorized
	case bus.CodeForbidden, bus.CodeNotRegistered:
		return http.StatusForbidden
	case bus.CodeNotFound:
		return http.StatusNotFound
	case bus.CodeConflict, bus.CodeReplaced:
		return http.StatusConflict
	case bus.CodeSessionLapsed, bus.CodeSessionClosed:
		return http.StatusGone
	case bus.CodeRateLimited:
		return http.StatusTooManyRequests
	case bus.CodeInspectionRejected:
		// Declared per operation as UnprocessableEntity (issue #33).
		return http.StatusUnprocessableEntity
	case bus.CodePayloadTooLarge:
		return http.StatusRequestEntityTooLarge
	case bus.CodeUnavailable:
		return http.StatusServiceUnavailable
	default:
		return http.StatusInternalServerError
	}
}

func newProblem(r *http.Request, status int, code bus.Code, detail string, retryable bool) gen.Problem {
	p := gen.Problem{
		Type:      ProblemTypePrefix + string(code),
		Title:     http.StatusText(status),
		Status:    status,
		Code:      gen.ProblemCode(code),
		Retryable: retryable,
	}
	if detail != "" {
		p.Detail = &detail
	}
	if r != nil && r.URL != nil {
		inst := r.URL.Path
		p.Instance = &inst
	}
	return p
}

// ProblemFor maps an error to a problem. write is false when nothing should
// be sent: the client is gone (context canceled or deadline exceeded).
func ProblemFor(err error) (status int, p gen.Problem, write bool) {
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return 0, gen.Problem{}, false
	}
	var be *bus.Error
	if errors.As(err, &be) {
		status = StatusFor(be.Code)
		return status, newProblem(nil, status, be.Code, be.Message, be.Retryable), true
	}
	return http.StatusInternalServerError,
		newProblem(nil, http.StatusInternalServerError, bus.CodeInternal, err.Error(), true), true
}

// WriteProblem writes one application/problem+json response. It truncates
// nothing: the core already bounded every message.
func WriteProblem(w http.ResponseWriter, r *http.Request, status int, code bus.Code, detail string, retryable bool) {
	writeProblemBody(w, newProblem(r, status, code, detail, retryable))
}

func writeProblemBody(w http.ResponseWriter, p gen.Problem) {
	w.Header().Set("Content-Type", "application/problem+json")
	// Every 429 carries Retry-After (issue #33 decision 1); responseError sets
	// the limiter's wait first, any other writer gets the one-second floor.
	if p.Status == http.StatusTooManyRequests && w.Header().Get("Retry-After") == "" {
		w.Header().Set("Retry-After", "1")
	}
	w.WriteHeader(p.Status)
	_ = json.NewEncoder(w).Encode(p)
}

// validatorCode maps the request validator's status to a code. 413 never
// reaches it: limitBody writes it first (as payload_too_large).
func validatorCode(status int) bus.Code {
	switch status {
	case http.StatusBadRequest, http.StatusUnprocessableEntity:
		return bus.CodeValidation
	case http.StatusUnauthorized:
		return bus.CodeUnauthenticated
	case http.StatusNotFound:
		return bus.CodeNotFound
	default:
		return bus.CodeInternal
	}
}

// responseError is the strict server's ResponseErrorHandlerFunc: every
// handler failure goes through ProblemFor (choice 4).
func responseError(w http.ResponseWriter, r *http.Request, err error) {
	_, p, write := ProblemFor(err)
	if !write {
		return
	}
	if r != nil && r.URL != nil {
		inst := r.URL.Path
		p.Instance = &inst
	}
	var be *bus.Error
	if errors.As(err, &be) && be.Code == bus.CodeRateLimited {
		w.Header().Set("Retry-After", strconv.Itoa(retryAfterSeconds(be.RetryAfter)))
	}
	writeProblemBody(w, p)
}

// retryAfterSeconds is the Retry-After value for a wait: whole seconds
// rounded up, at least 1.
func retryAfterSeconds(d time.Duration) int {
	return max(1, int(math.Ceil(d.Seconds())))
}
