package remote

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"time"

	ab2bus "github.com/ericfitz/agentmesh/internal/bus"
	"github.com/ericfitz/agentmesh/internal/gen"
)

// Bus is the remote implementation of ab2bus.Bus over the generated client.
// Names (channels, sessions, tag patterns) go to the generated client as
// given: there is no client-side path-parameter rule (Decision 80), with three
// exceptions, each for exactly the inputs that encode to an empty path
// segment (the router's 404 not_found where the core answers validation):
// Send with an empty channel (messages.go), Close with an empty session id
// (sessions.go) and UnsubscribeTags with an empty pattern set (channels.go).
// Decision (Eric, 2026-10-21): Milestone 4 item 6, options A and C (keep the
// three guards; UnsubscribeTags sends its patterns as query values).
type Bus struct{ c *gen.ClientWithResponses }

// New wraps a generated client.
func New(c *gen.ClientWithResponses) *Bus { return &Bus{c: c} }

var _ ab2bus.Bus = (*Bus)(nil)

// maxBodyExcerpt bounds the body text quoted in an unparsable-response error.
const maxBodyExcerpt = 200

// errorOf maps one response to a Bus error (spec 3.3, "never by guessing").
// status and header come from the HTTP response (header may be nil), body is
// the raw body, err the transport error. The problem is decoded from body at
// any status: the generated client types only declared statuses.
//
//   - err != nil: ctx.Err() when the context is done, else unavailable.
//   - 2xx: nil.
//   - a problem with a code: the code as received (known or not) with the
//     wire's retryable; the message is detail, or title when detail is empty;
//     on 429 RetryAfter is the Retry-After header in whole seconds (absent or
//     malformed leaves it 0).
//   - anything else: unavailable for 5xx, internal otherwise.
func errorOf(ctx context.Context, status int, header http.Header, body []byte, err error) error {
	if err != nil {
		if cerr := ctx.Err(); cerr != nil {
			return cerr
		}
		return &ab2bus.Error{Code: ab2bus.CodeUnavailable, Message: ab2bus.TruncateErrorMessage(err.Error()), Retryable: true}
	}
	if status >= 200 && status < 300 {
		return nil
	}
	var p gen.Problem
	if len(body) > 0 && json.Unmarshal(body, &p) == nil && p.Code != "" {
		msg := p.Title
		if p.Detail != nil && *p.Detail != "" {
			msg = *p.Detail
		}
		e := &ab2bus.Error{Code: ab2bus.Code(p.Code), Message: ab2bus.TruncateErrorMessage(msg), Retryable: p.Retryable}
		if status == http.StatusTooManyRequests {
			e.RetryAfter = retryAfter(header)
		}
		return e
	}
	if status >= 500 {
		return &ab2bus.Error{Code: ab2bus.CodeUnavailable, Message: fmt.Sprintf("HTTP %d", status), Retryable: true}
	}
	excerpt := strings.TrimSpace(string(body))
	if len(excerpt) > maxBodyExcerpt {
		excerpt = excerpt[:maxBodyExcerpt]
	}
	return &ab2bus.Error{Code: ab2bus.CodeInternal, Message: ab2bus.TruncateErrorMessage(fmt.Sprintf("HTTP %d: %s", status, excerpt)), Retryable: false}
}

// retryAfter reads the Retry-After header as whole seconds; absent, malformed
// or negative is 0.
func retryAfter(h http.Header) time.Duration {
	n, err := strconv.Atoi(strings.TrimSpace(h.Get("Retry-After")))
	if err != nil || n < 0 {
		return 0
	}
	return time.Duration(n) * time.Second
}

// headerOf is the response header of a generated response's HTTPResponse, nil
// when there is none.
func headerOf(r *http.Response) http.Header {
	if r == nil {
		return nil
	}
	return r.Header
}

// httpResponseOf reads the HTTPResponse member every generated response has.
func httpResponseOf(r any) *http.Response {
	v := reflect.ValueOf(r)
	if v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil
		}
		v = v.Elem()
	}
	if v.Kind() != reflect.Struct {
		return nil
	}
	if hr, ok := v.FieldByName("HTTPResponse").Interface().(*http.Response); ok {
		return hr
	}
	return nil
}

// unparsable is a 2xx whose body did not parse as the documented shape:
// internal and not retryable (the server did act, so a retry could repeat it).
func unparsable(status int) error {
	return &ab2bus.Error{Code: ab2bus.CodeInternal, Message: fmt.Sprintf("HTTP %d: response body is not the documented shape", status), Retryable: false}
}

// key maps an idempotency key to the optional header: "" omits it.
func key(k string) *string {
	if k == "" {
		return nil
	}
	return &k
}

// seconds maps the watch timeout to the optional query parameter: 0 omits it
// and a negative duration stays negative for the server to reject.
func seconds(d time.Duration) *float64 {
	if d == 0 {
		return nil
	}
	s := d.Seconds()
	return &s
}
