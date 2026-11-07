package bus

import (
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"time"
)

// Code is the machine-readable error code, the enumeration that Milestone 4
// writes into the schema (spec section 3.3).
type Code string

// The complete code set; a function that needs another code reports it
// instead of inventing one.
const (
	// CodeValidation: the input is malformed or names an unknown value.
	CodeValidation Code = "validation"
	// CodeNotFound: a named channel, message, task or identity does not exist.
	CodeNotFound Code = "not_found"
	// CodeConflict: a duplicate name, the task owner guard, or an idempotency
	// key reused with a different payload.
	CodeConflict Code = "conflict"
	// CodeForbidden: an ACL or administrator refusal (Decision 80).
	CodeForbidden Code = "forbidden"
	// CodeNotRegistered: the authenticated name is not a registered identity.
	CodeNotRegistered Code = "not_registered"
	// CodeRateLimited: a per-identity bucket could not pay; retryable.
	CodeRateLimited Code = "rate_limited"
	// CodeReplaced: a newer watch replaced this one (Decision 42).
	CodeReplaced Code = "replaced"
	// CodeSessionLapsed: the session lease lapsed; resumable with the token.
	CodeSessionLapsed Code = "session_lapsed"
	// CodeSessionClosed: the session was closed and can never resume.
	CodeSessionClosed Code = "session_closed"
	// CodeUnavailable: the store or the write inspector reported a retryable
	// failure (Decision 69; write inspection).
	CodeUnavailable Code = "unavailable"
	// CodeInternal: an unexpected failure; retryable, as in v1.
	CodeInternal Code = "internal"
	// CodeUnauthenticated: a failed security requirement at the HTTP layer
	// (Milestone 4, spec section 3.3); the core never produces it.
	CodeUnauthenticated Code = "unauthenticated"
	// CodeInspectionRejected: the write inspector refused the content (ADR
	// 0013); not retryable.
	CodeInspectionRejected Code = "inspection_rejected"
	// CodePayloadTooLarge: the request body exceeds the server's limit; not
	// retryable (HTTP layer only, issue #33).
	CodePayloadTooLarge Code = "payload_too_large"
)

var validCodes = map[Code]bool{
	CodeValidation: true, CodeNotFound: true, CodeConflict: true, CodeForbidden: true,
	CodeNotRegistered: true, CodeRateLimited: true, CodeReplaced: true,
	CodeSessionLapsed: true, CodeSessionClosed: true, CodeUnavailable: true, CodeInternal: true,
	CodeUnauthenticated: true, CodeInspectionRejected: true,
	CodePayloadTooLarge: true,
}

// ValidCode reports whether c is one of the codes above.
func ValidCode(c Code) bool { return validCodes[c] }

// Codes returns every valid code, sorted, as a fresh slice.
func Codes() []Code {
	out := make([]Code, 0, len(validCodes))
	for c := range validCodes {
		out = append(out, c)
	}
	slices.Sort(out)
	return out
}

// Error is the application error carried to the caller.
type Error struct {
	Code      Code   `json:"code"`
	Message   string `json:"message"`
	Retryable bool   `json:"retryable"`
	// RetryAfter is how long the caller should wait before retrying; set on
	// rate_limited from the limiter's wait (the server's Retry-After header),
	// zero when unknown. On the local transport it is the limiter's raw
	// duration; on the remote Bus it is whole seconds (the header's value). It
	// is not part of the JSON form, so Error() is unchanged.
	RetryAfter time.Duration `json:"-"`
}

// Error renders the JSON form, as v1 did.
func (e *Error) Error() string {
	j, err := json.Marshal(e)
	if err != nil {
		return fmt.Sprintf(`{"code":"internal","message":%q,"retryable":true}`, err.Error())
	}
	return string(j)
}

// MaxErrorMessageBytes bounds a rendered error message so an oversized
// caller-controlled string (a cursor, channel name, key, ...) interpolated
// into the message cannot bypass result budgets.
const MaxErrorMessageBytes = 1024

// TruncateErrorMessage bounds s to MaxErrorMessageBytes, appending a
// trailing "…" marker when truncated. Truncation is byte-based (not
// rune-aware) since the bound exists purely to cap size.
func TruncateErrorMessage(s string) string {
	if len(s) <= MaxErrorMessageBytes {
		return s
	}
	return s[:MaxErrorMessageBytes-len("…")] + "…"
}

// Errorf builds an Error with a bounded message. It panics on a code outside
// the set, which is a programming error.
func Errorf(code Code, retryable bool, format string, args ...any) *Error {
	if !ValidCode(code) {
		panic(fmt.Sprintf("bus: invalid error code %q", string(code)))
	}
	return &Error{Code: code, Message: TruncateErrorMessage(fmt.Sprintf(format, args...)), Retryable: retryable}
}

// Internal wraps an unexpected error so the caller sees code "internal". nil
// stays nil and an *Error passes through unchanged.
func Internal(err error) error {
	if err == nil {
		return nil
	}
	var be *Error
	if errors.As(err, &be) {
		return be
	}
	return &Error{Code: CodeInternal, Message: TruncateErrorMessage(err.Error()), Retryable: true}
}

// CodeOf returns the code of the *Error in err's chain, or "" when there is none.
func CodeOf(err error) Code {
	var be *Error
	if errors.As(err, &be) {
		return be.Code
	}
	return ""
}
