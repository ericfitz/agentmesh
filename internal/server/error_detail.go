package server

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"github.com/getkin/kin-openapi/openapi3filter"

	"github.com/ericfitz/agentmesh/internal/gen"
)

// maxDetailParts bounds how many reasons one detail lists.
const maxDetailParts = 8

// validationDetail words a request-validator refusal for a problem's detail:
// the JSON pointer (or the parameter) and the reason, never the schema and
// never the submitted value. kin-openapi's own text carries both (it dumps
// the schema and the value under "Schema:" and "Value:"), and a value may be a
// token (issue #30, CATS finding RB2). An error of a kind not handled here is
// worded without its text.
func validationDetail(err error) string {
	var parts []string
	collectDetail(err, "", &parts)
	if len(parts) == 0 {
		return "the request is not valid"
	}
	if len(parts) > maxDetailParts {
		parts = append(parts[:maxDetailParts], "and more")
	}
	return strings.Join(parts, "; ")
}

func collectDetail(err error, where string, parts *[]string) {
	switch e := err.(type) {
	case nil:
	case openapi3.MultiError:
		for _, one := range e {
			collectDetail(one, where, parts)
		}
	case *openapi3filter.RequestError:
		switch {
		case e.Parameter != nil:
			where = fmt.Sprintf("parameter %q in %s", e.Parameter.Name, e.Parameter.In)
		case e.RequestBody != nil:
			where = "request body"
		}
		before := len(*parts)
		collectDetail(e.Err, where, parts)
		if len(*parts) == before {
			*parts = append(*parts, prefixed(where, requestErrorReason(e)))
		}
	case *openapi3.SchemaError:
		reason := plainReason(e.Reason, e.Value)
		switch {
		case e.SchemaField == "additionalProperties" || strings.HasSuffix(reason, "is unsupported"):
			// The reason names the submitted member.
			reason = "has a member the schema does not declare"
		case reason == "":
			reason = fmt.Sprintf("does not match the schema's %q", e.SchemaField)
		}
		if p := e.JSONPointer(); len(p) > 0 {
			reason = "/" + strings.Join(p, "/") + ": " + reason
		}
		*parts = append(*parts, prefixed(where, reason))
	case *openapi3filter.ParseError:
		reason := e.Reason
		if reason == "" {
			reason = "is not in the expected format"
		}
		*parts = append(*parts, prefixed(where, reason))
	default:
		if errors.Is(err, openapi3filter.ErrInvalidRequired) || errors.Is(err, openapi3filter.ErrInvalidEmptyValue) {
			*parts = append(*parts, prefixed(where, err.Error()))
		}
	}
}

// jsonschemaPreamble is the wrapper kin-openapi puts around a message of the
// JSON Schema 2020-12 validator, with the pointer it repeats.
var jsonschemaPreamble = regexp.MustCompile(`(?s)^jsonschema validation failed with '[^']*'\n- at '[^']*': `)

// plainReason strips the validator's wrapper from reason and replaces the
// submitted string, which the validator's messages quote ('bad tag' does not
// match pattern ...), with "the value".
func plainReason(reason string, value any) string {
	reason = jsonschemaPreamble.ReplaceAllString(reason, "")
	reason = strings.ReplaceAll(reason, "\n- at '", "; at '")
	if v, ok := value.(string); ok && v != "" {
		for _, q := range []string{"'", `"`} {
			reason = strings.ReplaceAll(reason, q+v+q, "the value")
		}
	}
	return reason
}

// requestErrorReason is the fixed wording of a request error that carries no
// schema or parse error. The framework's own reason can quote a header value
// or a decoder's text, so only known reasons are repeated.
func requestErrorReason(e *openapi3filter.RequestError) string {
	switch {
	case errors.Is(e.Err, openapi3filter.ErrInvalidRequired), errors.Is(e.Err, openapi3filter.ErrInvalidEmptyValue):
		return e.Err.Error()
	case e.Reason == "failed to decode request body":
		return "is not well-formed for its Content-Type"
	case strings.Contains(e.Reason, "header Content-Type"):
		return "has a Content-Type the operation does not accept"
	case e.RequestBody != nil && e.Err != nil && e.Err.Error() == "request body not allowed for this request":
		return "is not allowed for this request"
	}
	return "is not valid"
}

func prefixed(where, reason string) string {
	if where == "" {
		return reason
	}
	return where + ": " + reason
}

// frameworkDetail words an error of the generated binder (a parameter that
// does not bind, a body that does not decode) without the offending value:
// the binder's own text quotes it.
func frameworkDetail(err error) string {
	var (
		format   *gen.InvalidParamFormatError
		required *gen.RequiredParamError
		header   *gen.RequiredHeaderError
		many     *gen.TooManyValuesForParamError
		unmarsh  *gen.UnmarshalingParamError
	)
	switch {
	case errors.As(err, &format):
		return fmt.Sprintf("invalid format for parameter %s", format.ParamName)
	case errors.As(err, &required):
		return required.Error()
	case errors.As(err, &header):
		return header.Error()
	case errors.As(err, &many):
		return many.Error()
	case errors.As(err, &unmarsh):
		return fmt.Sprintf("parameter %s is not valid JSON", unmarsh.ParamName)
	}
	return "the request could not be decoded"
}

// requestDetail is the detail of a refusal by the validator middleware.
func requestDetail(ctx context.Context, err error, status int) string {
	if status == http.StatusUnauthorized {
		// An authenticator's refusal keeps its text; a request with no
		// credential gets one fixed sentence, not the validator's.
		if aerr := authErrorFrom(ctx); aerr != nil {
			return aerr.Error()
		}
		return "a bearer token is required"
	}
	if status == http.StatusBadRequest || status == http.StatusUnprocessableEntity {
		return validationDetail(err)
	}
	return err.Error()
}
