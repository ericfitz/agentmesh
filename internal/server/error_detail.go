package server

import (
	"context"
	"errors"
	"fmt"
	"github.com/getkin/kin-openapi/routers"
	"net/http"
	"regexp"
	"slices"
	"strconv"
	"strings"
	"sync"

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
		var own string
		if p := e.JSONPointer(); len(p) > 0 {
			own = "/" + strings.Join(p, "/")
		}
		for _, c := range schemaCauses(e, own) {
			*parts = append(*parts, prefixed(where, c))
		}
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

// A quoted literal as the validator prints it: single quotes, with \' \\ \n
// and the like inside.
const quoted = `'(?:[^'\\]|\\.)*'`

var (
	// causeLine is one cause of a jsonschema failure: "- at '<pointer>': <message>".
	causeLine = regexp.MustCompile(`(?m)^- at '((?:[^'\\]|\\.)*)': (.*)$`)
	// patternMessage is "'<submitted value>' does not match pattern '<pattern>'".
	patternMessage = regexp.MustCompile(`^` + quoted + ` does not match pattern (` + quoted + `)$`)
	// memberMessage is the validator's refusal of a member the schema does not
	// declare; it names the caller's member.
	memberMessage = regexp.MustCompile(`^additional propert(?:y|ies) .* not allowed$`)
)

// schemaCauses words a SchemaError one line per cause: the pointer (with every
// segment that is not a declared member name or an index masked) and a message
// from a fixed set of shapes. Nothing the caller chose survives: not a value
// (the validator quotes it, escaped), not a member name, not a map key. The
// reason of a failure of the JSON Schema 2020-12 validator is a wrapper holding
// one "- at" line per cause; any other reason is one cause at the error's own
// pointer.
func schemaCauses(e *openapi3.SchemaError, own string) []string {
	type cause struct{ ptr, msg string }
	var causes []cause
	if rest, ok := strings.CutPrefix(e.Reason, "jsonschema validation failed with "); ok {
		for _, m := range causeLine.FindAllStringSubmatch(rest, -1) {
			causes = append(causes, cause{m[1], m[2]})
		}
	}
	if len(causes) == 0 {
		msg := e.Reason
		if msg == "" {
			msg = fmt.Sprintf("does not match the schema's %q", e.SchemaField)
		}
		if e.SchemaField == "additionalProperties" {
			msg = "additional properties not allowed"
		}
		causes = []cause{{own, msg}}
	}
	var out []string
	for _, c := range causes {
		line := plainMessage(c.msg)
		if ptr := maskPointer(c.ptr); ptr != "" {
			line = ptr + ": " + line
		}
		if !slices.Contains(out, line) {
			out = append(out, line)
		}
	}
	return out
}

// plainMessage keeps a validator message only in a shape known not to carry a
// submitted value or member name.
func plainMessage(msg string) string {
	switch {
	case patternMessage.MatchString(msg):
		return "does not match pattern " + patternMessage.FindStringSubmatch(msg)[1]
	case memberMessage.MatchString(msg), strings.HasSuffix(msg, "is unsupported"):
		return "has a member the schema does not declare"
	case !strings.ContainsAny(msg, `'"`),
		strings.HasPrefix(msg, "missing propert"), // names come from the schema
		strings.HasPrefix(msg, "value must be one of "), strings.HasPrefix(msg, "value is not one of the allowed values ["), strings.HasPrefix(msg, "value must be '"):
		return msg
	}
	return "is not valid"
}

// maskPointer masks every segment of a JSON pointer that the schemas of the
// document do not account for: an index is kept only below a declared array
// member (or at the root), and a name only when some schema declares it. Any
// other segment is a key the caller chose (a metadata key, even a numeric one).
func maskPointer(ptr string) string {
	if ptr == "" {
		return ""
	}
	names, arrays := declaredNames()
	segs := strings.Split(strings.TrimPrefix(ptr, "/"), "/")
	for i, seg := range segs {
		n, err := strconv.Atoi(seg)
		if err == nil && n >= 0 && strconv.Itoa(n) == seg {
			if i == 0 || arrays[segs[i-1]] {
				continue
			}
			segs[i] = "<key>"
			continue
		}
		if !names[seg] {
			segs[i] = "<key>"
		}
	}
	return "/" + strings.Join(segs, "/")
}

var (
	namesOnce sync.Once
	namesSet  map[string]bool
	arraysSet map[string]bool // declared members whose schema is an array
)

// declaredNames is every property name any schema of the embedded document
// declares.
func declaredNames() (names, arrays map[string]bool) {
	namesOnce.Do(func() {
		namesSet = map[string]bool{}
		arraysSet = map[string]bool{}
		seen := map[*openapi3.Schema]bool{}
		var walk func(r *openapi3.SchemaRef)
		walk = func(r *openapi3.SchemaRef) {
			if r == nil || r.Value == nil || seen[r.Value] {
				return
			}
			sc := r.Value
			seen[sc] = true
			for name, prop := range sc.Properties {
				namesSet[name] = true
				if prop != nil && prop.Value != nil && (prop.Value.Items != nil || prop.Value.Type.Includes("array")) {
					arraysSet[name] = true
				}
				walk(prop)
			}
			walk(sc.Items)
			walk(sc.AdditionalProperties.Schema)
			for _, group := range []openapi3.SchemaRefs{sc.AllOf, sc.OneOf, sc.AnyOf} {
				for _, one := range group {
					walk(one)
				}
			}
		}
		for _, sc := range Spec().Components.Schemas {
			walk(sc)
		}
	})
	return namesSet, arraysSet
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
	// Any other status carries a fixed text: the framework's own wording can
	// quote the request.
	if status == http.StatusNotFound {
		if errors.Is(err, routers.ErrMethodNotAllowed) {
			return "method not allowed"
		}
		return "no matching operation was found"
	}
	return "the request could not be validated"
}
