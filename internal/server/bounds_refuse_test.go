package server

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/core"

	"github.com/getkin/kin-openapi/openapi3"
)

// probeExceptions names the bounds rows no validator probe can reach, each with
// its reason. A row with neither a probe nor an entry here fails the coverage
// subtest; an entry for a row that no longer exists fails the stale one. The
// int64 rows are not exceptions: their lower bound is probed (the upper bound
// is the type, TestInt64OverflowRefused). The metadata key length is no row at
// all (core-only, ruling 11).
var probeExceptions = map[string]string{}

// probeStep is one move from a schema to the field below it: a property name,
// an array item ("[]") or a map value ("<key>").
type probeStep string

// schemaAlias gives a schema that only occurs nested the root schema and the
// steps that reach it, so a probe can build a request around it.
var schemaAlias = map[string]struct {
	root  string
	steps []probeStep
}{
	"ACLEntry":      {"CreateChannelRequest", []probeStep{"acl", "[]"}},
	"OfferedCursor": {"OpenSessionRequest", []probeStep{"cursors", "[]"}},
	"JWK":           {"RegisterRequest", []probeStep{"public_key_jwk"}},
}

type opRef struct {
	id     string
	method string
	path   string
	op     *openapi3.Operation
	params openapi3.Parameters // path-level then operation-level
}

func listOps(doc *openapi3.T) []opRef {
	var out []opRef
	paths := make([]string, 0)
	for p := range doc.Paths.Map() {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	for _, p := range paths {
		item := doc.Paths.Map()[p]
		methods := make([]string, 0)
		for m := range item.Operations() {
			methods = append(methods, m)
		}
		sort.Strings(methods)
		for _, m := range methods {
			op := item.Operations()[m]
			ps := append(append(openapi3.Parameters{}, item.Parameters...), op.Parameters...)
			out = append(out, opRef{id: lowerFirst(op.OperationID), method: m, path: p, op: op, params: ps})
		}
	}
	return out
}

// samplePrim is the smallest valid scalar of s.
func samplePrim(s *openapi3.Schema) any {
	if len(s.Enum) > 0 {
		return s.Enum[0]
	}
	switch {
	case isType(s, "integer"), isType(s, "number"):
		v := 1.0
		if s.Min != nil && *s.Min > v {
			v = *s.Min
		}
		return v
	case isType(s, "boolean"):
		return false
	case isType(s, "array"):
		out := []any{}
		for k := uint64(0); k < s.MinItems; k++ {
			out = append(out, sample(s.Items))
		}
		return out
	case isType(s, "object"):
		return sampleAlong(&openapi3.SchemaRef{Value: s}, nil, nil)
	}
	return strings.Repeat("a", max(1, int(s.MinLength)))
}

func sample(sr *openapi3.SchemaRef) any { return samplePrim(sr.Value) }

// objectSchemas is s and its allOf members, whose properties merge.
func objectSchemas(s *openapi3.Schema) []*openapi3.Schema {
	out := []*openapi3.Schema{s}
	for _, m := range s.AllOf {
		out = append(out, objectSchemas(m.Value)...)
	}
	return out
}

// sampleAlong builds the smallest valid value of sr that holds leaf at the end
// of steps (leaf is returned as is when steps is empty); every property the
// path passes is included even when optional.
func sampleAlong(sr *openapi3.SchemaRef, steps []probeStep, leaf any) any {
	if len(steps) == 0 {
		if leaf != nil {
			return leaf
		}
	}
	s := sr.Value
	if len(steps) == 0 {
		if !isType(s, "object") {
			return samplePrim(s)
		}
		obj := map[string]any{}
		for _, o := range objectSchemas(s) {
			for _, r := range o.Required {
				for _, p := range objectSchemas(s) {
					if ps, ok := p.Properties[r]; ok {
						obj[r] = sample(ps)
					}
				}
			}
		}
		return obj
	}
	switch steps[0] {
	case "[]":
		return []any{sampleAlong(s.Items, steps[1:], leaf)}
	case "<key>":
		return map[string]any{"k": sampleAlong(s.AdditionalProperties.Schema, steps[1:], leaf)}
	}
	obj := sampleAlong(sr, nil, nil).(map[string]any)
	for _, o := range objectSchemas(s) {
		if ps, ok := o.Properties[string(steps[0])]; ok {
			obj[string(steps[0])] = sampleAlong(ps, steps[1:], leaf)
			return obj
		}
	}
	panic(fmt.Sprintf("no property %q", steps[0]))
}

// withCommas formats n the way kin-openapi's keyword errors do (1,025).
func withCommas(n int) string {
	s := strconv.Itoa(n)
	for i := len(s) - 3; i > 0; i -= 3 {
		s = s[:i] + "," + s[i:]
	}
	return s
}

// gotWant is the two spellings of kin's keyword refusal (the plain one for a
// short bound, the one with grouped digits for a long one); the server drops
// the submitted number ("got N") and keeps the bound.
func gotWant(kw string, got, want int) []string {
	return []string{
		fmt.Sprintf("%s: want %d", kw, want),
		fmt.Sprintf("%s: want %s", kw, withCommas(want)),
	}
}

// overValue is the value that breaks the row's bound by one, and the phrase
// kin-openapi's refusal carries.
func overValue(b bound, l leaf) (v any, phrases []string, err error) {
	s := l.schema
	switch l.kind {
	case "string":
		if b.MaxLength == nil {
			return nil, nil, fmt.Errorf("a string row without a maxLength")
		}
		n := *b.MaxLength + 1
		ch := "a"
		switch {
		case b.Pattern == "^[0-9]+$":
			ch = "1"
		case b.Pattern == "" && b.Unit == codePoints:
			ch = "é"
		}
		return strings.Repeat(ch, n), append(gotWant("maxLength", n, *b.MaxLength), fmt.Sprintf("maximum string length is %d", *b.MaxLength)), nil
	case "array":
		if b.MaxItems == nil {
			return nil, nil, fmt.Errorf("an array row without a maxItems")
		}
		items := make([]any, *b.MaxItems+1)
		for i := range items {
			items[i] = sample(s.Items)
		}
		return items, append(gotWant("maxItems", len(items), *b.MaxItems), fmt.Sprintf("maximum number of items is %d", *b.MaxItems)), nil
	case "map":
		if b.MaxProps == nil {
			return nil, nil, fmt.Errorf("a map row without a maxProperties")
		}
		m := map[string]any{}
		var val any = "a"
		if s.AdditionalProperties.Schema != nil {
			val = sample(s.AdditionalProperties.Schema)
		}
		for i := 0; i <= *b.MaxProps; i++ {
			m["k"+strconv.Itoa(i)] = val
		}
		return m, append(gotWant("maxProperties", len(m), *b.MaxProps), fmt.Sprintf("there must be at most %d properties", *b.MaxProps)), nil
	case "integer", "number":
		if b.Max != nil && b.Format != "int64" {
			return *b.Max + 1, []string{"maximum: want", "number must be at most"}, nil
		}
		if b.Min != nil {
			return *b.Min - 1, []string{"minimum: want", "number must be at least"}, nil
		}
	}
	return nil, nil, fmt.Errorf("no over-bound value for a %s row", l.kind)
}

// probeRequest is one request built for a row: the method, the path with its
// query, the headers and the body.
type probeRequest struct {
	method, path string
	header       http.Header
	body         []byte
	contentType  string
}

// buildProbe resolves key to an operation and builds the request that carries
// over at the field the key names.
func buildProbe(doc *openapi3.T, key string, over any) (probeRequest, error) {
	ops := listOps(doc)
	var target opRef
	var found bool
	var paramIn, paramName string
	var bodyRoot *openapi3.SchemaRef
	var steps []probeStep
	var body bool

	switch {
	case strings.HasPrefix(key, "parameters/"):
		name := strings.TrimPrefix(key, "parameters/")
	outer:
		for _, o := range ops {
			for _, p := range o.params {
				if p.Ref != "" && refName(p.Ref) == name {
					target, found, paramIn, paramName = o, true, p.Value.In, p.Value.Name
					break outer
				}
			}
		}
	case strings.HasPrefix(key, "operations/"):
		parts := strings.SplitN(strings.TrimPrefix(key, "operations/"), "/", 3)
		if len(parts) == 2 && parts[1] == "body" {
			parts = append(parts, "")
		}
		if len(parts) != 3 {
			return probeRequest{}, fmt.Errorf("malformed key")
		}
		for _, o := range ops {
			if o.id == parts[0] {
				target, found = o, true
			}
		}
		if parts[1] == "body" {
			body = true
		} else {
			paramIn, paramName = parts[1], strings.TrimSuffix(parts[2], "[]")
			if strings.HasSuffix(parts[2], "[]") {
				steps = []probeStep{"[]"}
			}
		}
	case strings.HasPrefix(key, "schemas/"):
		rest := strings.TrimPrefix(key, "schemas/")
		cut := strings.IndexAny(rest, ".[")
		name := rest
		tail := ""
		if cut >= 0 {
			name, tail = rest[:cut], rest[cut:]
		}
		if a, ok := schemaAlias[name]; ok {
			name = a.root
			steps = append(steps, a.steps...)
		}
		for tail != "" {
			switch {
			case strings.HasPrefix(tail, "[]"):
				steps = append(steps, "[]")
				tail = tail[2:]
			case strings.HasPrefix(tail, ".<key>"):
				steps = append(steps, "<key>")
				tail = tail[len(".<key>"):]
			case strings.HasPrefix(tail, "."):
				tail = tail[1:]
				end := strings.IndexAny(tail, ".[")
				if end < 0 {
					end = len(tail)
				}
				steps = append(steps, probeStep(tail[:end]))
				tail = tail[end:]
			default:
				return probeRequest{}, fmt.Errorf("cannot parse key tail %q", tail)
			}
		}
		for _, o := range ops {
			if o.op.RequestBody == nil || o.op.RequestBody.Value == nil {
				continue
			}
			for _, mt := range o.op.RequestBody.Value.Content {
				if mt.Schema != nil && mt.Schema.Ref != "" && refName(mt.Schema.Ref) == name {
					target, found, body, bodyRoot = o, true, true, mt.Schema
				}
			}
			if found {
				break
			}
		}
	}
	if !found {
		return probeRequest{}, fmt.Errorf("no operation carries %s", key)
	}

	pr := probeRequest{method: strings.ToUpper(target.method), header: http.Header{}}
	path := target.path
	q := url.Values{}
	setQuery := func(name string, v any, explode bool) {
		switch x := v.(type) {
		case []any:
			if !explode {
				parts := make([]string, len(x))
				for i, it := range x {
					parts[i] = scalarString(it)
				}
				q.Set(name, strings.Join(parts, ","))
				return
			}
			for _, it := range x {
				q.Add(name, scalarString(it))
			}
		default:
			q.Set(name, scalarString(v))
		}
	}
	for _, p := range target.params {
		pv := p.Value
		isTarget := pv.In == paramIn && pv.Name == paramName
		var v any
		switch {
		case isTarget && len(steps) == 0:
			v = over
		case isTarget:
			v = []any{over}
		case pv.Required || pv.In == "path":
			v = sample(pv.Schema)
		default:
			continue
		}
		switch pv.In {
		case "path":
			path = strings.ReplaceAll(path, "{"+pv.Name+"}", url.PathEscape(scalarString(v)))
		case "query":
			setQuery(pv.Name, v, pv.Explode == nil || *pv.Explode)
		case "header":
			pr.header.Set(pv.Name, scalarString(v))
		}
	}
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	pr.path = path

	rb := target.op.RequestBody
	if body && rb != nil && rb.Value != nil {
		for ct, mt := range rb.Value.Content {
			pr.contentType = ct
			root := mt.Schema
			if bodyRoot != nil {
				root = bodyRoot
			}
			val := sampleAlong(root, steps, over)
			if len(steps) == 0 && over != nil {
				val = over
			}
			if ct == "application/x-www-form-urlencoded" {
				form := url.Values{}
				for k, x := range val.(map[string]any) {
					form.Set(k, scalarString(x))
				}
				pr.body = []byte(form.Encode())
			} else {
				b, err := json.Marshal(val)
				if err != nil {
					return pr, err
				}
				pr.body = b
			}
			break
		}
	} else if rb != nil && rb.Value != nil && rb.Value.Required {
		for ct, mt := range rb.Value.Content {
			pr.contentType = ct
			b, _ := json.Marshal(sample(mt.Schema))
			pr.body = b
		}
	}
	return pr, nil
}

func scalarString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	}
	return fmt.Sprint(v)
}

// TestValidatorRefusesOverBound sends one request per bounds row with that
// field one over its bound and expects the request validator, not the core, to
// refuse it: kin-openapi's own phrase is in the problem's detail (for the token
// endpoint, whose validator answer is the fixed RFC 6749 invalid_request text,
// that text, which the handler's own size check never writes).
func TestValidatorRefusesOverBound(t *testing.T) {
	doc := Spec()
	leaves, _ := walkRequests(doc)
	e := newEnv(t, envOptions{cfg: func(c *core.Config) { c.MaxMessageKiB = core.MessageKiBCeiling }})
	e.identity("alice", false)

	keysSorted := make([]string, 0, len(bounds))
	for k := range bounds {
		keysSorted = append(keysSorted, k)
	}
	sort.Strings(keysSorted)

	for _, k := range keysSorted {
		if reason, ok := probeExceptions[k]; ok {
			_ = reason
			continue
		}
		t.Run(k, func(t *testing.T) {
			l, ok := leaves[k]
			if !ok {
				t.Skip("stale row: see the stale subtest")
			}
			over, phrases, err := overValue(bounds[k], l)
			if err != nil {
				t.Fatalf("no probe: %v", err)
			}
			pr, err := buildProbe(doc, k, over)
			if err != nil {
				t.Fatalf("no probe: %v", err)
			}
			var rd io.Reader
			if pr.body != nil {
				rd = strings.NewReader(string(pr.body))
			}
			req, err := http.NewRequest(pr.method, "http://inproc"+pr.path, rd)
			if err != nil {
				t.Fatal(err)
			}
			for h, vs := range pr.header {
				req.Header[h] = vs
			}
			if pr.contentType != "" {
				req.Header.Set("Content-Type", pr.contentType)
			}
			resp := e.raw("alice", req)
			raw, _ := io.ReadAll(resp.Body)
			if resp.StatusCode != http.StatusBadRequest {
				t.Fatalf("%s %s: status %d, want 400: %.300s", pr.method, pr.path, resp.StatusCode, raw)
			}
			if strings.HasPrefix(k, "schemas/TokenRequest.") {
				var ob struct {
					Error       string `json:"error"`
					Description string `json:"error_description"`
				}
				if err := json.Unmarshal(raw, &ob); err != nil || ob.Error != "invalid_request" ||
					!strings.Contains(ob.Description, "not a well-formed") {
					t.Fatalf("token body %.300s: want invalid_request from the validator", raw)
				}
				return
			}
			code, detail := problemDetail(t, raw)
			if code != "validation" {
				t.Errorf("code %q, want validation: %.300s", code, raw)
			}
			ok = false
			for _, p := range phrases {
				ok = ok || strings.Contains(detail, p)
			}
			if !ok {
				t.Errorf("detail lacks the validator's %q (the core may have refused): %.400s", phrases, detail)
			}
		})
	}

	t.Run("coverage", func(t *testing.T) {
		for _, k := range keysSorted {
			if _, ok := probeExceptions[k]; ok {
				continue
			}
			l, ok := leaves[k]
			if !ok {
				continue
			}
			over, _, err := overValue(bounds[k], l)
			if err != nil {
				t.Errorf("%s: %v", k, err)
				continue
			}
			if _, err := buildProbe(doc, k, over); err != nil {
				t.Errorf("%s: %v", k, err)
			}
		}
		for k := range leaves {
			if _, ok := bounds[k]; !ok {
				t.Errorf("%s: spec bound with no bounds row, so no probe", k)
			}
		}
	})

	t.Run("stale", func(t *testing.T) {
		for k := range bounds {
			if _, ok := leaves[k]; !ok {
				t.Errorf("row %q matches no bounded field of the spec", k)
			}
		}
		for k := range probeExceptions {
			if _, ok := bounds[k]; !ok {
				t.Errorf("exception %q has no row", k)
			}
		}
	})
}
