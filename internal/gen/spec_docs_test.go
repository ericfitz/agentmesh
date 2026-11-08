package gen_test

import (
	"context"
	"encoding/json"
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// Issue #35: every tag, operation, parameter, response, schema and property of
// api/openapi.yaml has a description, and every request body, response body,
// parameter and schema has an example. The two tests walk the embedded
// document. Until the area tasks finish, `undocumented` (the deny-list, in
// spec_docs_undocumented_test.go) names what is still bare; a listed element
// that passes is `stale`, an unlisted one that fails is `undocumented`.

// elemChk is one check of one element; name is empty for the element itself.
type elemChk struct {
	name string
	msg  string // empty when the check passes
}

// elem is one documented thing: kind/name is its deny-list key.
type elem struct {
	kind, name string
	checks     []elemChk
}

func (e *elem) key() string { return e.kind + "/" + e.name }

func (e *elem) failing() bool {
	for _, c := range e.checks {
		if c.msg != "" {
			return true
		}
	}
	return false
}

// elemSet collects elements in first-seen order; a key seen twice merges.
type elemSet struct {
	elems []*elem
	index map[string]*elem
}

func (s *elemSet) get(kind, name string) *elem {
	k := kind + "/" + name
	if s.index == nil {
		s.index = map[string]*elem{}
	}
	if e, ok := s.index[k]; ok {
		return e
	}
	e := &elem{kind: kind, name: name}
	s.index[k] = e
	s.elems = append(s.elems, e)
	return e
}

func (s *elemSet) add(kind, name, check, msg string) {
	e := s.get(kind, name)
	for i := range e.checks {
		if e.checks[i].name == check {
			if e.checks[i].msg == "" {
				e.checks[i].msg = msg
			}
			return
		}
	}
	e.checks = append(e.checks, elemChk{name: check, msg: msg})
}

func (s *elemSet) failingKeys() map[string]bool {
	out := map[string]bool{}
	for _, e := range s.elems {
		if e.failing() {
			out[e.key()] = true
		}
	}
	return out
}

func (s *elemSet) keys() map[string]bool {
	out := map[string]bool{}
	for _, e := range s.elems {
		out[e.key()] = true
	}
	return out
}

// Element kinds of the deny-list. Anything else in a key is refused.
var (
	descriptionKinds = map[string]bool{"tags": true, "operations": true, "parameters": true, "responses": true, "schemas": true, "properties": true}
	exampleKinds     = map[string]bool{"requests": true, "responses": true, "parameters": true, "schemas": true}
)

func allKinds() map[string]bool {
	out := map[string]bool{}
	maps.Copy(out, descriptionKinds)
	maps.Copy(out, exampleKinds)
	return out
}

// denyKeyProblems returns one text per deny-list key whose kind is not in
// allowed or which is not of the form kind/name.
func denyKeyProblems(list map[string]string, allowed map[string]bool) []string {
	var out []string
	for _, k := range slices.Sorted(maps.Keys(list)) {
		kind, name, ok := strings.Cut(k, "/")
		switch {
		case !ok || name == "":
			out = append(out, fmt.Sprintf("malformed deny-list key %q (want kind/name)", k))
		case !allowed[kind]:
			out = append(out, fmt.Sprintf("deny-list key %q has unknown kind %q", k, kind))
		}
	}
	return out
}

// ---- walking the document ----

func opIDs(doc *openapi3.T) (ids []string, byID map[string]*openapi3.Operation, items map[string]*openapi3.PathItem) {
	byID = map[string]*openapi3.Operation{}
	items = map[string]*openapi3.PathItem{}
	for _, item := range doc.Paths.Map() {
		for _, op := range item.Operations() {
			id := lowerFirst(op.OperationID)
			ids = append(ids, id)
			byID[id] = op
			items[id] = item
		}
	}
	slices.Sort(ids)
	return
}

// sharedName returns the components name a local reference ends in, and an
// error for a reference this walker does not recognize.
func sharedName(ref, section string) (string, error) {
	prefix := "#/components/" + section + "/"
	if !strings.HasPrefix(ref, prefix) {
		return "", fmt.Errorf("reference %q is not under %s", ref, prefix)
	}
	return strings.TrimPrefix(ref, prefix), nil
}

// walkMembers calls fn for every property reachable from s through inline
// schemas only (properties, inline items, inline allOf/oneOf/anyOf members,
// inline additionalProperties); path is the dotted member path.
func walkMembers(prefix string, s *openapi3.Schema, fn func(path string, ref *openapi3.SchemaRef)) {
	if s == nil {
		return
	}
	for _, name := range slices.Sorted(maps.Keys(s.Properties)) {
		ref := s.Properties[name]
		path := prefix + "." + name
		fn(path, ref)
		if ref.Ref == "" {
			walkMembers(path, ref.Value, fn)
		}
	}
	inline := func(r *openapi3.SchemaRef) {
		if r != nil && r.Ref == "" {
			walkMembers(prefix, r.Value, fn)
		}
	}
	inline(s.Items)
	for _, list := range []openapi3.SchemaRefs{s.AllOf, s.OneOf, s.AnyOf} {
		for _, r := range list {
			inline(r)
		}
	}
	inline(s.AdditionalProperties.Schema)
}

func countProperties(doc *openapi3.T) int {
	n := 0
	for _, name := range slices.Sorted(maps.Keys(doc.Components.Schemas)) {
		walkMembers(name, doc.Components.Schemas[name].Value, func(string, *openapi3.SchemaRef) { n++ })
	}
	return n
}

// paramKeys resolves the parameters of an operation (and of its path item) to
// deny-list names: a shared one by its components name, an inline one as
// <op>.<name>. Inline path-level parameters are refused: the document has none
// and the walker does not know their key.
func paramKeys(opID string, op *openapi3.Operation, item *openapi3.PathItem, visit func(name string, p *openapi3.Parameter, shared bool)) error {
	seen := map[string]bool{}
	for i, list := range []openapi3.Parameters{item.Parameters, op.Parameters} {
		isPath := i == 0
		for _, pr := range list {
			if pr.Ref != "" {
				if _, err := sharedName(pr.Ref, "parameters"); err != nil {
					return fmt.Errorf("%s: %w", opID, err)
				}
				continue // the shared parameter is its own element
			}
			if isPath {
				return fmt.Errorf("%s: an inline path-level parameter %q is not supported by the walker", opID, pr.Value.Name)
			}
			name := opID + "." + pr.Value.Name
			if seen[name] {
				return fmt.Errorf("%s: two inline parameters named %q", opID, pr.Value.Name)
			}
			seen[name] = true
			visit(name, pr.Value, false)
		}
	}
	return nil
}

// ---- the description audit ----

var (
	citesSource = regexp.MustCompile(`(spec [0-9]+(\.[0-9]+)*|ADR 00[0-9]{2}|Decision [0-9]+)`)
	accessWords = []string{"Open operation.", "Any registered identity.", "Administrator only.", "The channel ACL's", "Inside the caller's scope.", "ACL"}
	typeOnly    = regexp.MustCompile(`(?i)^(string|integer|number|boolean|array|object|int64|int32)\.?$`)
)

func isTypeName(desc string) bool {
	d := strings.TrimSpace(desc)
	return typeOnly.MatchString(d) || strings.HasPrefix(strings.ToLower(d), "array of")
}

func emptyMsg(what, s string) string {
	if strings.TrimSpace(s) == "" {
		return what + " is empty"
	}
	return ""
}

func descWalk(doc *openapi3.T) (*elemSet, error) {
	set := &elemSet{}
	for _, tag := range doc.Tags {
		set.add("tags", tag.Name, "", emptyMsg("description", tag.Description))
	}
	ids, byID, items := opIDs(doc)
	for _, id := range ids {
		op := byID[id]
		item := items[id]
		set.add("operations", id, "", firstMsg(
			emptyMsg("summary", op.Summary),
			func() string {
				if strings.Contains(strings.TrimSpace(op.Summary), "\n") {
					return "summary is not one line"
				}
				return ""
			}(),
			emptyMsg("description", op.Description)))
		set.add("operations", id, "cites-source", func() string {
			if !citesSource.MatchString(op.Description) {
				return "description cites no spec section, ADR or Decision"
			}
			return ""
		}())
		takesKey := false
		for _, list := range []openapi3.Parameters{item.Parameters, op.Parameters} {
			for _, pr := range list {
				if pr.Ref == "#/components/parameters/IdempotencyKeyParam" {
					takesKey = true
				}
			}
		}
		set.add("operations", id, "idempotency", func() string {
			if takesKey && !strings.Contains(op.Description, "Idempotency-Key") {
				return "takes the Idempotency-Key header; description must say how it is used"
			}
			if !takesKey && !strings.Contains(op.Description, "idempotency key") {
				return `takes no key; description must say "No idempotency key."`
			}
			return ""
		}())
		set.add("operations", id, "access", func() string {
			for _, w := range accessWords {
				if strings.Contains(op.Description, w) {
					return ""
				}
			}
			return "description states no access rule"
		}())
		set.add("operations", id, "request-body", func() string {
			if op.RequestBody != nil && op.RequestBody.Value != nil {
				return emptyMsg("request body description", op.RequestBody.Value.Description)
			}
			return ""
		}())
		if err := paramKeys(id, op, item, func(name string, p *openapi3.Parameter, _ bool) {
			set.add("parameters", name, "", emptyMsg("description", p.Description))
		}); err != nil {
			return nil, err
		}
		for _, status := range slices.Sorted(maps.Keys(op.Responses.Map())) {
			r := op.Responses.Map()[status]
			if r.Ref != "" {
				if _, err := sharedName(r.Ref, "responses"); err != nil {
					return nil, fmt.Errorf("%s %s: %w", id, status, err)
				}
				continue
			}
			set.add("responses", id+"."+status, "", respDescMsg(r.Value))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(doc.Components.Parameters)) {
		set.add("parameters", name, "", emptyMsg("description", doc.Components.Parameters[name].Value.Description))
	}
	for _, name := range slices.Sorted(maps.Keys(doc.Components.Responses)) {
		set.add("responses", name, "", respDescMsg(doc.Components.Responses[name].Value))
	}
	for _, name := range slices.Sorted(maps.Keys(doc.Components.Schemas)) {
		s := doc.Components.Schemas[name].Value
		set.add("schemas", name, "", emptyMsg("description", s.Description))
		walkMembers(name, s, func(path string, ref *openapi3.SchemaRef) {
			if ref.Ref != "" {
				return // inherits the target's description (ruling 5); the target is its own element
			}
			set.add("properties", path, "", emptyMsg("description", ref.Value.Description))
		})
	}
	return set, nil
}

func respDescMsg(r *openapi3.Response) string {
	if r.Description == nil {
		return "description is empty"
	}
	return emptyMsg("description", *r.Description)
}

func firstMsg(msgs ...string) string {
	for _, m := range msgs {
		if m != "" {
			return m
		}
	}
	return ""
}

// ---- the example audit ----

// effectiveExample is ruling 1: the media type's example, else the first of
// its examples (default when present, else by name), else the referenced or
// inline schema's example.
func effectiveExample(mt *openapi3.MediaType) (any, bool) {
	if mt.Example != nil {
		return mt.Example, true
	}
	if len(mt.Examples) > 0 {
		name := "default"
		if _, ok := mt.Examples[name]; !ok {
			name = slices.Sorted(maps.Keys(mt.Examples))[0]
		}
		if ex := mt.Examples[name]; ex != nil && ex.Value != nil && ex.Value.Value != nil {
			return ex.Value.Value, true
		}
		return nil, false
	}
	if mt.Schema != nil && mt.Schema.Value != nil && mt.Schema.Value.Example != nil {
		return mt.Schema.Value.Example, true
	}
	return nil, false
}

func paramExampleMsg(p *openapi3.Parameter) string {
	if p.Example != nil {
		return ""
	}
	if len(p.Examples) > 0 {
		for _, name := range slices.Sorted(maps.Keys(p.Examples)) {
			if ex := p.Examples[name]; ex == nil || ex.Value == nil || ex.Value.Value == nil {
				return fmt.Sprintf("example %q has no value", name)
			}
		}
		return ""
	}
	return "no example"
}

func contentExampleMsgs(content openapi3.Content) string {
	for _, ct := range slices.Sorted(maps.Keys(content)) {
		if _, ok := effectiveExample(content[ct]); !ok {
			return "no example for " + ct
		}
	}
	return ""
}

func exampleWalk(doc *openapi3.T) (*elemSet, error) {
	set := &elemSet{}
	ids, byID, items := opIDs(doc)
	for _, id := range ids {
		op := byID[id]
		item := items[id]
		if op.RequestBody != nil && op.RequestBody.Value != nil {
			content := op.RequestBody.Value.Content
			set.add("requests", id, "", contentExampleMsgs(content))
			for _, ct := range slices.Sorted(maps.Keys(content)) {
				mt := content[ct]
				for _, name := range slices.Sorted(maps.Keys(mt.Examples)) {
					msg := ""
					if ex := mt.Examples[name]; ex == nil || ex.Value == nil || ex.Value.Value == nil {
						msg = fmt.Sprintf("example %q of %s has no value", name, ct)
					}
					set.add("requests", id+"."+name, "", msg)
				}
			}
		}
		if err := paramKeys(id, op, item, func(name string, p *openapi3.Parameter, _ bool) {
			set.add("parameters", name, "", paramExampleMsg(p))
		}); err != nil {
			return nil, err
		}
		for _, status := range slices.Sorted(maps.Keys(op.Responses.Map())) {
			r := op.Responses.Map()[status]
			if r.Ref != "" {
				if _, err := sharedName(r.Ref, "responses"); err != nil {
					return nil, fmt.Errorf("%s %s: %w", id, status, err)
				}
				continue
			}
			set.add("responses", id+"."+status, "", contentExampleMsgs(r.Value.Content))
		}
	}
	for _, name := range slices.Sorted(maps.Keys(doc.Components.Parameters)) {
		set.add("parameters", name, "", paramExampleMsg(doc.Components.Parameters[name].Value))
	}
	for _, name := range slices.Sorted(maps.Keys(doc.Components.Responses)) {
		set.add("responses", name, "", contentExampleMsgs(doc.Components.Responses[name].Value.Content))
	}
	for _, name := range slices.Sorted(maps.Keys(doc.Components.Schemas)) {
		msg := ""
		if doc.Components.Schemas[name].Value.Example == nil {
			msg = "no example"
		}
		set.add("schemas", name, "", msg)
	}
	return set, nil
}

// ---- running an audit against the deny-list ----

func runAudit(t *testing.T, set, other *elemSet, kinds map[string]bool) {
	t.Helper()
	otherFailing := other.failingKeys()
	var order []string
	for k := range kinds {
		order = append(order, k)
	}
	slices.Sort(order)
	for _, kind := range order {
		t.Run(kind, func(t *testing.T) {
			for _, e := range set.elems {
				if e.kind != kind {
					continue
				}
				t.Run(e.name, func(t *testing.T) {
					key := e.key()
					_, listed := undocumented[key]
					if !e.failing() && listed && !otherFailing[key] {
						t.Errorf("stale: %s is documented; remove it from undocumented", key)
					}
					for _, c := range e.checks {
						body := func(t *testing.T) {
							if c.msg != "" && !listed {
								t.Errorf("undocumented: %s (%s)", key, c.msg)
							}
						}
						if c.name == "" {
							body(t)
						} else {
							t.Run(c.name, body)
						}
					}
				})
			}
		})
	}
	t.Run("deny-list", func(t *testing.T) {
		seen := set.keys()
		maps.Copy(seen, other.keys())
		for _, p := range denyKeyProblems(undocumented, allKinds()) {
			t.Error(p)
		}
		for _, k := range slices.Sorted(maps.Keys(undocumented)) {
			kind, _, _ := strings.Cut(k, "/")
			if kinds[kind] && !seen[k] {
				t.Errorf("stale: %s names no element of the document", k)
			}
		}
	})
}

func TestSpecDescriptions(t *testing.T) {
	doc := loadDoc(t)
	desc, err := descWalk(doc)
	if err != nil {
		t.Fatal(err)
	}
	ex, err := exampleWalk(doc)
	if err != nil {
		t.Fatal(err)
	}
	runAudit(t, desc, ex, descriptionKinds)
	t.Run("not-a-type", func(t *testing.T) {
		raw := marshalDoc(t, doc)
		walkJSON(raw, false, nil, func(path, s string) {
			if isTypeName(s) {
				t.Errorf("%s: description %q only restates the generator's type", path, s)
			}
		})
	})
	t.Run("counts", func(t *testing.T) {
		_, byID, _ := opIDs(doc)
		for _, c := range []struct {
			what       string
			got, wants int
		}{
			{"tags", len(doc.Tags), 9},
			{"operations", len(byID), 57},
			{"schemas", len(doc.Components.Schemas), 72},
			{"properties", countProperties(doc), propertyCount},
		} {
			if c.got != c.wants {
				t.Errorf("%s: %d, want %d", c.what, c.got, c.wants)
			}
		}
	})
}

// propertyCount is what countProperties reports over the component schemas
// (every property reached through inline schemas, `$ref` members included).
const propertyCount = 322

// ---- JSON-level checks over every example and description ----

func marshalDoc(t *testing.T, doc *openapi3.T) any {
	t.Helper()
	b, err := json.Marshal(doc)
	if err != nil {
		t.Fatalf("marshal document: %v", err)
	}
	var v any
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatalf("unmarshal document: %v", err)
	}
	return v
}

// walkJSON visits every `example` and every named `examples[*].value` (onExample)
// and every string `description` (onDesc) of a marshaled OpenAPI document. It
// does not descend into example values, enums or defaults, and treats the
// keys of a `properties` map as names, not keywords.
func walkJSON(node any, isNames bool, onExample func(path string, v any), onDesc func(path, s string)) {
	var rec func(n any, path string, names bool)
	rec = func(n any, path string, names bool) {
		switch v := n.(type) {
		case map[string]any:
			for _, k := range slices.Sorted(maps.Keys(v)) {
				child := path + "/" + k
				val := v[k]
				if names {
					rec(val, child, false)
					continue
				}
				switch k {
				case "example":
					if onExample != nil {
						onExample(child, val)
					}
				case "examples":
					if m, ok := val.(map[string]any); ok && onExample != nil {
						for _, name := range slices.Sorted(maps.Keys(m)) {
							if e, ok := m[name].(map[string]any); ok {
								if ev, ok := e["value"]; ok {
									onExample(child+"/"+name, ev)
								}
							}
						}
					}
				case "enum", "const", "default":
				case "description":
					if s, ok := val.(string); ok {
						if onDesc != nil {
							onDesc(child, s)
						}
					} else {
						rec(val, child, false)
					}
				case "properties":
					rec(val, child, true)
				default:
					rec(val, child, false)
				}
			}
		case []any:
			for i, e := range v {
				rec(e, fmt.Sprintf("%s/%d", path, i), false)
			}
		}
	}
	rec(node, "", isNames)
}

func walkStrings(v any, path string, fn func(path, s string)) {
	switch x := v.(type) {
	case string:
		fn(path, x)
	case map[string]any:
		for _, k := range slices.Sorted(maps.Keys(x)) {
			walkStrings(x[k], path+"/"+k, fn)
		}
	case []any:
		for i, e := range x {
			walkStrings(e, fmt.Sprintf("%s/%d", path, i), fn)
		}
	}
}

var (
	placeholderRe = regexp.MustCompile(`<[^<>]*>|\{\{|(?i:changeme)|\b(?:TODO|TBD)\b|(?i:\bx{3,}\b)`)
	hostAfterURL  = regexp.MustCompile(`://(?:[^/@\s"']*@)?([A-Za-z0-9.\-]+|\[[0-9a-fA-F:]+\])`)
	hostAfterAt   = regexp.MustCompile(`@([A-Za-z0-9][A-Za-z0-9.\-]*)`)
	reservedHosts = []string{"example.com", "example.org", "example.net", "example.test"}
	realValues    = []string{"trojanunicorn", "efitz", "fitzgerald", "github.com"}
)

// placeholderProblem returns why s is a placeholder, or "".
func placeholderProblem(s string) string {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "string", "example":
		return fmt.Sprintf("%q is a placeholder", s)
	}
	if m := placeholderRe.FindString(s); m != "" {
		return fmt.Sprintf("contains the placeholder %q", m)
	}
	return ""
}

func reservedHost(h string) bool {
	h = strings.ToLower(strings.TrimRight(h, "."))
	if h == "localhost" {
		return true
	}
	for _, d := range reservedHosts {
		if h == d || strings.HasSuffix(h, "."+d) {
			return true
		}
	}
	return false
}

// realValueProblem returns why s names a real host or account, or "".
func realValueProblem(s string) string {
	for _, re := range []*regexp.Regexp{hostAfterURL, hostAfterAt} {
		for _, m := range re.FindAllStringSubmatch(s, -1) {
			if !reservedHost(m[1]) {
				return fmt.Sprintf("host %q is neither localhost nor a reserved example domain", m[1])
			}
		}
	}
	low := strings.ToLower(s)
	for _, w := range realValues {
		if strings.Contains(low, w) {
			return fmt.Sprintf("contains %q", w)
		}
	}
	return ""
}

func eachExampleString(t *testing.T, doc *openapi3.T, fn func(path, s string)) {
	t.Helper()
	walkJSON(marshalDoc(t, doc), false, func(path string, v any) {
		walkStrings(v, path, fn)
	}, nil)
}

func TestSpecExamples(t *testing.T) {
	doc := loadDoc(t)
	ex, err := exampleWalk(doc)
	if err != nil {
		t.Fatal(err)
	}
	desc, err := descWalk(doc)
	if err != nil {
		t.Fatal(err)
	}
	runAudit(t, ex, desc, exampleKinds)
	t.Run("no-placeholders", func(t *testing.T) {
		eachExampleString(t, doc, func(path, s string) {
			if p := placeholderProblem(s); p != "" {
				t.Errorf("%s: %s", path, p)
			}
		})
	})
	t.Run("no-real-values", func(t *testing.T) {
		eachExampleString(t, doc, func(path, s string) {
			if p := realValueProblem(s); p != "" {
				t.Errorf("%s: %s", path, p)
			}
		})
	})
	t.Run("validates", func(t *testing.T) {
		if err := doc.Validate(context.Background()); err != nil {
			t.Fatalf("Validate: %v", err)
		}
		ids, byID, _ := opIDs(doc)
		for _, id := range ids {
			op := byID[id]
			if op.RequestBody == nil || op.RequestBody.Value == nil {
				continue
			}
			content := op.RequestBody.Value.Content
			for _, ct := range slices.Sorted(maps.Keys(content)) {
				mt := content[ct]
				if mt.Schema == nil || mt.Schema.Value == nil {
					continue
				}
				check := func(name string, v any) {
					if err := mt.Schema.Value.VisitJSON(v, openapi3.VisitAsRequest()); err != nil {
						t.Errorf("%s %s example %q is not a valid request: %v", id, ct, name, err)
					}
				}
				if v, ok := effectiveExample(mt); ok {
					check("default", v)
				}
				for _, name := range slices.Sorted(maps.Keys(mt.Examples)) {
					if e := mt.Examples[name]; e != nil && e.Value != nil && e.Value.Value != nil {
						check(name, e.Value.Value)
					}
				}
			}
		}
	})
}

// ---- the tests' own tests (Definition of Done C) ----

func TestSpecDocsHelpers(t *testing.T) {
	t.Run("not-a-type", func(t *testing.T) {
		for s, want := range map[string]bool{
			"string": true, "String.": true, " Integer ": true, "int64": true, "Array of strings": true, "array": true,
			"A string that names the channel": false, "Unix milliseconds": false, "objects are rejected": false,
		} {
			if got := isTypeName(s); got != want {
				t.Errorf("isTypeName(%q) = %v, want %v", s, got, want)
			}
		}
	})
	t.Run("placeholders", func(t *testing.T) {
		for s, want := range map[string]bool{
			"<channel>": true, "{{name}}": true, "TODO": true, "ship it TBD": true, "xxx": true, "changeme": true,
			"string": true, "Example": true, "example-resume-token": false, "Build 42 is green": false, "boxxxed-in": false,
		} {
			if got := placeholderProblem(s) != ""; got != want {
				t.Errorf("placeholderProblem(%q) = %v, want %v", s, got, want)
			}
		}
	})
	t.Run("real-values", func(t *testing.T) {
		for s, want := range map[string]bool{
			"http://localhost:8420/v1": false, "dana@example.com": false, "https://api.example.org/x": false,
			"https://user@host.example.net/p": false, "https://real.io/x": true, "bob@corp.io": true,
			"http://127.0.0.1:8420": true, "see github.com/x": true, "Trojanunicorn": true, "someone@example.com.evil.io": true,
		} {
			if got := realValueProblem(s) != ""; got != want {
				t.Errorf("realValueProblem(%q) = %v, want %v", s, got, want)
			}
		}
	})
	t.Run("effective-example", func(t *testing.T) {
		withSchema := &openapi3.SchemaRef{Value: &openapi3.Schema{Example: "schema"}}
		named := func(names ...string) openapi3.Examples {
			out := openapi3.Examples{}
			for _, n := range names {
				out[n] = &openapi3.ExampleRef{Value: &openapi3.Example{Value: n}}
			}
			return out
		}
		for _, c := range []struct {
			name string
			mt   *openapi3.MediaType
			want any
			ok   bool
		}{
			{"own", &openapi3.MediaType{Example: "own", Schema: withSchema}, "own", true},
			{"default wins", &openapi3.MediaType{Examples: named("b", "default"), Schema: withSchema}, "default", true},
			{"first by name", &openapi3.MediaType{Examples: named("b", "a")}, "a", true},
			{"schema", &openapi3.MediaType{Schema: withSchema}, "schema", true},
			{"none", &openapi3.MediaType{Schema: &openapi3.SchemaRef{Value: &openapi3.Schema{}}}, nil, false},
			{"valueless named example", &openapi3.MediaType{Examples: openapi3.Examples{"x": &openapi3.ExampleRef{Value: &openapi3.Example{}}}, Schema: withSchema}, nil, false},
		} {
			got, ok := effectiveExample(c.mt)
			if ok != c.ok || got != c.want {
				t.Errorf("%s: (%v, %v), want (%v, %v)", c.name, got, ok, c.want, c.ok)
			}
		}
	})
	t.Run("unknown-kinds-are-refused", func(t *testing.T) {
		got := denyKeyProblems(map[string]string{
			"operations/ok": "Task 2", "widgets/x": "Task 2", "noslash": "Task 2", "schemas/": "Task 2", "requests/op": "Task 3",
		}, allKinds())
		if len(got) != 3 {
			t.Fatalf("problems = %v, want 3 (unknown kind, no slash, empty name)", got)
		}
		for _, k := range []string{"requests", "tags"} {
			if !allKinds()[k] {
				t.Errorf("kind %q missing from allKinds", k)
			}
		}
		if p := denyKeyProblems(map[string]string{"requests/op": "x"}, descriptionKinds); len(p) != 1 {
			t.Errorf("an example kind in a description-only list: %v, want 1 problem", p)
		}
	})
	t.Run("walker-refuses-unrecognized-shapes", func(t *testing.T) {
		doc := &openapi3.T{OpenAPI: "3.1.0"}
		doc.Paths = openapi3.NewPaths()
		item := &openapi3.PathItem{
			Parameters: openapi3.Parameters{{Value: &openapi3.Parameter{Name: "x", In: "query"}}},
			Get:        &openapi3.Operation{OperationID: "getThing", Responses: openapi3.NewResponses()},
		}
		doc.Paths.Set("/thing", item)
		if _, err := descWalk(doc); err == nil || !strings.Contains(err.Error(), "inline path-level parameter") {
			t.Errorf("descWalk with an inline path-level parameter: %v", err)
		}
		if _, err := exampleWalk(doc); err == nil {
			t.Errorf("exampleWalk with an inline path-level parameter: no error")
		}
		item.Parameters = openapi3.Parameters{{Ref: "#/components/headers/Odd"}}
		if _, err := descWalk(doc); err == nil || !strings.Contains(err.Error(), "is not under") {
			t.Errorf("descWalk with an unrecognized parameter reference: %v", err)
		}
		item.Parameters = nil
		item.Get.Parameters = openapi3.Parameters{
			{Value: &openapi3.Parameter{Name: "x", In: "query"}},
			{Value: &openapi3.Parameter{Name: "x", In: "header"}},
		}
		if _, err := descWalk(doc); err == nil || !strings.Contains(err.Error(), "two inline parameters") {
			t.Errorf("descWalk with duplicate inline parameters: %v", err)
		}
	})
	t.Run("walk-json-skips-names-and-examples", func(t *testing.T) {
		doc := map[string]any{
			"properties": map[string]any{
				"example":     map[string]any{"description": "a member named example"},
				"description": map[string]any{"description": "a member named description"},
			},
			"example":     map[string]any{"description": "inside an example"},
			"description": "top",
		}
		var descs, exs []string
		walkJSON(doc, false, func(p string, _ any) { exs = append(exs, p) }, func(p, s string) { descs = append(descs, s) })
		slices.Sort(descs)
		if strings.Join(descs, "|") != "a member named description|a member named example|top" {
			t.Errorf("descriptions = %v", descs)
		}
		if len(exs) != 1 || exs[0] != "/example" {
			t.Errorf("examples = %v", exs)
		}
	})
}

func TestSpecDocsDenyListWellFormed(t *testing.T) {
	for _, p := range denyKeyProblems(undocumented, allKinds()) {
		t.Error(p)
	}
	for k, v := range undocumented {
		if !regexp.MustCompile(`^Task [2-6]$`).MatchString(v) {
			t.Errorf("%s: owner %q is not Task 2 to Task 6", k, v)
		}
	}
}
