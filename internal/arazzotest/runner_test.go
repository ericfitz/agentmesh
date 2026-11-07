package arazzotest_test

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/ericfitz/agentmesh/internal/arazzotest"
)

var update = flag.Bool("update", false, "rewrite testdata/good.golden")

// fake is the scripted server: it records one line per request.
type fake struct {
	t          *testing.T
	srv        *httptest.Server
	mu         sync.Mutex
	log        []string
	failCreate bool
}

func newFake(t *testing.T) *fake {
	t.Helper()
	f := &fake{t: t}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fake) lines() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.log...)
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

func (f *fake) handle(w http.ResponseWriter, r *http.Request) {
	raw, _ := io.ReadAll(r.Body)
	f.mu.Lock()
	f.log = append(f.log, fmt.Sprintf("%s %s | Authorization: %s | Content-Type: %s | %s",
		r.Method, r.RequestURI, r.Header.Get("Authorization"), r.Header.Get("Content-Type"), raw))
	f.mu.Unlock()
	authed := r.Header.Get("Authorization") == "Bearer tok"
	switch {
	case r.Method == "POST" && r.URL.Path == "/token":
		if form, err := url.ParseQuery(string(raw)); err != nil || form.Get("grant_type") != "client_credentials" {
			writeJSON(w, 400, `{"code":"bad_form"}`)
			return
		}
		writeJSON(w, 200, `{"access_token":"tok"}`)
	case r.Method == "POST" && r.URL.Path == "/things":
		switch {
		case f.failCreate:
			writeJSON(w, 500, `{"code":"boom"}`)
		case !authed:
			writeJSON(w, 401, `{"code":"unauthorized"}`)
		case string(raw) != `{"count":2,"name":"x"}`:
			writeJSON(w, 400, `{"code":"bad_body"}`)
		default:
			writeJSON(w, 201, `{"id":41,"name":"x"}`)
		}
	case r.Method == "GET" && r.URL.Path == "/things/41":
		writeJSON(w, 200, `{"id":41,"state":"ok","tags":["a"],"flag":true,"other":false,"none":null,"a/b":5,"m~n":1}`)
	case r.Method == "GET" && strings.HasPrefix(r.URL.Path, "/things/"):
		writeJSON(w, 404, `{"code":"not_found"}`)
	case r.Method == "GET" && r.URL.Path == "/things":
		writeJSON(w, 200, `{"items":[{"id":41}]}`)
	case r.Method == "POST" && r.URL.Path == "/links":
		var m map[string]any
		if err := json.Unmarshal(raw, &m); err != nil {
			writeJSON(w, 400, `{"code":"bad_json"}`)
			return
		}
		from, isNum := m["from"].(float64)
		if !isNum || from != 41 || m["label"] != "thing-L" || m["both"] != "41" || m["html"] != "a<b&c" {
			writeJSON(w, 400, fmt.Sprintf(`{"code":"bad_types","got":%q}`, raw))
			return
		}
		writeJSON(w, 200, `{"linked":true}`)
	case r.Method == "GET" && r.URL.Path == "/redirect":
		http.Redirect(w, r, "/things", http.StatusFound)
	case r.Method == "GET" && r.URL.Path == "/plain":
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, "not json")
	default:
		writeJSON(w, 404, `{"code":"no_route"}`)
	}
}

func load(t *testing.T, name string) *arazzotest.Document {
	t.Helper()
	d, err := arazzotest.Load(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("Load %s: %v", name, err)
	}
	return d
}

func runner(t *testing.T, f *fake, name string) *arazzotest.Runner {
	return &arazzotest.Runner{Doc: load(t, name), BaseURL: f.srv.URL, Log: t.Logf}
}

func pretty(t *testing.T, v any) string {
	t.Helper()
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestGoodWorkflow(t *testing.T) {
	f := newFake(t)
	r := runner(t, f, "good.arazzo.yaml")
	if r.Doc.Arazzo != "1.0.1" || r.Doc.Info.Title != "Runner fixture" || r.Doc.Source.URL != "openapi.yaml" ||
		len(r.Doc.Workflows) != 2 || r.Doc.OpenAPI == nil {
		t.Fatalf("document not loaded as written: %+v", r.Doc)
	}
	ctx := context.Background()
	login, err := r.Run(ctx, "login", map[string]any{"client": "c1"})
	if err != nil {
		t.Fatal(err)
	}
	things, err := r.Run(ctx, "things", map[string]any{"bearer": login.Outputs["access_token"]})
	if err != nil {
		t.Fatal(err)
	}
	if len(things.Steps) != 3 || things.Steps[0].Status != 201 || things.Steps[1].Method != "GET" {
		t.Fatalf("steps: %+v", things.Steps)
	}

	got := "== requests\n" + strings.Join(f.lines(), "\n") +
		"\n== outputs login\n" + pretty(t, login.Outputs) +
		"\n== outputs things\n" + pretty(t, things.Outputs) + "\n"
	golden := filepath.Join("testdata", "good.golden")
	if *update {
		if err := os.WriteFile(golden, []byte(got), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	want, err := os.ReadFile(golden)
	if err != nil {
		t.Fatal(err)
	}
	if got != string(want) {
		t.Fatalf("request log and outputs differ from testdata/good.golden (rerun with -update to accept)\n--- got\n%s--- want\n%s", got, want)
	}
}

func TestDependsOnIsCheckedNotRun(t *testing.T) {
	f := newFake(t)
	r := runner(t, f, "good.arazzo.yaml")
	_, err := r.Run(context.Background(), "things", map[string]any{"bearer": "tok"})
	var oe *arazzotest.OrderError
	if !errors.As(err, &oe) || oe.Workflow != "things" || oe.Needs != "login" {
		t.Fatalf("want OrderError{things, login}, got %v", err)
	}
	if n := len(f.lines()); n != 0 {
		t.Fatalf("the server saw %d requests: %v", n, f.lines())
	}
}

func TestCriteriaFailure(t *testing.T) {
	f := newFake(t)
	f.failCreate = true
	r := runner(t, f, "good.arazzo.yaml")
	ctx := context.Background()
	if _, err := r.Run(ctx, "login", map[string]any{"client": "c1"}); err != nil {
		t.Fatal(err)
	}
	res, err := r.Run(ctx, "things", map[string]any{"bearer": "tok"})
	var ce *arazzotest.CriteriaError
	if !errors.As(err, &ce) {
		t.Fatalf("want CriteriaError, got %v", err)
	}
	if ce.Workflow != "things" || ce.Step != "create" || ce.Condition != "$statusCode == 201" ||
		ce.Status != 500 || string(ce.Body) != `{"code":"boom"}` {
		t.Fatalf("CriteriaError: %+v", ce)
	}
	if len(res.Steps) != 1 {
		t.Fatalf("steps run: %d, want 1", len(res.Steps))
	}
	if n := len(f.lines()); n != 2 { // the token request and the failed create
		t.Fatalf("requests: %v", f.lines())
	}
	// A failed workflow is not completed: a dependent one still sees only login.
	if _, err := r.Run(ctx, "login", map[string]any{"client": "c1"}); err != nil {
		t.Fatal(err)
	}
}

// refusals is every refuse-*.arazzo.yaml fixture with the exact refusal.
var refusals = []struct{ file, where, feature string }{
	{"arazzo-version", "arazzo", "arazzo version"},
	{"unknown-key", "line 7", "unknown key bogus"},
	{"extension-key", "line 7", "unknown key x-note"},
	{"second-source", "sourceDescriptions[1]", "second sourceDescription"},
	{"source-type", "sourceDescriptions[0].type", "sourceDescription type"},
	{"source-url-remote", "sourceDescriptions[0].url", "sourceDescription url"},
	{"source-url-absolute", "sourceDescriptions[0].url", "sourceDescription url"},
	{"components", "components", "components"},
	{"workflow-parameters", "workflows[0].parameters", "workflow parameters"},
	{"success-actions", "workflows[0].successActions", "successActions"},
	{"failure-actions", "workflows[0].failureActions", "failureActions"},
	{"operation-path", "workflows[0].steps[0].operationPath", "operationPath"},
	{"step-workflow-id", "workflows[0].steps[0].workflowId", "step workflowId"},
	{"on-success", "workflows[0].steps[0].onSuccess", "onSuccess"},
	{"on-failure", "workflows[0].steps[0].onFailure", "onFailure"},
	{"reference-parameter", "workflows[0].steps[0].parameters[0].reference", "reference parameter"},
	{"request-body-replacements", "workflows[0].steps[0].requestBody.replacements", "requestBody replacements"},
	{"param-cookie", "workflows[0].steps[0].parameters[0].in", "parameter in cookie"},
	{"param-location", "workflows[0].steps[0].parameters[0].in", "parameter location"},
	{"criterion-type", "workflows[0].steps[0].successCriteria[0].type", "criterion type"},
	{"criterion-context", "workflows[0].steps[0].successCriteria[0].context", "criterion context"},
	{"content-type", "workflows[0].steps[0].requestBody.contentType", "contentType"},
	{"condition-syntax", "workflows[0].steps[0].successCriteria[0].condition", "condition syntax"},
	{"condition-lhs", "workflows[0].steps[0].successCriteria[0].condition", "condition syntax"},
	{"expr-url", "workflows[0].steps[0].parameters[0].value", "expression $url"},
	{"expr-method", "workflows[0].steps[0].parameters[0].value", "expression $method"},
	{"expr-request", "workflows[0].steps[0].parameters[0].value", "expression $request"},
	{"expr-response-header", "workflows[0].steps[0].parameters[0].value", "expression $response.header"},
	{"expr-source-descriptions", "workflows[0].steps[0].parameters[0].value", "expression $sourceDescriptions"},
	{"expr-workflows", "workflows[0].steps[0].parameters[0].value", "expression $workflows"},
	{"expr-components", "workflows[0].steps[0].parameters[0].value", "expression $components"},
	{"expr-unrecognized", "workflows[0].steps[0].parameters[0].value", "unrecognized expression"},
	{"expr-embedded-space", "workflows[0].steps[0].parameters[0].value", "unrecognized expression"},
	{"key-expression", "workflows[0].steps[0].requestBody.payload.{$inputs.k}", "unrecognized expression"},
	{"expr-embedded-unrecognized", "workflows[0].steps[0].parameters[0].value", "unrecognized expression"},
}

func normalize(feature string) string {
	if strings.HasPrefix(feature, "unknown key ") {
		return "unknown key <k>"
	}
	return feature
}

func TestRefusals(t *testing.T) {
	for _, tc := range refusals {
		t.Run(tc.file, func(t *testing.T) {
			_, err := arazzotest.Load(filepath.Join("testdata", "refuse-"+tc.file+".arazzo.yaml"))
			var ue *arazzotest.UnsupportedError
			if !errors.As(err, &ue) {
				t.Fatalf("want *UnsupportedError, got %T %v", err, err)
			}
			if ue.Where != tc.where || ue.Feature != tc.feature {
				t.Fatalf("got Where=%q Feature=%q, want Where=%q Feature=%q", ue.Where, ue.Feature, tc.where, tc.feature)
			}
		})
	}
}

func TestRefusalCoverage(t *testing.T) {
	covered := map[string]bool{}
	files := map[string]bool{}
	for _, tc := range refusals {
		covered[normalize(tc.feature)] = true
		files[tc.file] = true
	}
	for _, f := range arazzotest.Unsupported() {
		if !covered[f] {
			t.Errorf("refusal %q has no fixture", f)
		}
	}
	listed := map[string]bool{}
	for _, f := range arazzotest.Unsupported() {
		listed[f] = true
	}
	for f := range covered {
		if !listed[f] {
			t.Errorf("fixture covers %q, which Unsupported does not list", f)
		}
	}
	matches, err := filepath.Glob(filepath.Join("testdata", "refuse-*.arazzo.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	var onDisk []string
	for _, m := range matches {
		name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(m), "refuse-"), ".arazzo.yaml")
		onDisk = append(onDisk, name)
		if !files[name] {
			t.Errorf("fixture %s is not in the refusals table", m)
		}
	}
	sort.Strings(onDisk)
	if len(onDisk) != len(files) {
		t.Errorf("refusals table names %d fixtures, %d on disk (%v)", len(files), len(onDisk), onDisk)
	}
}

// writeDoc writes an Arazzo document beside a copy of the fixture OpenAPI
// document and loads it.
func writeDoc(t *testing.T, workflows string) (*arazzotest.Document, error) {
	t.Helper()
	dir := t.TempDir()
	spec, err := os.ReadFile(filepath.Join("testdata", "openapi.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "openapi.yaml"), spec, 0o644); err != nil {
		t.Fatal(err)
	}
	head := "arazzo: 1.0.1\ninfo: {title: t, version: 1.0.0}\nsourceDescriptions:\n  - {name: api, url: openapi.yaml, type: openapi}\nworkflows:\n"
	p := filepath.Join(dir, "doc.arazzo.yaml")
	if err := os.WriteFile(p, []byte(head+workflows), 0o644); err != nil {
		t.Fatal(err)
	}
	return arazzotest.Load(p)
}

func TestResolveErrors(t *testing.T) {
	const getPlain = "  - workflowId: w\n    steps:\n      - stepId: s\n        operationId: getPlain\n        successCriteria:\n          - condition: $statusCode == 200\n"
	cases := []struct {
		name, workflows string
		run             string // workflow to run ("" : the error is Load's)
		inputs          map[string]any
		expr            string
	}{
		{"unknown operationId", "  - workflowId: w\n    steps:\n      - stepId: s\n        operationId: nope\n", "", nil, "nope"},
		{"undefined step output", getPlain + "        outputs: {a: $steps.x.outputs.y}\n", "w", nil, "$steps.x.outputs.y"},
		{"missing required input", "  - workflowId: w\n    inputs: {required: [a], properties: {a: {}}}\n    steps: []\n", "w", nil, "$inputs.a"},
		{"undeclared input", "  - workflowId: w\n    inputs: {properties: {a: {}}}\n    steps: []\n", "w", map[string]any{"b": 1}, "$inputs.b"},
		{"input not provided", "  - workflowId: w\n    inputs: {properties: {a: {}}}\n    steps:\n      - stepId: s\n        operationId: getPlain\n        parameters:\n          - {name: q, in: query, value: $inputs.a}\n        successCriteria:\n          - condition: $statusCode == 200\n", "w", nil, "$inputs.a"},
		{"pointer does not resolve", "  - workflowId: w\n    steps:\n      - stepId: s\n        operationId: listThings\n        successCriteria:\n          - condition: $statusCode == 200\n        outputs: {a: $response.body#/nope}\n", "w", nil, "$response.body#/nope"},
		{"array index out of range", "  - workflowId: w\n    steps:\n      - stepId: s\n        operationId: listThings\n        successCriteria:\n          - condition: $statusCode == 200\n        outputs: {a: $response.body#/items/5}\n", "w", nil, "$response.body#/items/5"},
		{"non-JSON body with a pointer", getPlain + "        outputs: {a: $response.body#/x}\n", "w", nil, "$response.body#/x"},
		{"unknown workflow", "  - workflowId: w\n    steps: []\n", "other", nil, "other"},
		{"missing path parameter", "  - workflowId: w\n    steps:\n      - stepId: s\n        operationId: getThing\n", "", nil, "id"},
		{"extra path parameter", "  - workflowId: w\n    steps:\n      - stepId: s\n        operationId: listThings\n        parameters:\n          - {name: id, in: path, value: x}\n", "", nil, "id"},
		{"no successCriteria", "  - workflowId: w\n    steps:\n      - stepId: s\n        operationId: listThings\n", "", nil, "successCriteria"},
		{"empty successCriteria", "  - workflowId: w\n    steps:\n      - stepId: s\n        operationId: listThings\n        successCriteria: []\n", "", nil, "successCriteria"},
		{"required input not a property", "  - workflowId: w\n    inputs: {required: [a], properties: {b: {}}}\n    steps: []\n", "", nil, "a"},
		{"required without properties", "  - workflowId: w\n    inputs: {required: [a]}\n    steps: []\n", "", nil, "a"},
		{"workflow output outside a step", "  - workflowId: w\n    steps: []\n    outputs: {a: $statusCode}\n", "w", nil, "$statusCode"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := newFake(t)
			doc, err := writeDoc(t, tc.workflows)
			if tc.run != "" {
				if err != nil {
					t.Fatalf("Load: %v", err)
				}
				r := &arazzotest.Runner{Doc: doc, BaseURL: f.srv.URL}
				_, err = r.Run(context.Background(), tc.run, tc.inputs)
			}
			var re *arazzotest.ResolveError
			if !errors.As(err, &re) {
				t.Fatalf("want *ResolveError, got %T %v", err, err)
			}
			if re.Expr != tc.expr {
				t.Fatalf("Expr = %q, want %q (%v)", re.Expr, tc.expr, err)
			}
		})
	}
}

func TestEmbeddedExpressions(t *testing.T) {
	f := newFake(t)
	r := runner(t, f, "embedded.arazzo.yaml")
	if _, err := r.Run(context.Background(), "link", map[string]any{"label": "L", "bearer": "tok"}); err != nil {
		t.Fatal(err) // the fake answers 400 bad_types unless from is a JSON number, label is "thing-L", both is "41"
	}
	lines := f.lines()
	if got := lines[len(lines)-1]; !strings.HasSuffix(got, `{"both":"41","from":41,"html":"a<b&c","label":"thing-L"}`) {
		t.Fatalf("link request: %s", got)
	}
}

func TestEmbeddedAuthorizationHeader(t *testing.T) {
	f := newFake(t)
	r := runner(t, f, "good.arazzo.yaml")
	if _, err := r.Run(context.Background(), "login", map[string]any{"client": "c1"}); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Run(context.Background(), "things", map[string]any{"bearer": "tok"}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(f.lines()[1], "Authorization: Bearer tok |") {
		t.Fatalf("header not embedded: %s", f.lines()[1])
	}
}

func TestPathEscaping(t *testing.T) {
	f := newFake(t)
	r := runner(t, f, "embedded.arazzo.yaml")
	if _, err := r.Run(context.Background(), "escape", map[string]any{"id": "a/b 100%"}); err != nil {
		t.Fatal(err)
	}
	if got := f.lines()[0]; !strings.HasPrefix(got, "GET /things/a%2Fb%20100%25 |") {
		t.Fatalf("request: %s", got)
	}
}

func TestConditions(t *testing.T) {
	f := newFake(t)
	r := runner(t, f, "embedded.arazzo.yaml")
	if _, err := r.Run(context.Background(), "conditions", nil); err != nil {
		t.Fatal(err)
	}
	_, err := r.Run(context.Background(), "conditionsfail", nil)
	var ce *arazzotest.CriteriaError
	if !errors.As(err, &ce) || ce.Condition != `$response.body#/state != "ok"` {
		t.Fatalf("want CriteriaError for the != condition, got %v", err)
	}
}

func TestLoadRefusesMissingFile(t *testing.T) {
	if _, err := arazzotest.Load(filepath.Join("testdata", "nope.arazzo.yaml")); err == nil {
		t.Fatal("want an error")
	}
}

func TestDefaultClientDoesNotFollowRedirects(t *testing.T) {
	f := newFake(t)
	r := runner(t, f, "embedded.arazzo.yaml")
	res, err := r.Run(context.Background(), "redirect", nil)
	if err != nil {
		t.Fatal(err) // $statusCode == 302 holds only if the redirect was not followed
	}
	if res.Steps[0].Status != 302 || len(f.lines()) != 1 {
		t.Fatalf("status %d, requests %v", res.Steps[0].Status, f.lines())
	}
}

// TestRefusalsTieToSource: every feat* constant is listed by Unsupported, and
// every unsupported(...) call site passes a feat* constant (the one table), so
// a refusal cannot exist outside the list the fixtures are checked against.
func TestRefusalsTieToSource(t *testing.T) {
	fset := token.NewFileSet()
	names, err := filepath.Glob("*.go")
	if err != nil {
		t.Fatal(err)
	}
	var files []*ast.File
	for _, name := range names {
		if strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatal(err)
		}
		files = append(files, file)
	}
	consts := map[string]string{} // name -> value
	var calls int
	{
		for _, file := range files {
			ast.Inspect(file, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.ValueSpec:
					for i, id := range x.Names {
						if strings.HasPrefix(id.Name, "feat") && i < len(x.Values) {
							if lit, ok := x.Values[i].(*ast.BasicLit); ok {
								v, _ := strconv.Unquote(lit.Value)
								consts[id.Name] = v
							}
						}
					}
				case *ast.CallExpr:
					if id, ok := x.Fun.(*ast.Ident); ok && id.Name == "unsupported" && len(x.Args) == 2 {
						calls++
						switch a := x.Args[1].(type) {
						case *ast.Ident:
							if !strings.HasPrefix(a.Name, "feat") {
								t.Errorf("%s: unsupported(...) takes %s, not a feat* constant", fset.Position(x.Pos()), a.Name)
							}
						case *ast.BinaryExpr: // "unknown key " + key
							if lit, ok := a.X.(*ast.BasicLit); !ok || lit.Value != `"unknown key "` {
								t.Errorf("%s: unsupported(...) takes an unlisted expression", fset.Position(x.Pos()))
							}
						default:
							t.Errorf("%s: unsupported(...) takes an unlisted feature", fset.Position(x.Pos()))
						}
					}
				}
				return true
			})
		}
	}
	if calls == 0 || len(consts) == 0 {
		t.Fatalf("scan found %d call sites and %d constants", calls, len(consts))
	}
	listed := map[string]bool{}
	for _, f := range arazzotest.Unsupported() {
		listed[f] = true
	}
	for name, v := range consts {
		if !listed[v] {
			t.Errorf("%s = %q is not listed by Unsupported", name, v)
		}
	}
	if len(listed) != len(consts) {
		t.Errorf("Unsupported lists %d features, the source declares %d feat* constants", len(listed), len(consts))
	}
}
