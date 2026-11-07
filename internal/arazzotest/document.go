package arazzotest

import (
	"errors"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/getkin/kin-openapi/openapi3"
	"gopkg.in/yaml.v3"
)

// Info is the document's info object.
type Info struct{ Title, Summary, Description, Version string }

// Source is the document's one source description.
type Source struct{ Name, URL, Type string }

// Document is a loaded Arazzo document.
type Document struct {
	Arazzo    string
	Info      Info
	Source    Source     // the one sourceDescriptions entry
	Workflows []Workflow // in document order
	OpenAPI   *openapi3.T
}

// Workflow is one workflow; Required and Properties come from its inputs
// schema.
type Workflow struct {
	ID, Summary, Description string
	Required                 []string
	Properties               []string // declared input names, sorted
	DependsOn                []string
	Steps                    []Step
	outputs                  map[string]*tmpl
}

// Step is one step, bound to a method and path template of the source.
type Step struct {
	ID, Description, OperationID string
	Method, Path                 string
	where                        string
	params                       []param
	body                         *body
	criteria                     []criterion
	outputs                      map[string]*tmpl
}

type param struct {
	name, in, where string
	value           *tmpl
}

type body struct {
	contentType, where string
	payload            *tmpl
}

// The raw shapes declare every key the Arazzo 1.0 objects define, so
// KnownFields(true) refuses a key no object has; the unsupported keys are
// yaml.Node values, so presence (not shape) is detected.
type rawDoc struct {
	Arazzo     string      `yaml:"arazzo"`
	Info       rawInfo     `yaml:"info"`
	Sources    []rawSource `yaml:"sourceDescriptions"`
	Workflows  []rawWF     `yaml:"workflows"`
	Components yaml.Node   `yaml:"components"`
}

type rawInfo struct {
	Title       string `yaml:"title"`
	Summary     string `yaml:"summary"`
	Description string `yaml:"description"`
	Version     string `yaml:"version"`
}

type rawSource struct {
	Name string `yaml:"name"`
	URL  string `yaml:"url"`
	Type string `yaml:"type"`
}

type rawWF struct {
	ID          string         `yaml:"workflowId"`
	Summary     string         `yaml:"summary"`
	Description string         `yaml:"description"`
	Inputs      map[string]any `yaml:"inputs"`
	DependsOn   []string       `yaml:"dependsOn"`
	Steps       []rawStep      `yaml:"steps"`
	Outputs     map[string]any `yaml:"outputs"`
	Parameters  yaml.Node      `yaml:"parameters"`
	SuccessActs yaml.Node      `yaml:"successActions"`
	FailureActs yaml.Node      `yaml:"failureActions"`
}

type rawStep struct {
	ID          string         `yaml:"stepId"`
	Description string         `yaml:"description"`
	OperationID string         `yaml:"operationId"`
	OpPath      yaml.Node      `yaml:"operationPath"`
	WorkflowID  yaml.Node      `yaml:"workflowId"`
	Parameters  []rawParam     `yaml:"parameters"`
	RequestBody *rawBody       `yaml:"requestBody"`
	Criteria    []rawCriterion `yaml:"successCriteria"`
	OnSuccess   yaml.Node      `yaml:"onSuccess"`
	OnFailure   yaml.Node      `yaml:"onFailure"`
	Outputs     map[string]any `yaml:"outputs"`
}

type rawParam struct {
	Name      string    `yaml:"name"`
	In        string    `yaml:"in"`
	Value     any       `yaml:"value"`
	Reference yaml.Node `yaml:"reference"`
}

type rawBody struct {
	ContentType  string    `yaml:"contentType"`
	Payload      any       `yaml:"payload"`
	Replacements yaml.Node `yaml:"replacements"`
}

type rawCriterion struct {
	Condition string    `yaml:"condition"`
	Type      yaml.Node `yaml:"type"`
	Context   yaml.Node `yaml:"context"`
}

var (
	unknownKeyRE = regexp.MustCompile(`^line (\d+): field (\S+) not found in type `)
	versionRE    = regexp.MustCompile(`^1\.0\.[0-9]+$`)
	placeholder  = regexp.MustCompile(`\{[^{}]+\}`)
)

func decodeError(err error) error {
	var te *yaml.TypeError
	if errors.As(err, &te) {
		for _, m := range te.Errors {
			if sub := unknownKeyRE.FindStringSubmatch(m); sub != nil {
				return unsupported("line "+sub[1], "unknown key "+sub[2])
			}
		}
	}
	return fmt.Errorf("arazzotest: %w", err)
}

func resolveErr(where, expr, cause string) error {
	return &ResolveError{Where: where, Expr: expr, Cause: errors.New(cause)}
}

// Load parses an Arazzo document, resolves its one source description against
// the file's directory and binds every step's operationId to a method and path
// template of that OpenAPI document.
func Load(path string) (*Document, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("arazzotest: %w", err)
	}
	defer func() { _ = f.Close() }()
	var raw rawDoc
	dec := yaml.NewDecoder(f)
	dec.KnownFields(true)
	if err := dec.Decode(&raw); err != nil {
		return nil, decodeError(err)
	}
	var extra any
	if err := dec.Decode(&extra); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("arazzotest: %s: more than one YAML document", path)
	}

	if !versionRE.MatchString(raw.Arazzo) {
		return nil, unsupported("arazzo", featVersion)
	}
	if present(&raw.Components) {
		return nil, unsupported("components", featComponents)
	}
	d := &Document{Arazzo: raw.Arazzo, Info: Info(raw.Info)}
	if err := d.loadSource(path, raw.Sources); err != nil {
		return nil, err
	}
	ids := map[string]bool{}
	for i, w := range raw.Workflows {
		wf, err := d.compileWorkflow(i, w)
		if err != nil {
			return nil, err
		}
		if ids[wf.ID] {
			return nil, resolveErr(fmt.Sprintf("workflows[%d].workflowId", i), wf.ID, "duplicate workflowId")
		}
		ids[wf.ID] = true
		d.Workflows = append(d.Workflows, wf)
	}
	for i, wf := range d.Workflows {
		for _, need := range wf.DependsOn {
			if !ids[need] {
				return nil, resolveErr(fmt.Sprintf("workflows[%d].dependsOn", i), need, "no such workflow")
			}
		}
	}
	return d, nil
}

func (d *Document) loadSource(arazzoPath string, srcs []rawSource) error {
	if len(srcs) == 0 {
		return resolveErr("sourceDescriptions", "sourceDescriptions", "no source description")
	}
	if len(srcs) > 1 {
		return unsupported("sourceDescriptions[1]", featSecondSource)
	}
	s := srcs[0]
	if s.Type != "" && s.Type != "openapi" {
		return unsupported("sourceDescriptions[0].type", featSourceType)
	}
	if s.URL == "" {
		return resolveErr("sourceDescriptions[0].url", "url", "missing")
	}
	u, err := url.Parse(s.URL)
	if err != nil || u.Scheme != "" || u.Host != "" || strings.HasPrefix(s.URL, "/") || filepath.IsAbs(filepath.FromSlash(s.URL)) {
		return unsupported("sourceDescriptions[0].url", featSourceURL)
	}
	d.Source = Source{Name: s.Name, URL: s.URL, Type: "openapi"}
	file := filepath.Join(filepath.Dir(arazzoPath), filepath.FromSlash(s.URL))
	doc, err := openapi3.NewLoader().LoadFromFile(file)
	if err != nil {
		return fmt.Errorf("arazzotest: source description %q: %w", s.URL, err)
	}
	d.OpenAPI = doc
	return nil
}

type opRef struct{ method, path string }

func (d *Document) operation(id string) (opRef, bool, error) {
	var found []opRef
	if d.OpenAPI.Paths != nil {
		for p, item := range d.OpenAPI.Paths.Map() {
			for m, op := range item.Operations() {
				if op.OperationID == id {
					found = append(found, opRef{method: m, path: p})
				}
			}
		}
	}
	switch len(found) {
	case 0:
		return opRef{}, false, nil
	case 1:
		return found[0], true, nil
	}
	return opRef{}, false, fmt.Errorf("operationId %q is defined %d times", id, len(found))
}

func (d *Document) compileWorkflow(i int, w rawWF) (Workflow, error) {
	where := fmt.Sprintf("workflows[%d]", i)
	switch {
	case present(&w.Parameters):
		return Workflow{}, unsupported(where+".parameters", featWFParameters)
	case present(&w.SuccessActs):
		return Workflow{}, unsupported(where+".successActions", featSuccessActs)
	case present(&w.FailureActs):
		return Workflow{}, unsupported(where+".failureActions", featFailureActs)
	case w.ID == "":
		return Workflow{}, resolveErr(where+".workflowId", "workflowId", "missing")
	}
	wf := Workflow{ID: w.ID, Summary: w.Summary, Description: w.Description, DependsOn: w.DependsOn}
	if w.Inputs != nil {
		req, ok := w.Inputs["required"].([]any)
		if _, has := w.Inputs["required"]; has && !ok {
			return wf, resolveErr(where+".inputs.required", "required", "not a list")
		}
		for _, n := range req {
			s, ok := n.(string)
			if !ok {
				return wf, resolveErr(where+".inputs.required", fmt.Sprint(n), "not a string")
			}
			wf.Required = append(wf.Required, s)
		}
		props, _ := w.Inputs["properties"].(map[string]any)
		for n := range props {
			wf.Properties = append(wf.Properties, n)
		}
		sort.Strings(wf.Properties)
	}
	stepIDs := map[string]bool{}
	for j, s := range w.Steps {
		st, err := d.compileStep(where, j, s)
		if err != nil {
			return wf, err
		}
		if stepIDs[st.ID] {
			return wf, resolveErr(st.where+".stepId", st.ID, "duplicate stepId")
		}
		stepIDs[st.ID] = true
		wf.Steps = append(wf.Steps, st)
	}
	outs, err := compileOutputs(where+".outputs", w.Outputs)
	if err != nil {
		return wf, err
	}
	wf.outputs = outs
	return wf, nil
}

func compileOutputs(where string, m map[string]any) (map[string]*tmpl, error) {
	out := make(map[string]*tmpl, len(m))
	for k, v := range m {
		t, err := compile(where+"."+k, v)
		if err != nil {
			return nil, err
		}
		out[k] = t
	}
	return out, nil
}

func (d *Document) compileStep(wfWhere string, j int, s rawStep) (Step, error) {
	where := fmt.Sprintf("%s.steps[%d]", wfWhere, j)
	st := Step{ID: s.ID, Description: s.Description, OperationID: s.OperationID, where: where}
	switch {
	case present(&s.OpPath):
		return st, unsupported(where+".operationPath", featOperationPath)
	case present(&s.WorkflowID):
		return st, unsupported(where+".workflowId", featStepWorkflow)
	case present(&s.OnSuccess):
		return st, unsupported(where+".onSuccess", featOnSuccess)
	case present(&s.OnFailure):
		return st, unsupported(where+".onFailure", featOnFailure)
	case s.ID == "":
		return st, resolveErr(where+".stepId", "stepId", "missing")
	case s.OperationID == "":
		return st, resolveErr(where+".operationId", "operationId", "missing")
	}
	ref, ok, err := d.operation(s.OperationID)
	if err != nil {
		return st, &ResolveError{Where: where + ".operationId", Expr: s.OperationID, Cause: err}
	}
	if !ok {
		return st, resolveErr(where+".operationId", s.OperationID, "no such operationId in "+d.Source.URL)
	}
	st.Method, st.Path = ref.method, ref.path

	pathParams := map[string]bool{}
	for k, p := range s.Parameters {
		pw := fmt.Sprintf("%s.parameters[%d]", where, k)
		switch {
		case present(&p.Reference):
			return st, unsupported(pw+".reference", featReferenceParm)
		case p.In == "cookie":
			return st, unsupported(pw+".in", featCookie)
		case p.In != "path" && p.In != "query" && p.In != "header":
			return st, unsupported(pw+".in", featParamLocation)
		case p.Name == "":
			return st, resolveErr(pw+".name", "name", "missing")
		case p.Value == nil:
			return st, resolveErr(pw+".value", p.Name, "missing")
		}
		t, err := compile(pw+".value", p.Value)
		if err != nil {
			return st, err
		}
		if p.In == "path" {
			pathParams[p.Name] = true
		}
		st.params = append(st.params, param{name: p.Name, in: p.In, where: pw, value: t})
	}
	inPath := map[string]bool{}
	for _, m := range placeholder.FindAllString(st.Path, -1) {
		n := m[1 : len(m)-1]
		inPath[n] = true
		if !pathParams[n] {
			return st, resolveErr(where+".parameters", n, "no in: path parameter for "+m+" of "+st.Path)
		}
	}
	for n := range pathParams {
		if !inPath[n] {
			return st, resolveErr(where+".parameters", n, "in: path parameter is not in "+st.Path)
		}
	}

	if b := s.RequestBody; b != nil {
		bw := where + ".requestBody"
		switch {
		case present(&b.Replacements):
			return st, unsupported(bw+".replacements", featReplacements)
		case b.ContentType != "application/json" && b.ContentType != "application/x-www-form-urlencoded":
			return st, unsupported(bw+".contentType", featContentType)
		case b.Payload == nil:
			return st, resolveErr(bw+".payload", "payload", "missing")
		}
		t, err := compile(bw+".payload", b.Payload)
		if err != nil {
			return st, err
		}
		st.body = &body{contentType: b.ContentType, where: bw + ".payload", payload: t}
	}

	for k, c := range s.Criteria {
		cw := fmt.Sprintf("%s.successCriteria[%d]", where, k)
		switch {
		case present(&c.Type):
			return st, unsupported(cw+".type", featCritType)
		case present(&c.Context):
			return st, unsupported(cw+".context", featCritContext)
		}
		cr, err := parseCondition(cw+".condition", c.Condition)
		if err != nil {
			return st, err
		}
		st.criteria = append(st.criteria, cr)
	}
	outs, err := compileOutputs(where+".outputs", s.Outputs)
	if err != nil {
		return st, err
	}
	st.outputs = outs
	return st, nil
}

// present reports whether a yaml.Node field was written in the document.
func present(n *yaml.Node) bool { return n.Kind != 0 }
