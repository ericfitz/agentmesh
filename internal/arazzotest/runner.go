package arazzotest

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Runner runs the workflows of a Document against BaseURL.
type Runner struct {
	Doc     *Document
	BaseURL string                           // the server (the e2e validating proxy)
	Client  *http.Client                     // nil: a client with a 30 s timeout
	Log     func(format string, args ...any) // nil: silent; the e2e test passes t.Logf
	done    map[string]bool                  // workflows completed in this runner (dependsOn)
}

// Result is a completed workflow's outputs and its steps.
type Result struct {
	Outputs map[string]any
	Steps   []StepResult
}

// StepResult is one executed step.
type StepResult struct {
	StepID      string
	Method, URL string
	Status      int
	Body        []byte
	Outputs     map[string]any
}

func (r *Runner) logf(format string, args ...any) {
	if r.Log != nil {
		r.Log(format, args...)
	}
}

func (r *Runner) client() *http.Client {
	if r.Client != nil {
		return r.Client
	}
	// A criterion on $statusCode must see the step's own response, so the
	// default client never follows a redirect (a caller's Client is its own).
	return &http.Client{
		Timeout:       30 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
}

// Run runs one workflow. A dependsOn prerequisite must already have completed
// in this Runner (an *OrderError otherwise: it is never run for the caller);
// the inputs must name only declared properties and carry every required one.
// On a failed criterion the Result holds the steps run so far (the failed one
// last) beside the *CriteriaError.
func (r *Runner) Run(ctx context.Context, workflowID string, inputs map[string]any) (Result, error) {
	var res Result
	var wf *Workflow
	for i := range r.Doc.Workflows {
		if r.Doc.Workflows[i].ID == workflowID {
			wf = &r.Doc.Workflows[i]
		}
	}
	if wf == nil {
		return res, resolveErr("workflowId", workflowID, "no such workflow")
	}
	for _, need := range wf.DependsOn {
		if !r.done[need] {
			return res, &OrderError{Workflow: wf.ID, Needs: need}
		}
	}
	declared := map[string]bool{}
	for _, n := range wf.Properties {
		declared[n] = true
	}
	for n := range inputs {
		if !declared[n] {
			return res, resolveErr("workflow "+wf.ID, "$inputs."+n, "input is not a declared property")
		}
	}
	for _, n := range wf.Required {
		if _, ok := inputs[n]; !ok {
			return res, resolveErr("workflow "+wf.ID, "$inputs."+n, "required input not provided")
		}
	}
	ec := &evalCtx{inputs: make(map[string]any, len(inputs)), steps: map[string]map[string]any{}}
	for k, v := range inputs {
		ec.inputs[k] = v
	}
	for i := range wf.Steps {
		sr, err := r.runStep(ctx, wf, &wf.Steps[i], ec)
		if sr.StepID != "" {
			res.Steps = append(res.Steps, sr)
		}
		if err != nil {
			return res, err
		}
	}
	res.Outputs = make(map[string]any, len(wf.outputs))
	for k, t := range wf.outputs {
		v, err := t.eval("workflow "+wf.ID+".outputs."+k, ec)
		if err != nil {
			return res, err
		}
		res.Outputs[k] = v
	}
	if r.done == nil {
		r.done = map[string]bool{}
	}
	r.done[wf.ID] = true
	return res, nil
}

func (r *Runner) runStep(ctx context.Context, wf *Workflow, st *Step, ec *evalCtx) (StepResult, error) {
	pathVals := map[string]string{}
	query := url.Values{}
	header := http.Header{}
	for _, p := range st.params {
		v, err := p.value.eval(p.where, ec)
		if err != nil {
			return StepResult{}, err
		}
		s, ok := scalarString(v)
		if !ok {
			return StepResult{}, resolveErr(p.where, p.name, "parameter value is not a scalar")
		}
		switch p.in {
		case "path":
			pathVals[p.name] = url.PathEscape(s)
		case "query":
			query.Add(p.name, s)
		default:
			header.Set(p.name, s)
		}
	}
	path := placeholder.ReplaceAllStringFunc(st.Path, func(m string) string { return pathVals[m[1:len(m)-1]] })
	target := strings.TrimRight(r.BaseURL, "/") + path
	if len(query) > 0 {
		target += "?" + query.Encode()
	}

	var payload io.Reader
	if st.body != nil {
		v, err := st.body.payload.eval(st.body.where, ec)
		if err != nil {
			return StepResult{}, err
		}
		b, err := encodeBody(st.body, v)
		if err != nil {
			return StepResult{}, err
		}
		header.Set("Content-Type", st.body.contentType)
		payload = bytes.NewReader(b)
	}
	req, err := http.NewRequestWithContext(ctx, st.Method, target, payload)
	if err != nil {
		return StepResult{}, fmt.Errorf("arazzotest: %s: %w", st.where, err)
	}
	for k, vs := range header {
		req.Header[k] = vs
	}
	sr := StepResult{StepID: st.ID, Method: st.Method, URL: target}
	resp, err := r.client().Do(req)
	if err != nil {
		return sr, fmt.Errorf("arazzotest: %s: %w", st.where, err)
	}
	defer func() { _ = resp.Body.Close() }()
	data, err := io.ReadAll(resp.Body)
	if err != nil {
		return sr, fmt.Errorf("arazzotest: %s: reading the response: %w", st.where, err)
	}
	sr.Status, sr.Body = resp.StatusCode, data
	r.logf("workflow %s step %s: %s %s -> %d", wf.ID, st.ID, st.Method, target, resp.StatusCode)

	ec.resp = &respCtx{status: resp.StatusCode, body: data}
	defer func() { ec.resp = nil }()
	for _, c := range st.criteria {
		ok, err := c.eval(st.where, ec)
		if err != nil {
			return sr, err
		}
		if !ok {
			return sr, &CriteriaError{Workflow: wf.ID, Step: st.ID, Condition: c.text, Status: resp.StatusCode, Body: data}
		}
	}
	outs := make(map[string]any, len(st.outputs))
	for k, t := range st.outputs {
		v, err := t.eval(st.where+".outputs."+k, ec)
		if err != nil {
			return sr, err
		}
		outs[k] = v
	}
	sr.Outputs = outs
	ec.steps[st.ID] = outs
	return sr, nil
}

func encodeBody(b *body, v any) ([]byte, error) {
	if b.contentType == "application/json" {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(v); err != nil {
			return nil, &ResolveError{Where: b.where, Expr: "payload", Cause: err}
		}
		return bytes.TrimRight(buf.Bytes(), "\n"), nil
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, resolveErr(b.where, "payload", "a form payload must be an object")
	}
	vals := url.Values{}
	for k, x := range m {
		s, ok := x.(string)
		if !ok {
			return nil, &ResolveError{Where: b.where + "." + k, Expr: k, Cause: errors.New("a form value must resolve to a string")}
		}
		vals.Set(k, s)
	}
	return []byte(vals.Encode()), nil
}
