package arazzotest

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

type exprKind int

const (
	exprInput exprKind = iota
	exprStepOutput
	exprStatus
	exprBody
)

// expr is one parsed runtime expression.
type expr struct {
	kind   exprKind
	text   string // as written, for error messages
	name   string // input or output name
	step   string // step id of $steps.<step>.outputs.<name>
	ptr    string // JSON pointer after '#' ("" is the whole body)
	hasPtr bool
}

// parseExpr parses one runtime expression; an expression outside the supported
// surface is an *UnsupportedError at where.
func parseExpr(where, text string) (expr, error) {
	e := expr{text: text}
	switch {
	case text == "$statusCode":
		e.kind = exprStatus
	case text == "$url":
		return e, unsupported(where, featExprURL)
	case text == "$method":
		return e, unsupported(where, featExprMethod)
	case text == "$request" || strings.HasPrefix(text, "$request."):
		return e, unsupported(where, featExprRequest)
	case text == "$response.header" || strings.HasPrefix(text, "$response.header."):
		return e, unsupported(where, featExprHeader)
	case text == "$sourceDescriptions" || strings.HasPrefix(text, "$sourceDescriptions."):
		return e, unsupported(where, featExprSources)
	case text == "$workflows" || strings.HasPrefix(text, "$workflows."):
		return e, unsupported(where, featExprWorkflows)
	case text == "$components" || strings.HasPrefix(text, "$components."):
		return e, unsupported(where, featExprComps)
	case text == "$response.body" || strings.HasPrefix(text, "$response.body#"):
		e.kind = exprBody
		if i := strings.Index(text, "#"); i >= 0 {
			e.hasPtr = true
			e.ptr = text[i+1:]
			if e.ptr != "" && e.ptr[0] != '/' {
				return e, unsupported(where, featExprOther)
			}
		}
	case strings.HasPrefix(text, "$inputs."):
		e.kind = exprInput
		e.name = strings.TrimPrefix(text, "$inputs.")
		if e.name == "" {
			return e, unsupported(where, featExprOther)
		}
	case strings.HasPrefix(text, "$steps."):
		parts := strings.SplitN(strings.TrimPrefix(text, "$steps."), ".", 3)
		if len(parts) != 3 || parts[0] == "" || parts[1] != "outputs" || parts[2] == "" {
			return e, unsupported(where, featExprOther)
		}
		e.kind, e.step, e.name = exprStepOutput, parts[0], parts[2]
	default:
		return e, unsupported(where, featExprOther)
	}
	return e, nil
}

// respCtx is the current step's response; the body is decoded on demand.
type respCtx struct {
	status int
	body   []byte
	done   bool
	val    any
	err    error
}

func (r *respCtx) json() (any, error) {
	if !r.done {
		r.done = true
		dec := json.NewDecoder(bytes.NewReader(r.body))
		dec.UseNumber()
		if err := dec.Decode(&r.val); err != nil {
			r.err = err
		} else if dec.More() {
			r.err = errors.New("trailing data after the JSON value")
		}
	}
	return r.val, r.err
}

// evalCtx is what an expression can see.
type evalCtx struct {
	inputs map[string]any
	steps  map[string]map[string]any
	resp   *respCtx // nil outside a step
}

func (e expr) resolve(where string, c *evalCtx) (any, error) {
	fail := func(cause string) error {
		return &ResolveError{Where: where, Expr: e.text, Cause: errors.New(cause)}
	}
	switch e.kind {
	case exprInput:
		v, ok := c.inputs[e.name]
		if !ok {
			return nil, fail("input not provided")
		}
		return v, nil
	case exprStepOutput:
		outs, ok := c.steps[e.step]
		if !ok {
			return nil, fail("step has not run")
		}
		v, ok := outs[e.name]
		if !ok {
			return nil, fail("step has no such output")
		}
		return v, nil
	case exprStatus:
		if c.resp == nil {
			return nil, fail("no response at this point")
		}
		return c.resp.status, nil
	default: // exprBody
		if c.resp == nil {
			return nil, fail("no response at this point")
		}
		v, err := c.resp.json()
		if !e.hasPtr {
			if err != nil {
				return string(c.resp.body), nil
			}
			return v, nil
		}
		if err != nil {
			return nil, fail("response body is not JSON: " + err.Error())
		}
		got, ok := resolvePointer(v, e.ptr)
		if !ok {
			return nil, fail("pointer does not resolve")
		}
		return got, nil
	}
}

// resolvePointer follows an RFC 6901 pointer ("" is the whole document).
func resolvePointer(doc any, ptr string) (any, bool) {
	if ptr == "" {
		return doc, true
	}
	cur := doc
	for _, tok := range strings.Split(ptr[1:], "/") {
		tok = strings.ReplaceAll(strings.ReplaceAll(tok, "~1", "/"), "~0", "~")
		switch node := cur.(type) {
		case map[string]any:
			v, ok := node[tok]
			if !ok {
				return nil, false
			}
			cur = v
		case []any:
			if tok == "" || (len(tok) > 1 && tok[0] == '0') {
				return nil, false
			}
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(node) {
				return nil, false
			}
			cur = node[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// scalarString renders a scalar the way a path, query, header or form value
// carries it; a null, object or array is not a scalar.
func scalarString(v any) (string, bool) {
	switch x := v.(type) {
	case string:
		return x, true
	case json.Number:
		return x.String(), true
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64), true
	case bool:
		return strconv.FormatBool(x), true
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return fmt.Sprint(x), true
	}
	return "", false
}

// tmpl is a compiled value: a literal, one bare expression (which keeps the
// resolved value's type), a string with embedded {expr} parts (always a string,
// even when the string is only one {expr}), an object or
// an array.
type tmpl struct {
	kind  tmplKind
	lit   any
	e     expr
	parts []tpart
	obj   map[string]*tmpl
	arr   []*tmpl
}

type tmplKind int

const (
	tLit tmplKind = iota
	tWhole
	tConcat
	tObject
	tArray
)

type tpart struct {
	lit string
	e   *expr
}

func compile(where string, v any) (*tmpl, error) {
	switch x := v.(type) {
	case string:
		return compileString(where, x)
	case map[string]any:
		t := &tmpl{kind: tObject, obj: make(map[string]*tmpl, len(x))}
		for k, e := range x {
			if strings.Contains(k, "{$") {
				return nil, unsupported(where+"."+k, featExprOther)
			}
			c, err := compile(where+"."+k, e)
			if err != nil {
				return nil, err
			}
			t.obj[k] = c
		}
		return t, nil
	case map[any]any:
		m := make(map[string]any, len(x))
		for k, e := range x {
			m[fmt.Sprint(k)] = e
		}
		return compile(where, m)
	case []any:
		t := &tmpl{kind: tArray, arr: make([]*tmpl, len(x))}
		for i, e := range x {
			c, err := compile(fmt.Sprintf("%s[%d]", where, i), e)
			if err != nil {
				return nil, err
			}
			t.arr[i] = c
		}
		return t, nil
	}
	return &tmpl{kind: tLit, lit: v}, nil
}

// spacedBrace matches "{ $", a placeholder with whitespace inside the braces:
// it is refused, never taken as literal text.
var spacedBrace = regexp.MustCompile(`\{\s+\$`)

func compileString(where, s string) (*tmpl, error) {
	if strings.HasPrefix(s, "$") {
		e, err := parseExpr(where, s)
		if err != nil {
			return nil, err
		}
		return &tmpl{kind: tWhole, e: e}, nil
	}
	if spacedBrace.MatchString(s) {
		return nil, unsupported(where, featExprOther)
	}
	if !strings.Contains(s, "{$") {
		return &tmpl{kind: tLit, lit: s}, nil
	}
	var parts []tpart
	rest := s
	for {
		i := strings.Index(rest, "{$")
		if i < 0 {
			break
		}
		j := strings.Index(rest[i:], "}")
		if j < 0 {
			return nil, unsupported(where, featExprOther)
		}
		e, err := parseExpr(where, rest[i+1:i+j])
		if err != nil {
			return nil, err
		}
		if i > 0 {
			parts = append(parts, tpart{lit: rest[:i]})
		}
		parts = append(parts, tpart{e: &e})
		rest = rest[i+j+1:]
	}
	if rest != "" {
		parts = append(parts, tpart{lit: rest})
	}
	return &tmpl{kind: tConcat, parts: parts}, nil
}

func (t *tmpl) eval(where string, c *evalCtx) (any, error) {
	switch t.kind {
	case tWhole:
		return t.e.resolve(where, c)
	case tConcat:
		var b strings.Builder
		for _, p := range t.parts {
			if p.e == nil {
				b.WriteString(p.lit)
				continue
			}
			v, err := p.e.resolve(where, c)
			if err != nil {
				return nil, err
			}
			s, ok := scalarString(v)
			if !ok {
				return nil, &ResolveError{Where: where, Expr: p.e.text, Cause: errors.New("embedded value is not a scalar")}
			}
			b.WriteString(s)
		}
		return b.String(), nil
	case tObject:
		out := make(map[string]any, len(t.obj))
		for k, e := range t.obj {
			v, err := e.eval(where+"."+k, c)
			if err != nil {
				return nil, err
			}
			out[k] = v
		}
		return out, nil
	case tArray:
		out := make([]any, len(t.arr))
		for i, e := range t.arr {
			v, err := e.eval(fmt.Sprintf("%s[%d]", where, i), c)
			if err != nil {
				return nil, err
			}
			out[i] = v
		}
		return out, nil
	}
	return t.lit, nil
}
