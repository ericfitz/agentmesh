package main

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"gopkg.in/yaml.v3"
)

// The rule vocabulary is the cats plugin's (catslib/rules.py).
//
// Deviations from rules.py:
//   - Regexes are RE2, not Python re (ruling 4): a pattern RE2 refuses
//     (lookahead, lookbehind, backreference, possessive quantifier, atomic
//     group) is a load error; `$` matches only at the end of the text (Python
//     also before a trailing newline); \d, \w, \s are ASCII.
//   - A text operator on the bare `json_body` field sees a map with sorted
//     keys, where Python prints insertion order (Go decodes into a map);
//     use `response_body` for text matching of the whole body.
//   - Duplicate JSON keys in a response body are kept in `response_body`,
//     where Python's json.loads collapses them.
//   - yaml.v3 follows YAML 1.2: `yes`/`no`/`on`/`off` are strings, not
//     booleans, so `enabled: yes` is a load error here (PyYAML: True) and
//     `equals: yes` compares a string. Write true and false.
//   - A YAML value with no Python str() port (a timestamp) is a load error.
//   - Top-level keys other than version and rules are a load error.

var scalarFields = map[string]bool{
	"result": true, "response_code": true, "fuzzer": true, "path": true,
	"contract_path": true, "method": true, "url": true, "scenario": true,
	"result_reason": true, "result_details": true, "response_body": true,
	"response_content_type": true, "request_body": true, "any_text": true,
}

var bareFields = map[string]bool{"json_body": true, "request_headers": true}

var prefixFields = []string{"json_body.", "request_header."}

var operators = map[string]bool{
	"equals": true, "not_equals": true, "in": true, "exists": true,
	"contains": true, "contains_any": true, "contains_all": true,
	"starts_with": true, "starts_with_any": true, "ends_with": true,
	"matches": true,
}

var listOperandOps = map[string]bool{"in": true, "contains_any": true, "contains_all": true, "starts_with_any": true}

var ruleKeys = map[string]bool{"id": true, "why": true, "when": true, "any_of": true, "enabled": true, "tags": true}

// Rule is one false-positive rule.
type Rule struct {
	ID      string
	Why     string
	When    []cond // nil when absent
	AnyOf   [][]cond
	Enabled bool
	Tags    []string
}

// cond is one field's condition: a bare value (implicit equals) or operators.
type cond struct {
	field  string
	bare   any
	hasOps bool
	ops    []opCond
}

type opCond struct {
	name    string
	operand any
	re      *regexp.Regexp
}

// missingT marks a field the record does not have.
type missingT struct{}

func isMissing(v any) bool { _, ok := v.(missingT); return ok }

func typeName(v any) string {
	switch v.(type) {
	case nil:
		return "NoneType"
	case bool:
		return "bool"
	case int, int64, uint64:
		return "int"
	case float64:
		return "float"
	case string:
		return "str"
	case []any:
		return "list"
	case map[string]any, map[any]any:
		return "dict"
	}
	return fmt.Sprintf("%T", v)
}

// strMap returns v as a string-keyed map; ok is false when v is not a map,
// and badKey names a non-string key.
func strMap(v any) (m map[string]any, ok bool, badKey string) {
	switch t := v.(type) {
	case map[string]any:
		return t, true, ""
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			s, isStr := k.(string)
			if !isStr {
				return nil, true, fmt.Sprint(k)
			}
			out[s] = val
		}
		return out, true, ""
	}
	return nil, false, ""
}

func sortedKeys(m map[string]any) []string {
	ks := make([]string, 0, len(m))
	for k := range m {
		ks = append(ks, k)
	}
	sort.Strings(ks)
	return ks
}

// LoadRules reads and validates a rules file.
func LoadRules(path string) ([]Rule, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("cannot read rules file %s: %v", path, err)
	}
	var raw any
	if err := yaml.Unmarshal(b, &raw); err != nil {
		return nil, fmt.Errorf("%s: invalid YAML: %v", path, err)
	}
	top := map[string]any{}
	if raw != nil {
		m, ok, bad := strMap(raw)
		if !ok {
			return nil, fmt.Errorf("%s: top level must be a mapping with 'version' and 'rules'", path)
		}
		if bad != "" {
			return nil, fmt.Errorf("%s: top-level key %s is not a string", path, bad)
		}
		top = m
	}
	for _, k := range sortedKeys(top) {
		if k != "version" && k != "rules" {
			return nil, fmt.Errorf("%s: unknown top-level key %q", path, k)
		}
	}
	if v, ok := top["version"]; ok {
		if _, isBool := v.(bool); isBool || !numEq(v, 1) {
			return nil, fmt.Errorf("%s: unsupported version %v", path, v)
		}
	}
	entriesRaw, ok := top["rules"]
	if !ok || entriesRaw == nil {
		return nil, fmt.Errorf("%s: missing 'rules' list", path)
	}
	entries, ok := entriesRaw.([]any)
	if !ok {
		return nil, fmt.Errorf("%s: 'rules' must be a list, got %s", path, typeName(entriesRaw))
	}
	var rules []Rule
	seen := map[string]bool{}
	for i, e := range entries {
		where := fmt.Sprintf("%s: rule #%d", path, i+1)
		entry, ok, bad := strMap(e)
		if !ok {
			return nil, fmt.Errorf("%s: must be a mapping, got %s", where, typeName(e))
		}
		if bad != "" {
			return nil, fmt.Errorf("%s: key %s is not a string", where, bad)
		}
		if id, ok := entry["id"].(string); ok && id != "" {
			where += " (" + id + ")"
		}
		var unknown []string
		for _, k := range sortedKeys(entry) {
			if !ruleKeys[k] {
				unknown = append(unknown, k)
			}
		}
		if len(unknown) > 0 {
			return nil, fmt.Errorf("%s: unknown key(s) %s", where, strings.Join(unknown, ", "))
		}
		id, ok := entry["id"].(string)
		if !ok || id == "" {
			return nil, fmt.Errorf("%s: 'id' must be a non-empty string, got %v", where, entry["id"])
		}
		if seen[id] {
			return nil, fmt.Errorf("%s: duplicate rule id %q", path, id)
		}
		seen[id] = true
		why, ok := entry["why"].(string)
		if !ok || why == "" {
			return nil, fmt.Errorf("%s: missing 'why': every rule must justify itself", where)
		}
		var tags []string
		if tr, ok := entry["tags"]; ok && tr != nil {
			tl, ok := tr.([]any)
			if !ok {
				return nil, fmt.Errorf("%s: 'tags' must be a list, got %s", where, typeName(tr))
			}
			for _, t := range tl {
				s, ok := t.(string)
				if !ok {
					return nil, fmt.Errorf("%s: 'tags' entries must be strings, got %s", where, typeName(t))
				}
				tags = append(tags, s)
			}
		}
		enabled := true
		if er, ok := entry["enabled"]; ok {
			enabled, ok = er.(bool)
			if !ok {
				return nil, fmt.Errorf("%s: 'enabled' must be a boolean, got %s", where, typeName(er))
			}
		}
		when, anyOf := entry["when"], entry["any_of"]
		if when == nil && anyOf == nil {
			return nil, fmt.Errorf("%s: needs 'when' or 'any_of'", where)
		}
		r := Rule{ID: id, Why: why, Enabled: enabled, Tags: tags}
		if when != nil {
			blk, err := parseBlock(when, where)
			if err != nil {
				return nil, err
			}
			r.When = blk
		}
		if anyOf != nil {
			l, ok := anyOf.([]any)
			if !ok || len(l) == 0 {
				return nil, fmt.Errorf("%s: 'any_of' must be a non-empty list", where)
			}
			for _, bl := range l {
				blk, err := parseBlock(bl, where)
				if err != nil {
					return nil, err
				}
				r.AnyOf = append(r.AnyOf, blk)
			}
		}
		rules = append(rules, r)
	}
	return rules, nil
}

func validField(name string) bool {
	if scalarFields[name] || bareFields[name] {
		return true
	}
	for _, p := range prefixFields {
		if strings.HasPrefix(name, p) && len(name) > len(p) {
			return true
		}
	}
	return false
}

// checkValue refuses a YAML value no Python str() port exists for (a
// timestamp, for one): PyYAML would give a date object there.
func checkValue(v any) error {
	switch t := v.(type) {
	case nil, bool, int, int64, uint64, float64, string:
		return nil
	case []any:
		for _, e := range t {
			if err := checkValue(e); err != nil {
				return err
			}
		}
		return nil
	case map[string]any, map[any]any:
		m, _, _ := strMap(t)
		for _, e := range m {
			if err := checkValue(e); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("unsupported value %v of type %T (quote it to make it a string)", v, v)
}

func parseBlock(v any, where string) ([]cond, error) {
	m, ok, bad := strMap(v)
	if !ok || len(m) == 0 {
		return nil, fmt.Errorf("%s: condition blocks must be non-empty mappings", where)
	}
	if bad != "" {
		return nil, fmt.Errorf("%s: field name %s is not a string", where, bad)
	}
	var out []cond
	for _, name := range sortedKeys(m) {
		if !validField(name) {
			return nil, fmt.Errorf("%s: unknown field %q", where, name)
		}
		spec := m[name]
		if err := checkValue(spec); err != nil {
			return nil, fmt.Errorf("%s: field %q: %v", where, name, err)
		}
		c := cond{field: name}
		if sm, isMap, badOp := strMap(spec); isMap {
			if badOp != "" {
				return nil, fmt.Errorf("%s: operator name %s on field %q is not a string", where, badOp, name)
			}
			var unknown []string
			for _, op := range sortedKeys(sm) {
				if _, ok := operators[op]; !ok {
					unknown = append(unknown, op)
				}
			}
			if len(unknown) > 0 {
				return nil, fmt.Errorf("%s: unknown operator(s) %s on field %q", where, strings.Join(unknown, ", "), name)
			}
			if len(sm) == 0 {
				return nil, fmt.Errorf("%s: empty operator mapping on field %q", where, name)
			}
			c.hasOps = true
			for _, op := range sortedKeys(sm) {
				operand := sm[op]
				if listOperandOps[op] {
					if _, isList := operand.([]any); !isList {
						return nil, fmt.Errorf("%s: operator %q on field %q needs a list operand, got %s", where, op, name, typeName(operand))
					}
				}
				oc := opCond{name: op, operand: operand}
				if op == "matches" {
					re, err := regexp.Compile("(?i)" + pyStr(operand))
					if err != nil {
						return nil, fmt.Errorf("%s: invalid regex for %q (RE2 subset only): %v", where, name, err)
					}
					oc.re = re
				}
				c.ops = append(c.ops, oc)
			}
		} else {
			if _, isList := spec.([]any); isList && scalarFields[name] {
				return nil, fmt.Errorf("%s: bare list not allowed for scalar field %q (it can never match; did you mean {in: [...]}?)", where, name)
			}
			c.bare = spec
		}
		out = append(out, c)
	}
	return out, nil
}

// numeric converts the number-like values (a bool counts, as in Python).
func numeric(v any) (float64, bool) {
	switch t := v.(type) {
	case int:
		return float64(t), true
	case int64:
		return float64(t), true
	case uint64:
		return float64(t), true
	case float64:
		return t, true
	case bool:
		if t {
			return 1, true
		}
		return 0, true
	case json.Number:
		f, err := t.Float64()
		return f, err == nil
	}
	return 0, false
}

func numEq(a any, n float64) bool {
	f, ok := numeric(a)
	return ok && f == n
}

// pyEq is Python's == over decoded JSON and YAML values.
func pyEq(a, b any) bool {
	if isMissing(a) || isMissing(b) {
		return isMissing(a) && isMissing(b)
	}
	if x, ok := numeric(a); ok {
		y, ok := numeric(b)
		return ok && x == y
	}
	switch x := a.(type) {
	case nil:
		return b == nil
	case string:
		y, ok := b.(string)
		return ok && x == y
	case []any:
		y, ok := b.([]any)
		if !ok || len(x) != len(y) {
			return false
		}
		for i := range x {
			if !pyEq(x[i], y[i]) {
				return false
			}
		}
		return true
	case map[string]string:
		conv := make(map[string]any, len(x))
		for k, v := range x {
			conv[k] = v
		}
		return pyEq(conv, b)
	case map[string]any, map[any]any:
		xm, _, _ := strMap(x)
		ym, ok, _ := strMap(b)
		if !ok || len(xm) != len(ym) {
			return false
		}
		for k, v := range xm {
			w, ok := ym[k]
			if !ok || !pyEq(v, w) {
				return false
			}
		}
		return true
	}
	return false
}

func pyTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case string:
		return t != ""
	case []any:
		return len(t) > 0
	case map[string]any:
		return len(t) > 0
	case map[any]any:
		return len(t) > 0
	}
	if f, ok := numeric(v); ok {
		return f != 0
	}
	return true
}

func pyRepr(v any) string {
	switch t := v.(type) {
	case string:
		q := "'"
		if strings.Contains(t, "'") && !strings.Contains(t, `"`) {
			q = `"`
		}
		r := strings.NewReplacer(`\`, `\\`, "\n", `\n`, "\r", `\r`, "\t", `\t`)
		s := r.Replace(t)
		if q == "'" {
			s = strings.ReplaceAll(s, "'", `\'`)
		}
		return q + s + q
	case []any:
		parts := make([]string, len(t))
		for i, e := range t {
			parts[i] = pyRepr(e)
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case map[string]string:
		m := make(map[string]any, len(t))
		for k, val := range t {
			m[k] = val
		}
		return pyRepr(m)
	case map[string]any, map[any]any:
		m, _, _ := strMap(t)
		var parts []string
		for _, k := range sortedKeys(m) {
			parts = append(parts, pyRepr(k)+": "+pyRepr(m[k]))
		}
		return "{" + strings.Join(parts, ", ") + "}"
	}
	return pyStr(v)
}

// pyStr is Python's str() over decoded values.
func pyStr(v any) string {
	switch t := v.(type) {
	case nil:
		return "None"
	case string:
		return t
	case bool:
		if t {
			return "True"
		}
		return "False"
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case uint64:
		return strconv.FormatUint(t, 10)
	case float64:
		if math.IsInf(t, 0) || math.IsNaN(t) {
			return fmt.Sprint(t)
		}
		return pyFloat(t)
	case json.Number:
		s := t.String()
		if strings.ContainsAny(s, ".eE") {
			if f, err := strconv.ParseFloat(s, 64); err == nil {
				return pyFloat(f)
			}
		}
		return s
	case []any, map[string]any, map[any]any, map[string]string:
		return pyRepr(v)
	}
	return fmt.Sprint(v)
}

// fieldValue resolves a vocabulary field of a record, or missingT.
func fieldValue(r *Record, name string) any {
	switch name {
	case "any_text":
		return r.ResultReason + " " + r.ResultDetails
	case "result":
		return r.Result
	case "response_code":
		return r.ResponseCode
	case "fuzzer":
		return r.Fuzzer
	case "path":
		return r.Path
	case "contract_path":
		return r.ContractPath
	case "method":
		return r.Method
	case "url":
		return r.URL
	case "scenario":
		return r.Scenario
	case "result_reason":
		return r.ResultReason
	case "result_details":
		return r.ResultDetails
	case "response_body":
		return r.ResponseBody
	case "response_content_type":
		return r.ResponseContentType
	case "request_body":
		return r.RequestBody
	case "json_body":
		return r.JSONBody
	case "request_headers":
		return r.RequestHeaders
	}
	if rest, ok := strings.CutPrefix(name, "json_body."); ok {
		cur := r.JSONBody
		for _, part := range strings.Split(rest, ".") {
			m, ok := cur.(map[string]any)
			if !ok {
				return missingT{}
			}
			if cur, ok = m[part]; !ok {
				return missingT{}
			}
		}
		return cur
	}
	if rest, ok := strings.CutPrefix(name, "request_header."); ok {
		wanted := strings.ToLower(rest)
		for k, v := range r.RequestHeaders {
			if strings.ToLower(k) == wanted {
				return v
			}
		}
	}
	return missingT{}
}

func asText(v any) string {
	if isMissing(v) || v == nil {
		return ""
	}
	return pyStr(v)
}

func apply(oc opCond, actual any) bool {
	switch oc.name {
	case "exists":
		present := !isMissing(actual) && actual != nil
		return present == pyTruthy(oc.operand)
	case "equals":
		return pyEq(actual, oc.operand)
	case "not_equals":
		return !pyEq(actual, oc.operand)
	case "in":
		for _, e := range oc.operand.([]any) {
			if pyEq(actual, e) {
				return true
			}
		}
		return false
	}
	text := strings.ToLower(asText(actual))
	lower := func(v any) string { return strings.ToLower(pyStr(v)) }
	switch oc.name {
	case "contains":
		return strings.Contains(text, lower(oc.operand))
	case "contains_any":
		for _, e := range oc.operand.([]any) {
			if strings.Contains(text, lower(e)) {
				return true
			}
		}
		return false
	case "contains_all":
		for _, e := range oc.operand.([]any) {
			if !strings.Contains(text, lower(e)) {
				return false
			}
		}
		return true
	case "starts_with":
		return strings.HasPrefix(text, lower(oc.operand))
	case "starts_with_any":
		for _, e := range oc.operand.([]any) {
			if strings.HasPrefix(text, lower(e)) {
				return true
			}
		}
		return false
	case "ends_with":
		return strings.HasSuffix(text, lower(oc.operand))
	case "matches":
		return oc.re.FindStringIndex(text) != nil
	}
	return false
}

func matchBlock(b []cond, r *Record) bool {
	for _, c := range b {
		actual := fieldValue(r, c.field)
		if c.hasOps {
			for _, oc := range c.ops {
				if !apply(oc, actual) {
					return false
				}
			}
		} else if !pyEq(actual, c.bare) {
			return false
		}
	}
	return true
}

// Match reports whether the rule's conditions all hold for the record.
func Match(rule Rule, rec Record) bool {
	if rule.When == nil && rule.AnyOf == nil {
		return false
	}
	if rule.When != nil && !matchBlock(rule.When, &rec) {
		return false
	}
	if rule.AnyOf == nil {
		return true
	}
	for _, b := range rule.AnyOf {
		if matchBlock(b, &rec) {
			return true
		}
	}
	return false
}

// Classify returns whether rec is a recorded false positive and by which
// rule. Only error and warn records are classified; the first enabled rule
// that matches wins. A match on a 5xx response is never a suppression: it
// comes back as a violation naming the rule.
func Classify(rules []Rule, rec Record) (fp bool, ruleID string, violation string) {
	if rec.Result != "error" && rec.Result != "warn" {
		return false, "", ""
	}
	for _, rule := range rules {
		if !rule.Enabled || !Match(rule, rec) {
			continue
		}
		code := rec.ResponseCode
		if code >= 500 && code < 600 {
			return false, "", rule.ID
		}
		return true, rule.ID, ""
	}
	return false, "", ""
}
