package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rulesFrom writes a rules file holding one rule with the given body lines.
func rulesFrom(t *testing.T, body string) ([]Rule, error) {
	t.Helper()
	f := filepath.Join(t.TempDir(), "r.yaml")
	text := "version: 1\nrules:\n  - id: R\n    why: test\n" + body
	if err := os.WriteFile(f, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	return LoadRules(f)
}

func mustRule(t *testing.T, body string) Rule {
	t.Helper()
	rs, err := rulesFrom(t, body)
	if err != nil || len(rs) != 1 {
		t.Fatalf("load %q: %v", body, err)
	}
	return rs[0]
}

func base() Record {
	return Record{
		Result: "error", ResponseCode: 400, Fuzzer: "HappyPath", Path: "/v1/channels",
		Method: "POST", ResultReason: "Unexpected response code: 400", ResultDetails: "Details Here",
		ResponseContentType: "application/problem+json", RequestBody: "{}",
		RequestHeaders: map[string]string{"accept": "application/json"},
	}
}

func TestLoadRules(t *testing.T) {
	cases := []struct {
		name, file string
		want       []string // substrings of the error; nil: loads
	}{
		{"valid", "valid.yaml", nil},
		{"unknown_operator_rejected", "unknown-operator.yaml", []string{"BAD_OP", "greater_than"}},
		{"unknown_field_rejected", "unknown-field.yaml", []string{"BAD_FIELD", "status_code"}},
		{"bare_list_rejected", "bare-list.yaml", []string{"BARE_LIST", "bare list"}},
		{"no_condition_rejected", "no-condition.yaml", []string{"NO_CONDITION", "needs 'when' or 'any_of'"}},
		{"unknown_key_rejected", "unknown-key.yaml", []string{"BAD_KEY", "reason"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rs, err := LoadRules(filepath.Join("testdata", "rules", c.file))
			if c.want == nil {
				if err != nil || len(rs) != 4 || rs[3].Enabled || len(rs[0].Tags) != 1 {
					t.Fatalf("valid.yaml: %v %+v", err, rs)
				}
				return
			}
			if err == nil {
				t.Fatal("loaded")
			}
			for _, w := range c.want {
				if !strings.Contains(err.Error(), w) {
					t.Errorf("error %q lacks %q", err, w)
				}
			}
		})
	}
}

// Every other rejection of the loader (Definition of Done B).
func TestLoadRulesRejects(t *testing.T) {
	cases := []struct{ name, body, want string }{
		{"empty_when", "    when: {}\n", "non-empty mappings"},
		{"when_not_map", "    when: 7\n", "non-empty mappings"},
		{"empty_any_of", "    any_of: []\n", "non-empty list"},
		{"any_of_empty_block", "    any_of: [{}]\n", "non-empty mappings"},
		{"empty_operator_map", "    when: {path: {}}\n", "empty operator mapping"},
		{"scalar_operand_for_in", "    when: {response_code: {in: 400}}\n", "needs a list operand"},
		{"scalar_operand_for_contains_any", "    when: {path: {contains_any: a}}\n", "needs a list operand"},
		{"bad_regex", "    when: {path: {matches: '('}}\n", "invalid regex"},
		{"lookahead_refused_by_re2", "    when: {path: {matches: 'a(?=b)'}}\n", "invalid regex"},
		{"backreference_refused_by_re2", "    when: {path: {matches: '(a)\\1'}}\n", "invalid regex"},
		{"empty_prefix_field", "    when: {'json_body.': 1}\n", "unknown field"},
		{"enabled_not_bool", "    enabled: 'false'\n    when: {response_code: 1}\n", "'enabled' must be a boolean"},
		{"tags_not_list", "    tags: x\n    when: {response_code: 1}\n", "'tags' must be a list"},
		{"tag_not_string", "    tags: [1]\n    when: {response_code: 1}\n", "must be strings"},
		{"timestamp_operand", "    when: {path: {contains: 2026-01-01T00:00:00Z}}\n", "unsupported value"},
		{"timestamp_in_list", "    when: {path: {contains_any: [2026-01-01]}}\n", "unsupported value"},
		{"unknown_operator_in_any_of", "    any_of: [{path: {nope: 1}}]\n", "unknown operator"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := rulesFrom(t, c.body)
			if err == nil || !strings.Contains(err.Error(), c.want) || !strings.Contains(err.Error(), "(R)") {
				t.Fatalf("got %v, want %q naming rule R", err, c.want)
			}
		})
	}
	files := []struct{ name, text, want string }{
		{"top_level_unknown_key", "version: 1\nextra: 1\nrules: []\n", "unknown top-level key"},
		{"version_2", "version: 2\nrules: []\n", "unsupported version"},
		{"missing_rules", "version: 1\n", "missing 'rules'"},
		{"empty_file", "", "missing 'rules'"},
		{"rules_not_list", "version: 1\nrules: {}\n", "must be a list"},
		{"not_a_mapping", "- a\n", "top level must be a mapping"},
		{"bad_yaml", "a: [\n", "invalid YAML"},
		{"rule_not_mapping", "rules:\n  - 3\n", "must be a mapping"},
		{"missing_id", "rules:\n  - why: x\n    when: {response_code: 1}\n", "'id' must be"},
		{"missing_why", "rules:\n  - id: A\n    when: {response_code: 1}\n", "missing 'why'"},
		{"duplicate_id", "rules:\n  - {id: A, why: x, when: {response_code: 1}}\n  - {id: A, why: x, when: {response_code: 1}}\n", "duplicate rule id"},
	}
	for _, c := range files {
		t.Run(c.name, func(t *testing.T) {
			f := filepath.Join(t.TempDir(), "r.yaml")
			if err := os.WriteFile(f, []byte(c.text), 0o600); err != nil {
				t.Fatal(err)
			}
			if _, err := LoadRules(f); err == nil || !strings.Contains(err.Error(), c.want) {
				t.Fatalf("got %v, want %q", err, c.want)
			}
		})
	}
	if _, err := LoadRules(filepath.Join(t.TempDir(), "none.yaml")); err == nil {
		t.Error("a missing file loaded")
	}
}

func TestMatch(t *testing.T) {
	type chk struct {
		cond string
		mut  func(*Record)
		want bool
	}
	none := func(*Record) {}
	cases := []struct {
		op   string
		chks []chk
	}{
		{"equals", []chk{
			{"{response_code: {equals: 400}}", none, true},
			{"{response_code: 400}", none, true},
			{"{response_code: '400'}", none, false},        // int is not string
			{"{fuzzer: {equals: happypath}}", none, false}, // case-sensitive
			{"{fuzzer: HappyPath}", none, true},
			{"{json_body.x: {equals: 1}}", none, false}, // missing equals nothing
			{"{json_body.x: {equals: 1}}", func(r *Record) { r.JSONBody = map[string]any{"x": float64(1)} }, true},
		}},
		{"not_equals", []chk{
			{"{response_code: {not_equals: 401}}", none, true},
			{"{response_code: {not_equals: 400}}", none, false},
			{"{json_body.x: {not_equals: ''}}", none, true}, // missing is not_equals everything
		}},
		{"in", []chk{
			{"{response_code: {in: [400, 401]}}", none, true},
			{"{response_code: {in: [401, 404]}}", none, false},
			{"{fuzzer: {in: [happypath]}}", none, false},
			{"{json_body.x: {in: [1, null]}}", none, false}, // missing is in nothing
		}},
		{"exists", []chk{
			{"{json_body.x: {exists: true}}", none, false},
			{"{json_body.x: {exists: false}}", none, true},
			{"{json_body.x: {exists: true}}", func(r *Record) { r.JSONBody = map[string]any{"x": "v"} }, true},
			{"{json_body.x: {exists: true}}", func(r *Record) { r.JSONBody = map[string]any{"x": nil} }, false}, // null is absent
			{"{any_text: {exists: false}}", none, false},                                                        // never missing
			{"{request_header.accept: {exists: true}}", none, true},
		}},
		{"contains", []chk{
			{"{result_reason: {contains: RESPONSE CODE}}", none, true},
			{"{result_reason: {contains: nope}}", none, false},
			{"{json_body.x: {contains: 'n'}}", none, false}, // missing is ""
			{"{json_body.x: {contains: ''}}", none, true},
			{"{json_body.x: {contains: tr}}", func(r *Record) { r.JSONBody = map[string]any{"x": true} }, true}, // str(True).lower()
		}},
		{"contains_any", []chk{
			{"{path: {contains_any: [NOPE, CHANNELS]}}", none, true},
			{"{path: {contains_any: [nope]}}", none, false},
			{"{path: {contains_any: []}}", none, false},
		}},
		{"contains_all", []chk{
			{"{path: {contains_all: [V1, Channels]}}", none, true},
			{"{path: {contains_all: [v1, nope]}}", none, false},
			{"{path: {contains_all: []}}", none, true},
		}},
		{"starts_with", []chk{
			{"{path: {starts_with: /V1}}", none, true},
			{"{path: {starts_with: channels}}", none, false},
		}},
		{"starts_with_any", []chk{
			{"{path: {starts_with_any: [/x, /V1/]}}", none, true},
			{"{path: {starts_with_any: [/x]}}", none, false},
		}},
		{"ends_with", []chk{
			{"{path: {ends_with: CHANNELS}}", none, true},
			{"{path: {ends_with: v1}}", none, false},
		}},
		{"matches", []chk{
			{"{request_headers: {contains: \"'accept': 'application/json'\"}}", none, true}, // str(dict)
			{"{request_headers: {contains: nope}}", none, false},
			{"{path: {matches: 'v1/chan'}}", none, true}, // search, not full match
			{"{path: {matches: '^chan'}}", none, false},
			{"{path: {matches: 'CHANNELS$'}}", none, true}, // case-insensitive
			{"{result_reason: {matches: 'code: (400|401)'}}", none, true},
		}},
	}
	for _, c := range cases {
		t.Run(c.op, func(t *testing.T) {
			for i, k := range c.chks {
				r := mustRule(t, "    when: "+k.cond+"\n")
				rec := base()
				k.mut(&rec)
				if got := Match(r, rec); got != k.want {
					t.Errorf("check %d %s: got %v, want %v", i, k.cond, got, k.want)
				}
			}
		})
	}
	t.Run("when_and_any_of_are_anded", func(t *testing.T) {
		r := mustRule(t, "    when: {response_code: 400}\n    any_of: [{method: GET}, {method: POST}]\n")
		if !Match(r, base()) {
			t.Error("no match")
		}
		rec := base()
		rec.ResponseCode = 401
		if Match(r, rec) {
			t.Error("when ignored")
		}
		rec = base()
		rec.Method = "PUT"
		if Match(r, rec) {
			t.Error("any_of ignored")
		}
	})
	t.Run("block_is_anded", func(t *testing.T) {
		r := mustRule(t, "    when: {response_code: 400, fuzzer: Other}\n")
		if Match(r, base()) {
			t.Error("matched with one false condition")
		}
	})
	t.Run("no_condition_never_matches", func(t *testing.T) {
		if Match(Rule{ID: "X", Enabled: true}, base()) {
			t.Error("a rule with no condition matched")
		}
	})
}

func TestPyStr(t *testing.T) {
	cases := []struct {
		in   any
		want string
	}{
		{nil, "None"}, {true, "True"}, {5, "5"}, {5.0, "5.0"}, {1e16, "1e+16"}, {0.00001, "1e-05"},
		{[]any{"a", 1.0, nil}, "['a', 1.0, None]"}, {map[string]any{"k": "it's"}, `{'k': "it's"}`},
	}
	for _, c := range cases {
		if got := pyStr(c.in); got != c.want {
			t.Errorf("pyStr(%v) = %q, want %q", c.in, got, c.want)
		}
	}
}
