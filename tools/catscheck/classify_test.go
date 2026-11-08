package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func loadRec(t *testing.T, n int) Record {
	t.Helper()
	recs, err := loadReport(filepath.Join("testdata", "report"), &bytes.Buffer{})
	if err != nil || len(recs) < n {
		t.Fatalf("report: %v (%d records)", err, len(recs))
	}
	return recs[n-1]
}

func TestLoadReport(t *testing.T) {
	t.Run("fields", func(t *testing.T) {
		recs, err := loadReport(filepath.Join("testdata", "report"), &bytes.Buffer{})
		if err != nil || len(recs) != 6 {
			t.Fatalf("%v %d", err, len(recs))
		}
		r := recs[0]
		if r.Result != "error" || r.ResponseCode != 400 || r.Method != "POST" || r.Fuzzer != "HappyPath" ||
			r.Path != "/v1/channels" || r.ContractPath != "/v1/channels" ||
			r.ResponseContentType != "application/problem+json" {
			t.Errorf("record %+v", r)
		}
		if !strings.Contains(r.ResponseBody, `"code": "validation", "detail"`) || !strings.HasPrefix(r.ResponseBody, "{") {
			t.Errorf("response_body is not Python-style JSON: %q", r.ResponseBody)
		}
		if r.RequestHeaders["accept"] != "application/json" || !strings.HasPrefix(r.RequestHeaders["authorization"], "sha256:") {
			t.Errorf("headers %v", r.RequestHeaders)
		}
		if !strings.HasPrefix(r.RequestBody, `{"name"`) || r.JSONBody == nil {
			t.Error("request body or json body missing")
		}
		if recs[4].ResponseBody != `{"notAJson": "Unsupported transfer encoding"}` {
			t.Errorf("a text/plain response body is %q", recs[4].ResponseBody)
		}
	})
	t.Run("skips_malformed_file", func(t *testing.T) {
		var warn bytes.Buffer
		recs, err := loadReport(filepath.Join("testdata", "report-malformed"), &warn)
		if err != nil || len(recs) != 1 {
			t.Fatalf("%v %d", err, len(recs))
		}
		if !strings.Contains(warn.String(), "Test2.json") || !strings.Contains(warn.String(), "missing fields") {
			t.Errorf("warning %q", warn.String())
		}
	})
	t.Run("numeric_order_and_non_json", func(t *testing.T) {
		d := t.TempDir()
		src, _ := os.ReadFile(filepath.Join("testdata", "report", "Test1.json"))
		for _, n := range []string{"Test10.json", "Test2.json", "Test1.json"} {
			if err := os.WriteFile(filepath.Join(d, n), bytes.ReplaceAll(src, []byte(`"HappyPath"`), []byte(`"`+n+`"`)), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		if err := os.WriteFile(filepath.Join(d, "Test3.json"), []byte("not json"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(d, "cats-summary-report.json"), []byte("{}"), 0o600); err != nil {
			t.Fatal(err)
		}
		var warn bytes.Buffer
		recs, err := loadReport(d, &warn)
		if err != nil || len(recs) != 3 || recs[0].Fuzzer != "Test1.json" || recs[1].Fuzzer != "Test2.json" || recs[2].Fuzzer != "Test10.json" {
			t.Fatalf("%v %+v", err, recs)
		}
		if !strings.Contains(warn.String(), "Test3.json") {
			t.Errorf("no warning for invalid JSON: %q", warn.String())
		}
	})
	t.Run("missing_ten_fields", func(t *testing.T) {
		d := t.TempDir()
		src, _ := os.ReadFile(filepath.Join("testdata", "report", "Test1.json"))
		for _, k := range []string{"traceId", "expectedResult", "server"} {
			var m map[string]any
			if err := json.Unmarshal(src, &m); err != nil {
				t.Fatal(err)
			}
			delete(m, k)
			b, _ := json.Marshal(m)
			if err := os.WriteFile(filepath.Join(d, "Test"+k+"1.json"), b, 0o600); err != nil {
				t.Fatal(err)
			}
		}
		var warn bytes.Buffer
		recs, err := loadReport(d, &warn)
		if err != nil || len(recs) != 0 || strings.Count(warn.String(), "missing fields") != 3 {
			t.Fatalf("%v %d %q", err, len(recs), warn.String())
		}
	})
	t.Run("missing_dir", func(t *testing.T) {
		if _, err := loadReport(filepath.Join(t.TempDir(), "none"), &bytes.Buffer{}); err == nil {
			t.Error("a missing directory loaded")
		}
	})
}

func TestPyJSON(t *testing.T) {
	for in, want := range map[string]string{
		`{"b":1,"a":[true,null,"x"],"c":{}}`: `{"b": 1, "a": [true, null, "x"], "c": {}}`,
		`"é\n\u0001/😀"`:                      `"\u00e9\n\u0001/\ud83d\ude00"`,
		`[1.0, 1e2, 0.5, 1e16, 1.5e-7, -0]`:  `[1.0, 100.0, 0.5, 1e+16, 1.5e-07, 0]`,
		"\"a\x7fb\"":                         `"a\u007fb"`,
		`[12345678901234567890]`:             `[12345678901234567890]`,
	} {
		if got := pyJSON([]byte(in)); got != want {
			t.Errorf("pyJSON(%s) = %s, want %s", in, got, want)
		}
	}
}

func TestClassify(t *testing.T) {
	r400 := loadRec(t, 1)
	rule := func(id string, code int) Rule {
		return Rule{ID: id, Why: "w", Enabled: true, When: []cond{{field: "response_code", bare: code}}}
	}
	t.Run("first_match_wins", func(t *testing.T) {
		fp, id, v := Classify([]Rule{rule("A", 401), rule("B", 400), rule("C", 400)}, r400)
		if !fp || id != "B" || v != "" {
			t.Errorf("%v %q %q", fp, id, v)
		}
	})
	t.Run("success_never_classified", func(t *testing.T) {
		r := r400
		r.Result = "success"
		if fp, id, v := Classify([]Rule{rule("B", 400)}, r); fp || id != "" || v != "" {
			t.Errorf("%v %q %q", fp, id, v)
		}
	})
	t.Run("warn_is_classified", func(t *testing.T) {
		r := r400
		r.Result = "warn"
		if fp, _, _ := Classify([]Rule{rule("B", 400)}, r); !fp {
			t.Error("a warn was not classified")
		}
	})
	t.Run("disabled_rule_skipped", func(t *testing.T) {
		off := rule("OFF", 400)
		off.Enabled = false
		fp, id, _ := Classify([]Rule{off, rule("ON", 400)}, r400)
		if !fp || id != "ON" {
			t.Errorf("%v %q", fp, id)
		}
		if fp, _, v := Classify([]Rule{off}, r400); fp || v != "" {
			t.Error("a disabled rule matched")
		}
	})
	t.Run("rule_never_suppresses_5xx", func(t *testing.T) {
		rs, err := LoadRules(filepath.Join("testdata", "rules", "five-xx.yaml"))
		if err != nil {
			t.Fatal(err)
		}
		r503 := loadRec(t, 6)
		if fp, id, v := Classify(rs, r503); fp || id != "" || v != "FIVE_XX" {
			t.Errorf("%v %q %q", fp, id, v)
		}
		for code, wantViolation := range map[int]bool{499: false, 500: true, 599: true, 600: false, 999: false} {
			r := r400
			r.ResponseCode = code
			fp, _, v := Classify([]Rule{rule("X", code)}, r)
			if (v != "") != wantViolation || fp == wantViolation {
				t.Errorf("code %d: fp %v violation %q", code, fp, v)
			}
		}
		var out, errb bytes.Buffer
		code := run([]string{"classify", "--rules", filepath.Join("testdata", "rules", "five-xx.yaml"), filepath.Join("testdata", "report")}, &out, &errb)
		if code != 1 || !strings.Contains(out.String(), "catscheck: rule FIVE_XX matched a 503 response and was refused") {
			t.Errorf("exit %d, out %q", code, out.String())
		}
	})
	t.Run("any_text_contains", func(t *testing.T) {
		r := mustRule(t, "    when: {any_text: {contains_all: ['unexpected response', 'does not match']}}\n")
		rec := r400
		rec.ResultReason, rec.ResultDetails = "Unexpected response code", "Response does NOT match expected"
		if !Match(r, rec) {
			t.Error("reason and details are not joined")
		}
		rec.ResultReason = ""
		if Match(r, rec) {
			t.Error("matched without the reason")
		}
	})
	t.Run("json_body_path", func(t *testing.T) {
		r := mustRule(t, "    when: {json_body.code: validation, json_body.nest.deep: {equals: 3}}\n")
		rec := r400
		rec.JSONBody = map[string]any{"code": "validation", "nest": map[string]any{"deep": 3}}
		if !Match(r, rec) {
			t.Error("dotted path not walked")
		}
		rec.JSONBody = map[string]any{"code": "validation", "nest": "flat"}
		if Match(r, rec) {
			t.Error("a non-map was walked")
		}
		rec.JSONBody = []any{"validation"}
		if Match(r, rec) {
			t.Error("a list body was walked")
		}
		if Match(r, loadRec(t, 5)) {
			t.Error("a record with no body matched")
		}
		real := mustRule(t, "    when: {json_body.code: validation}\n")
		if !Match(real, r400) {
			t.Error("the recorded problem body does not match")
		}
	})
	t.Run("request_header_case_insensitive", func(t *testing.T) {
		r := mustRule(t, "    when: {request_header.ACCEPT: {equals: application/json}}\n")
		if !Match(r, r400) {
			t.Error("header name case mattered")
		}
		r = mustRule(t, "    when: {request_header.x-nope: {exists: false}}\n")
		if !Match(r, r400) {
			t.Error("absent header exists")
		}
	})
}

func TestMainClassify(t *testing.T) {
	rep := filepath.Join("testdata", "report")
	valid := filepath.Join("testdata", "rules", "valid.yaml")
	starter := filepath.Join("testdata", "rules", "starter.yaml") // the two starter rules (1433416); the real file grows each round
	// A copy of the report without the 503 record: the rules file covers the rest.
	covered := t.TempDir()
	for _, n := range []string{"Test1.json", "Test2.json", "Test3.json", "Test4.json", "Test5.json"} {
		b, err := os.ReadFile(filepath.Join(rep, n))
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(covered, n), b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Run("exit_codes", func(t *testing.T) {
		cases := []struct {
			name string
			args []string
			code int
			out  string
		}{
			{"all_suppressed", []string{"classify", "--rules", valid, covered}, 0, "catscheck: 5 tests, 2 error, 1 warn, 3 suppressed by 3 rule(s), 0 finding(s)"},
			{"starter_file", []string{"classify", "--rules", starter, covered}, 1, "catscheck: 5 tests, 2 error, 1 warn, 0 suppressed by 0 rule(s), 3 finding(s)"},
			{"violation_counts", []string{"classify", "--rules", valid, rep}, 1, "6 tests, 3 error, 1 warn, 3 suppressed by 3 rule(s), 1 finding(s)"},
			{"bad_rules", []string{"classify", "--rules", filepath.Join("testdata", "rules", "unknown-key.yaml"), rep}, 2, ""},
			{"missing_rules_file", []string{"classify", "--rules", filepath.Join(covered, "none.yaml"), rep}, 2, ""},
			{"missing_report_dir", []string{"classify", "--rules", valid, filepath.Join(covered, "none")}, 2, ""},
			{"no_rules_flag", []string{"classify", rep}, 2, ""},
			{"no_report_dir", []string{"classify", "--rules", valid}, 2, ""},
			{"extra_argument", []string{"classify", "--rules", valid, rep, rep}, 2, ""},
			{"empty_report_dir", []string{"classify", "--rules", valid, t.TempDir()}, 2, ""},
			{"bad_max_lines", []string{"classify", "--rules", valid, "--max-lines", "x", rep}, 2, ""},
			{"negative_max_lines", []string{"classify", "--rules", valid, "--max-lines", "-1", rep}, 2, ""},
		}
		for _, c := range cases {
			t.Run(c.name, func(t *testing.T) {
				var out, errb bytes.Buffer
				if code := run(c.args, &out, &errb); code != c.code {
					t.Fatalf("exit %d, want %d (stdout %q stderr %q)", code, c.code, out.String(), errb.String())
				}
				if c.name == "empty_report_dir" && !strings.Contains(errb.String(), "no CATS test records in") {
					t.Errorf("stderr %q", errb.String())
				}
				if !strings.Contains(out.String(), c.out) {
					t.Errorf("stdout %q lacks %q", out.String(), c.out)
				}
			})
		}
	})
	t.Run("unknown_result_refused", func(t *testing.T) {
		// A record whose result is neither success, warn nor error is not
		// dropped: exit 2, naming the value.
		dir := t.TempDir()
		b, err := os.ReadFile(filepath.Join(rep, "Test1.json"))
		if err != nil {
			t.Fatal(err)
		}
		var rec map[string]any
		if err := json.Unmarshal(b, &rec); err != nil {
			t.Fatal(err)
		}
		rec["result"] = "skipped"
		b, err = json.Marshal(rec)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "Test1.json"), b, 0o600); err != nil {
			t.Fatal(err)
		}
		var out, errb bytes.Buffer
		if code := run([]string{"classify", "--rules", valid, dir}, &out, &errb); code != 2 {
			t.Fatalf("exit %d, want 2 (stdout %q stderr %q)", code, out.String(), errb.String())
		}
		if !strings.Contains(errb.String(), `unknown result "skipped"`) {
			t.Errorf("stderr %q does not name the value", errb.String())
		}
	})
	t.Run("tsv_and_cap", func(t *testing.T) {
		var out, errb bytes.Buffer
		code := run([]string{"classify", "--rules", starter, "--max-lines", "2", covered}, &out, &errb)
		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		if code != 1 || len(lines) != 4 {
			t.Fatalf("exit %d, lines %q", code, lines)
		}
		want := "error\tPOST\t/v1/channels\t400\tHappyPath\tUnexpected response code: 400"
		if lines[0] != want {
			t.Errorf("line %q, want %q", lines[0], want)
		}
		if lines[2] != "... and 1 more" {
			t.Errorf("cap line %q", lines[2])
		}
	})
}
