package main

import (
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// TestCommittedRules holds api/cats-false-positives.yaml to ruling 6: every
// rule names its response codes and none names a 5xx one.
func TestCommittedRules(t *testing.T) {
	rules, err := LoadRules(filepath.Join("..", "..", "api", "cats-false-positives.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	id := regexp.MustCompile(`^[A-Z][A-Z0-9]*(_[A-Z0-9]+)*$`)
	seen := map[string]bool{}
	for _, r := range rules {
		if !id.MatchString(r.ID) || seen[r.ID] {
			t.Errorf("rule id %q is not unique UPPER_SNAKE_CASE", r.ID)
		}
		seen[r.ID] = true
		if strings.TrimSpace(r.Why) == "" {
			t.Errorf("%s: empty why", r.ID)
		}
		var blocks [][]cond
		if r.When != nil {
			blocks = append(blocks, r.When)
		}
		blocks = append(blocks, r.AnyOf...)
		for _, b := range blocks {
			codes := false
			for _, c := range b {
				if c.field == "fuzzer" && mentions(c, "FakeCatsFuzzer") {
					t.Errorf("%s: names FakeCatsFuzzer, the selftest fake's fuzzer", r.ID)
				}
				if c.field != "response_code" {
					continue
				}
				for _, v := range codeValues(t, r.ID, c) {
					codes = true
					if v >= 500 && v < 600 {
						t.Errorf("%s: response_code %d is 5xx", r.ID, v)
					}
				}
			}
			if !codes {
				t.Errorf("%s: a condition block does not constrain response_code with equals or in", r.ID)
			}
		}
	}
	if len(rules) == 0 {
		t.Error("no rules")
	}
}

func mentions(c cond, name string) bool {
	if c.bare != nil && pyStr(c.bare) == name {
		return true
	}
	for _, o := range c.ops {
		if pyStr(o.operand) == name {
			return true
		}
		if l, ok := o.operand.([]any); ok {
			for _, e := range l {
				if pyStr(e) == name {
					return true
				}
			}
		}
	}
	return false
}

// codeValues returns the codes a response_code condition names through a bare
// value, equals or in; any other operator on the field names none.
func codeValues(t *testing.T, id string, c cond) []int {
	t.Helper()
	var out []int
	add := func(v any) {
		f, ok := numeric(v)
		if !ok {
			t.Errorf("%s: response_code operand %v is not a number", id, v)
			return
		}
		out = append(out, int(f))
	}
	if !c.hasOps {
		add(c.bare)
	}
	for _, o := range c.ops {
		switch o.name {
		case "equals":
			add(o.operand)
		case "in":
			for _, e := range o.operand.([]any) {
				add(e)
			}
		}
	}
	return out
}
