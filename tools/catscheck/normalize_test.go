package main

import (
	"bytes"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func readSpec(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("testdata", "spec-min.yaml"))
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func parse(t *testing.T, s string) *yaml.Node {
	t.Helper()
	var d yaml.Node
	if err := yaml.Unmarshal([]byte(s), &d); err != nil {
		t.Fatal(err)
	}
	return &d
}

func normalized(t *testing.T, s string) string {
	t.Helper()
	return string(canonical(Normalize(parse(t, s))))
}

func TestNormalize(t *testing.T) {
	spec := readSpec(t)
	got := normalized(t, spec)
	cases := []struct {
		name string
		has  []string
		not  []string
	}{
		{"strips_operation_description", nil, []string{"Lists the things.", "Gets one.", "List things"}},
		{"strips_schema_example", nil, []string{"A thing.", "id: a\n"}},
		{"strips_components_examples", nil, []string{"Sample:", "examples:"}},
		{"property_named_description_kept", []string{"description:\n"}, nil},
		{"response_description_stripped", []string{"'200':", "'404':", "'201':"}, []string{"The things.", "Created.", "Not found."}},
		{"extensions_kept", []string{"x-foo: bar"}, nil},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if c.name == "property_named_description_kept" && !regexp.MustCompile(`(?m)^ +description:\n +type: string$`).MatchString(got) {
				t.Errorf("property description lost:\n%s", got)
			}
			for _, h := range c.has {
				if !strings.Contains(got, h) {
					t.Errorf("normalized document lacks %q:\n%s", h, got)
				}
			}
			for _, n := range c.not {
				if strings.Contains(got, n) {
					t.Errorf("normalized document still has %q", n)
				}
			}
		})
	}
	t.Run("idempotent", func(t *testing.T) {
		once := Normalize(parse(t, spec))
		twice := Normalize(once)
		if !bytes.Equal(canonical(once), canonical(twice)) {
			t.Error("normalizing twice differs from once")
		}
	})
	t.Run("input_not_modified", func(t *testing.T) {
		d := parse(t, spec)
		before := canonical(d)
		Normalize(d)
		if !bytes.Equal(before, canonical(d)) {
			t.Error("Normalize modified its input")
		}
	})
	t.Run("key_order_and_flow_style_ignored", func(t *testing.T) {
		a := normalized(t, "b: 1\na: {y: 1, x: 2}\n")
		b := normalized(t, "a:\n  x: 2\n  y: 1\nb: 1\n")
		if a != b {
			t.Errorf("canonical forms differ:\n%s\n%s", a, b)
		}
	})
}
