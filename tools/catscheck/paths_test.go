package main

import (
	"bytes"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
)

// edit replaces old by new once in s and fails when old is absent.
func edit(t *testing.T, s, old, new string) string {
	t.Helper()
	if strings.Count(s, old) != 1 {
		t.Fatalf("fixture anchor %q occurs %d times", old, strings.Count(s, old))
	}
	return strings.Replace(s, old, new, 1)
}

const orphanAnchor = "  examples:\n    Sample:"

// withOrphan adds a component no path references.
func withOrphan(t *testing.T, s, typ string) string {
	return edit(t, s, orphanAnchor, "  schemas2:\n    Orphan:\n      type: "+typ+"\n"+orphanAnchor)
}

// withScheme adds components.securitySchemes.bearerAuth of the given type.
func withScheme(t *testing.T, s, typ string) string {
	return edit(t, s, "  parameters:\n    Limit:", "  securitySchemes:\n    bearerAuth:\n      type: "+typ+"\n  parameters:\n    Limit:")
}

const idProp = "        id:\n          type: string\n        description:"

func TestChangedPaths(t *testing.T) {
	spec := readSpec(t)
	both := []string{"/v1/things", "/v1/things/{id}"}
	// nested: Thing references Inner, which no path references directly.
	nestedBase := edit(t, edit(t, spec, "        description:\n          type: string\n  examples:", "        description:\n          type: string\n        inner:\n          $ref: '#/components/schemas/Inner'\n    Inner:\n      type: object\n      properties:\n        v:\n          type: string\n  examples:"), "x-foo: bar", "x-foo: bar")
	cycleBase := edit(t, spec, idProp, "        self:\n          $ref: '#/components/schemas/Thing'\n"+idProp)
	docEdit := spec
	for _, e := range [][2]string{
		{"description: Lists the things.", "description: Edited."},
		{"summary: List things", "summary: Edited summary"},
		{"example: []", "example: [1]"},
		{"url: https://example.com", "url: https://example.org"},
		{"description: The name.", "description: Edited name."},
		{"description: Not found.", "description: Edited 404."},
		{"      summary: Get a thing\n", "      summary: Get a thing\n      example: x\n"},
	} {
		docEdit = edit(t, docEdit, e[0], e[1])
	}
	cases := []struct {
		name     string
		old, new string
		paths    []string
		docOnly  bool
		wantErr  bool
	}{
		{"documentation_only", spec, docEdit, nil, true, false},
		{"required_change_is_a_change", spec, edit(t, spec, "required: [name]", "required: [name, x]"), []string{"/v1/things"}, false, false},
		{"path_added", spec, edit(t, spec, "components:\n", "  /v1/other:\n    get:\n      operationId: other\ncomponents:\n"), []string{"/v1/other"}, false, false},
		{"path_removed", edit(t, spec, "components:\n", "  /v1/other:\n    get:\n      operationId: other\ncomponents:\n"), spec, []string{"/v1/other"}, false, false},
		{"servers_change_is_every_path", spec, edit(t, spec, "localhost:8420", "localhost:1"), []string{"/v1/things", "/v1/things/{id}"}, false, false},
		{"security_change_is_every_path", spec, edit(t, spec, "- bearerAuth: []", "- other: []"), []string{"/v1/things", "/v1/things/{id}"}, false, false},
		{"openapi_change_is_every_path", spec, edit(t, spec, "openapi: 3.1.0", "openapi: 3.1.1"), []string{"/v1/things", "/v1/things/{id}"}, false, false},
		{"info_change_is_documentation", spec, edit(t, spec, "title: min", "title: other"), nil, true, false},
		{"tags_change_is_documentation", spec, edit(t, spec, "- name: things\n", "- name: stuff\n"), nil, true, false},
		{"unreferenced_component_is_no_path", withOrphan(t, spec, "string"), withOrphan(t, spec, "integer"), nil, false, false},
		{"schema_change_widens", spec, edit(t, spec, idProp, "        id:\n          type: integer\n        description:"), both, false, false},
		{"nested_ref_widens", nestedBase, edit(t, nestedBase, "        v:\n          type: string", "        v:\n          type: integer"), both, false, false},
		{"ref_cycle_terminates", cycleBase, edit(t, cycleBase, idProp, "        id:\n          type: integer\n        description:"), both, false, false},
		{"parameter_change_widens", spec, edit(t, spec, "type: integer", "type: string"), []string{"/v1/things"}, false, false},
		{"response_change_widens", spec, edit(t, spec, "    NotFound:\n      description: Not found.", "    NotFound:\n      description: Not found.\n      headers:\n        X-A:\n          schema:\n            type: string"), both, false, false},
		{"security_scheme_change_is_every_path", withScheme(t, spec, "http"), withScheme(t, spec, "apiKey"), both, false, false},
		{"component_removed_from_referenced_name", spec, edit(t, spec, "    NotFound:\n      description: Not found.\n", ""), both, false, false},
		{"component_added_to_referenced_name", edit(t, spec, "    NotFound:\n      description: Not found.\n", ""), spec, both, false, false},
		{"property_named_description_change", spec, edit(t, spec, "                description:\n                  type: string", "                description:\n                  type: integer"), []string{"/v1/things"}, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			paths, docOnly, err := ChangedPaths(parse(t, c.old), parse(t, c.new))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(paths, c.paths) || docOnly != c.docOnly {
				t.Errorf("got %v docOnly=%v, want %v docOnly=%v", paths, docOnly, c.paths, c.docOnly)
			}
		})
	}
	for _, c := range []struct{ name, ref string }{
		{"external_ref_is_error", "other.yaml#/components/schemas/Thing"},
		{"absolute_url_ref_is_error", "https://example.com/s.yaml"},
		{"unknown_section_ref_is_error", "#/components/widgets/Thing"},
		{"non_component_ref_is_error", "#/paths/~1v1~1things"},
		{"malformed_ref_is_error", "#/components/schemas/Thing/properties/id"},
		{"empty_name_ref_is_error", "#/components/schemas/"},
	} {
		t.Run(c.name, func(t *testing.T) {
			bad := edit(t, spec, "      tags: [things]\n      externalDocs:", "      tags: [things]\n      x-bad:\n        $ref: '"+c.ref+"'\n      externalDocs:")
			if _, _, err := ChangedPaths(parse(t, spec), parse(t, bad)); err == nil {
				t.Error("ref accepted")
			}
			var out, errb bytes.Buffer
			dir := t.TempDir()
			o, n := filepath.Join(dir, "o.yaml"), filepath.Join(dir, "n.yaml")
			if err := os.WriteFile(o, []byte(spec), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(n, []byte(bad), 0o600); err != nil {
				t.Fatal(err)
			}
			if code := run([]string{"changed-paths", o, n}, &out, &errb); code != 2 {
				t.Errorf("exit %d, want 2", code)
			}
		})
	}
	t.Run("unparsable_is_error", func(t *testing.T) {
		if _, _, err := ChangedPaths(parse(t, "- a\n- b\n"), parse(t, spec)); err == nil {
			t.Error("a sequence document was accepted")
		}
	})
	t.Run("missing_file_is_empty", func(t *testing.T) {
		code, out, _ := runChanged(t, "", spec, true)
		if code != 10 || out != "/v1/things\n/v1/things/{id}\n" {
			t.Errorf("code %d, stdout %q", code, out)
		}
	})
	t.Run("empty_file_is_empty", func(t *testing.T) {
		code, out, _ := runChanged(t, "", spec, false)
		if code != 10 || out != "/v1/things\n/v1/things/{id}\n" {
			t.Errorf("code %d, stdout %q", code, out)
		}
	})
	t.Run("removed_when_new_empty", func(t *testing.T) {
		paths, _, err := ChangedPaths(parse(t, spec), parse(t, ""))
		if err != nil || len(paths) != 2 {
			t.Errorf("got %v, %v", paths, err)
		}
	})
}

// runChanged writes old and new into a temp dir (old absent when missing) and
// runs the dispatcher on them.
func runChanged(t *testing.T, old, new string, missing bool) (int, string, string) {
	t.Helper()
	dir := t.TempDir()
	o, n := filepath.Join(dir, "old.yaml"), filepath.Join(dir, "new.yaml")
	if !missing {
		if err := os.WriteFile(o, []byte(old), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(n, []byte(new), 0o600); err != nil {
		t.Fatal(err)
	}
	var out, errb bytes.Buffer
	code := run([]string{"changed-paths", o, n}, &out, &errb)
	return code, out.String(), errb.String()
}

func TestMainChangedPaths(t *testing.T) {
	spec := readSpec(t)
	cases := []struct {
		name     string
		old, new string
		code     int
		stdout   string
		stderr   string // substring
	}{
		{"equal", spec, spec, 0, "", ""},
		{"documentation_only", spec, edit(t, spec, "description: Lists the things.", "description: x"), 0, "", ""},
		{"differ_but_no_path", withOrphan(t, spec, "string"), withOrphan(t, spec, "integer"), 0, "", "catscheck: no path is affected\n"},
		{"path_affected", spec, edit(t, spec, "required: [name]", "required: [name, x]"), 10, "/v1/things\n", ""},
		{"not_a_mapping", spec, "- a\n", 2, "", "catscheck: "},
		{"parse_error", spec, "a: [\n", 2, "", "catscheck: "},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			code, out, errs := runChanged(t, c.old, c.new, false)
			if code != c.code || out != c.stdout {
				t.Errorf("code %d stdout %q, want %d %q (stderr %q)", code, out, c.code, c.stdout, errs)
			}
			if c.code == 2 && !strings.HasPrefix(errs, "catscheck: ") {
				t.Errorf("stderr %q lacks the file prefix", errs)
			}
			if c.code != 2 && errs != c.stderr {
				t.Errorf("stderr %q, want %q", errs, c.stderr)
			}
		})
	}
}

func TestMainDispatch(t *testing.T) {
	dir := t.TempDir()
	bad := filepath.Join(dir, "bad.yaml")
	if err := os.WriteFile(bad, []byte("a: [\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	good := filepath.Join("testdata", "spec-min.yaml")
	cases := []struct {
		name string
		args []string
		code int
	}{
		{"no_args", nil, 2},
		{"unknown_command", []string{"frob"}, 2},
		{"normalize_ok", []string{"normalize", good}, 0},
		{"normalize_parse_error", []string{"normalize", bad}, 2},
		{"normalize_missing_file", []string{"normalize", filepath.Join(dir, "none.yaml")}, 2},
		{"normalize_arity", []string{"normalize"}, 2},
		{"changed_paths_arity", []string{"changed-paths", good}, 2},
		{"flag_as_file", []string{"changed-paths", "--foo", good}, 2},
		{"classify_stub", []string{"classify", "--rules", good, dir}, 2},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var out, errb bytes.Buffer
			if code := run(c.args, &out, &errb); code != c.code {
				t.Errorf("code %d, want %d (stderr %q)", code, c.code, errb.String())
			}
			if c.code == 0 && !strings.Contains(out.String(), "paths:") {
				t.Error("normalize printed no document")
			}
		})
	}
}
