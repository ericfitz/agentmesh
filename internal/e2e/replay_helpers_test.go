//go:build !windows

package e2e_test

// TestReplayHelpers (issue #35) tests the replay's own logic in
// zz_examples_test.go over fabricated JSON: no fixture, no server, no Docker.
// Without it the helpers would be exercised only by the live rows.

import (
	"fmt"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// recorder is a testing.TB that records failures instead of failing: Errorf
// notes a message, Fatalf notes one and stops the helper.
type recorder struct {
	testing.TB
	msgs  []string
	fatal bool
}

type recorderStop struct{}

func (r *recorder) Helper() {}

func (r *recorder) Errorf(format string, args ...any) {
	r.msgs = append(r.msgs, sprintf(format, args...))
}

func (r *recorder) Fatalf(format string, args ...any) {
	r.msgs = append(r.msgs, sprintf(format, args...))
	r.fatal = true
	panic(recorderStop{})
}

// record runs f against a fresh recorder and returns it.
func record(f func(r *recorder)) *recorder {
	r := &recorder{}
	func() {
		defer func() {
			if v := recover(); v != nil {
				if _, ok := v.(recorderStop); !ok {
					panic(v)
				}
			}
		}()
		f(r)
	}()
	return r
}

func sprintf(format string, args ...any) string {
	return strings.TrimSpace(fmt.Sprintf(format, args...))
}

func TestReplayHelpers(t *testing.T) {
	obj := func(kv ...any) map[string]any {
		m := map[string]any{}
		for i := 0; i < len(kv); i += 2 {
			m[kv[i].(string)] = kv[i+1]
		}
		return m
	}
	arr := func(v ...any) []any { return append([]any{}, v...) }

	t.Run("shapeCheck", func(t *testing.T) {
		cases := []struct {
			name           string
			live, example  any
			emptyOK        []string
			wantErr        string // substring of the one expected message; "" for none
			wantFired      []string
			wantNoFiredAny bool
		}{
			{name: "same shape", live: obj("a", "x", "n", 1.0), example: obj("a", "y", "n", 2.0)},
			{name: "kind mismatch", live: obj("a", 1.0), example: obj("a", "y"), wantErr: "member a is number in the live body and string in the example"},
			{name: "missing member", live: obj("a", "x", "b", "z"), example: obj("a", "y"), wantErr: "member b of the live body is not in the example"},
			{name: "nested missing member", live: obj("o", obj("k", "v")), example: obj("o", obj()), wantErr: "member o.k of the live body is not in the example"},
			{name: "extra example member is fine", live: obj("a", "x"), example: obj("a", "y", "b", "z")},
			{name: "first element of an array is checked", live: arr(obj("a", "x"), obj("zzz", 1.0)), example: arr(obj("a", "y")), wantErr: ""},
			{name: "first element mismatch", live: arr(obj("a", 1.0)), example: arr(obj("a", "y")), wantErr: "member [0].a is number in the live body and string in the example"},
			{name: "empty live, non-empty example, no emptyOK", live: obj("l", arr()), example: obj("l", arr("x")), wantErr: "empty array in the live body and the example's is not (/l is not in the row's emptyOK)"},
			{name: "empty live, non-empty example, emptyOK fires", live: obj("l", arr()), example: obj("l", arr("x")), emptyOK: []string{"/l"}, wantFired: []string{"/l"}},
			{name: "empty live, empty example", live: obj("l", arr()), example: obj("l", arr())},
			{name: "non-empty live, empty example", live: obj("l", arr("x")), example: obj("l", arr()), wantErr: "non-empty array in the live body and an empty one in the example"},
			{name: "stale emptyOK does not fire", live: obj("l", arr("x")), example: obj("l", arr("x")), emptyOK: []string{"/l"}, wantNoFiredAny: true},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				ok := map[string]bool{}
				for _, p := range tc.emptyOK {
					ok[p] = true
				}
				fired := map[string]bool{}
				r := record(func(r *recorder) { shapeCheck(r, tc.live, tc.example, "", "", ok, fired) })
				switch {
				case tc.wantErr == "" && len(r.msgs) > 0:
					t.Fatalf("unexpected failure: %v", r.msgs)
				case tc.wantErr != "" && (len(r.msgs) != 1 || !strings.Contains(r.msgs[0], tc.wantErr)):
					t.Fatalf("failures %q, want one containing %q", r.msgs, tc.wantErr)
				}
				for _, p := range tc.wantFired {
					if !fired[p] {
						t.Errorf("emptyOK %s did not fire", p)
					}
				}
				if tc.wantNoFiredAny && len(fired) != 0 {
					t.Errorf("fired %v, want none (the caller fails the stale entry)", fired)
				}
			})
		}
	})

	t.Run("setPointer", func(t *testing.T) {
		doc := obj("a", obj("b", arr("x", "y")))
		if got, ok := setPointer(doc, []string{"a", "b", "1"}, "Z"); !ok || got.(map[string]any)["a"].(map[string]any)["b"].([]any)[1] != "Z" {
			t.Fatalf("array element not replaced: %v %v", got, ok)
		}
		if got, ok := setPointer("old", nil, "new"); !ok || got != "new" {
			t.Fatalf("empty pointer: %v %v", got, ok)
		}
		for _, segs := range [][]string{{"a", "nope"}, {"nope"}, {"a", "b", "2"}, {"a", "b", "-1"}, {"a", "b", "x"}, {"a", "b", "0", "deeper"}} {
			if _, ok := setPointer(doc, segs, "Z"); ok {
				t.Errorf("pointer %v reported a hit", segs)
			}
		}
	})

	t.Run("effectiveExample", func(t *testing.T) {
		named := func(v any) *openapi3.ExampleRef { return &openapi3.ExampleRef{Value: &openapi3.Example{Value: v}} }
		mt := &openapi3.MediaType{
			Example:  obj("from", "singular"),
			Examples: openapi3.Examples{"alpha": named(obj("from", "alpha")), "default": named(obj("from", "default"))},
		}
		if got := effectiveExample(mt, "alpha"); got.(map[string]any)["from"] != "alpha" {
			t.Errorf("named example not chosen: %v", got)
		}
		if got := effectiveExample(mt, "nope"); got.(map[string]any)["from"] != "singular" {
			t.Errorf("an unknown name must fall to the singular example: %v", got)
		}
		many := &openapi3.MediaType{Examples: openapi3.Examples{"b": named(obj("from", "b")), "a": named(obj("from", "a"))}}
		if got := effectiveExample(many, ""); got.(map[string]any)["from"] != "a" {
			t.Errorf("first by name expected: %v", got)
		}
		many.Examples["default"] = named(obj("from", "default"))
		if got := effectiveExample(many, ""); got.(map[string]any)["from"] != "default" {
			t.Errorf("default expected: %v", got)
		}
		if got := effectiveExample(&openapi3.MediaType{}, ""); got != nil {
			t.Errorf("no example must be nil: %v", got)
		}
	})

	t.Run("scalarString", func(t *testing.T) {
		for _, tc := range []struct {
			in   any
			want string
		}{{"s", "s"}, {true, "true"}, {12.0, "12"}, {1.5, "1.5"}, {int64(7), "7"}, {3, "3"}} {
			if got := scalarString(t, tc.in); got != tc.want {
				t.Errorf("scalarString(%v) = %q, want %q", tc.in, got, tc.want)
			}
		}
		r := record(func(r *recorder) { scalarString(r, arr("x")) })
		if !r.fatal {
			t.Errorf("a non-scalar must be fatal: %v", r.msgs)
		}
	})

	t.Run("encodeQuery", func(t *testing.T) {
		query := map[string]any{"ch": arr("a", "b"), "tag": arr("x", "y"), "n": 5.0}
		q := encodeQuery(t, []string{"ch", "tag", "n"}, query, map[string]bool{"tag": true})
		if got := q["ch"]; len(got) != 2 || got[0] != "a" || got[1] != "b" {
			t.Errorf("exploded array: %v", got)
		}
		if got := q["tag"]; len(got) != 1 || got[0] != "x,y" {
			t.Errorf("explode=false comma join: %v", got)
		}
		if q.Get("n") != "5" {
			t.Errorf("scalar: %q", q.Get("n"))
		}
	})

	t.Run("encodeForm", func(t *testing.T) {
		f := encodeForm(t, "op", obj("grant_type", "g", "n", 2.0, "ok", true))
		if f.Get("grant_type") != "g" || f.Get("n") != "2" || f.Get("ok") != "true" {
			t.Errorf("form: %v", f)
		}
		r := record(func(r *recorder) { encodeForm(r, "op", arr("x")) })
		if !r.fatal || !strings.Contains(r.msgs[0], "form body of op is not an object") {
			t.Errorf("a non-object body must be fatal: %v", r.msgs)
		}
		r = record(func(r *recorder) { encodeForm(r, "op", obj("k", arr("x"))) })
		if !r.fatal {
			t.Errorf("a non-scalar member must be fatal: %v", r.msgs)
		}
	})
}
