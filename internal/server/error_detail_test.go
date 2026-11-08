package server

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"

	"github.com/ericfitz/agentmesh/internal/gen"
)

// secretValue stands for a submitted token: no refusal may echo it.
const secretValue = "SECRETVALUE-eyJhbGciOi"

// TestValidationDetailNeverEchoes: the validation detail names the JSON
// pointer and the reason, never the schema or the submitted value (issue #30,
// CATS finding RB2).
func TestValidationDetailNeverEchoes(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.identity("pat", false)
	cases := []struct {
		name, method, path, body string
	}{
		{"body null member", "POST", "/v1/channels", `{"name":"zz-null-probe","scope":null}`},
		{"body wrong type", "POST", "/v1/channels", `{"name":1,"scope":"` + secretValue + `"}`},
		{"body enum outside", "POST", "/v1/channels", `{"name":"a","kind":"` + secretValue + `"}`},
		{"body unknown member", "POST", "/v1/channels", `{"name":"a","` + secretValue + `":1}`},
		{"query parameter", "GET", "/v1/sessions/s/watch?timeout=" + secretValue, ""},
		{"path parameter", "GET", "/v1/memories/" + secretValue, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			var req *http.Request
			if c.body != "" {
				req = newReq(t, c.method, c.path, strings.NewReader(c.body))
			} else {
				req = newReq(t, c.method, c.path, nil)
			}
			resp := e.raw("pat", req)
			p := readProblem(t, resp)
			if resp.StatusCode != 400 || p.Detail == nil {
				t.Fatalf("got %d %+v, want a 400 with a detail", resp.StatusCode, p)
			}
			for _, bad := range []string{"Schema:", "Value:", "SECRETVALUE"} {
				if strings.Contains(*p.Detail, bad) {
					t.Errorf("detail contains %q: %s", bad, *p.Detail)
				}
			}
			if len(*p.Detail) > 300 {
				t.Errorf("detail is %d bytes: %.200s", len(*p.Detail), *p.Detail)
			}
		})
	}
}

// TestUnauthenticatedDetailIsFixed: a protected operation without a bearer
// answers a fixed detail, not the validator's text (issue #30, CATS finding
// RB3); an authenticator's own refusal keeps its text.
func TestUnauthenticatedDetailIsFixed(t *testing.T) {
	e := newEnv(t, envOptions{})
	resp := e.raw("", newReq(t, "GET", "/v1/channels", nil))
	p := readProblem(t, resp)
	if resp.StatusCode != 401 || p.Detail == nil || *p.Detail != "a bearer token is required" {
		t.Fatalf("got %d detail %q, want 401 with the fixed detail", resp.StatusCode, detailText(p))
	}
	e2 := newEnv(t, envOptions{auth: authFunc(func(*http.Request) (string, error) { return "", errors.New("invalid bearer token: expired") })})
	resp = e2.raw("", newReq(t, "GET", "/v1/channels", nil))
	p = readProblem(t, resp)
	if resp.StatusCode != 401 || p.Detail == nil || *p.Detail != "invalid bearer token: expired" {
		t.Fatalf("got %d detail %q, want the authenticator's text", resp.StatusCode, detailText(p))
	}
}

func detailText(p gen.Problem) string {
	if p.Detail == nil {
		return ""
	}
	return *p.Detail
}

// TestTrailingJSONRefused: a JSON request body is exactly one JSON value
// (issue #30, CATS finding RB1). The token endpoint keeps its RFC 6749 body.
func TestTrailingJSONRefused(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.identity("root", true)
	cases := []struct{ name, path, body string }{
		{"junk after the value", "/v1/channels", `{"name":"zz-trailing-probe-1"}bla`},
		{"second value", "/v1/admin/scopes", `{"name":"a"} {"name":"b"}`},
		{"array after the value", "/v1/channels", `{"name":"zz-trailing-probe-2"} []`},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			resp := e.rawAllowUnrouted("root", newReq(t, "POST", c.path, strings.NewReader(c.body)))
			p := readProblem(t, resp)
			if resp.StatusCode != 400 || p.Code != gen.ProblemCode("validation") {
				t.Fatalf("got %d %s, want 400 validation", resp.StatusCode, p.Code)
			}
			if d := detailText(p); strings.Contains(d, "zz-trailing") || !strings.Contains(d, "one JSON value") {
				t.Errorf("detail %q", d)
			}
		})
	}
	// Trailing whitespace is not data.
	resp := e.raw("root", newReq(t, "POST", "/v1/channels", strings.NewReader("{\"name\":\"zz-ws\"} \n\t")))
	if resp.StatusCode != 201 {
		t.Errorf("trailing whitespace: %d", resp.StatusCode)
	}
	// The token endpoint answers its OAuth body for the same shape.
	treq := newReq(t, "POST", "/v1/auth/token", strings.NewReader(`{"a":1}bla`))
	resp = e.rawAllowUnrouted("", treq)
	var oe gen.OAuthError
	if err := json.NewDecoder(resp.Body).Decode(&oe); err != nil || resp.StatusCode != 400 || oe.Error != "invalid_request" {
		t.Errorf("token endpoint: %d %+v %v", resp.StatusCode, oe, err)
	}
}

// TestPatternDetailIsPlain: a pattern refusal names the rule in one line and
// never the submitted string (the validator quotes it: 'bad tag' does not
// match pattern).
func TestPatternDetailIsPlain(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.identity("pat", false)
	resp := e.raw("pat", newReq(t, "GET", "/v1/channels/dev/messages?tags="+secretValue+"%20x", nil))
	p := readProblem(t, resp)
	d := detailText(p)
	if resp.StatusCode != 400 && resp.StatusCode != 404 {
		t.Fatalf("got %d %q", resp.StatusCode, d)
	}
	if strings.Contains(d, "SECRETVALUE") || strings.Contains(d, "jsonschema validation failed") || strings.Contains(d, "\n") {
		t.Errorf("detail %q", d)
	}
}

// TestDetailDropsEscapedLiteralsAndNames: no refusal quotes a submitted value
// however the validator escapes it, and none names a member or map key the
// caller chose (issue #30, RB2, review finding 1 and 3).
func TestDetailDropsEscapedLiteralsAndNames(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.identity("pat", false)
	jwt := "eyJhbGciOiJFZERTQSJ9.eyJzdWIiOiJwYXQifQ.c2lnbmF0dXJlLWJ5dGVz"
	values := []string{"'", "it's SECRETVALUE", `a\b SECRETVALUE`, "line\nSECRETVALUE", "tab\tSECRETVALUE", "nul\x00SECRETVALUE", "", "!", jwt}
	forms := []struct {
		name  string
		build func(v string) *http.Request
	}{
		{"body tags", func(v string) *http.Request {
			b, _ := json.Marshal(map[string]any{"content": "x", "tags": []string{v}})
			return newReq(t, "POST", "/v1/channels/dev/messages", strings.NewReader(string(b)))
		}},
		{"query tags", func(v string) *http.Request {
			return newReq(t, "GET", "/v1/channels/dev/messages?tags="+url.QueryEscape(v), nil)
		}},
		{"query pattern", func(v string) *http.Request {
			return newReq(t, "DELETE", "/v1/tag-subscriptions?pattern="+url.QueryEscape(v), nil)
		}},
	}
	check := func(t *testing.T, resp *http.Response, parts ...string) {
		t.Helper()
		p := readProblem(t, resp)
		d := detailText(p)
		if resp.StatusCode != 400 {
			t.Fatalf("got %d %q", resp.StatusCode, d)
		}
		if strings.Contains(d, "jsonschema") || strings.Contains(d, "\n") || strings.Contains(d, "' does not match") {
			t.Errorf("detail carries the validator's wrapper or a quoted literal: %q", d)
		}
		for _, part := range parts {
			if len(part) >= 3 && strings.Contains(d, part) {
				t.Errorf("detail %q contains %q", d, part)
			}
		}
	}
	for _, f := range forms {
		for _, v := range values {
			t.Run(fmt.Sprintf("%s %q", f.name, v), func(t *testing.T) {
				parts := []string{v, strings.Trim(strconv.Quote(v), `"`), "SECRETVALUE"}
				if v == jwt {
					parts = append(parts, strings.Split(jwt, ".")...)
				}
				if v == "" || v == "!" || v == "'" {
					parts = nil
				}
				check(t, e.rawAllowUnrouted("pat", f.build(v)), parts...)
			})
		}
	}
	names := []struct{ name, path, body string }{
		{"unknown member with a missing one", "/v1/channels", `{"SECRETVALUE":1}`},
		{"unknown member with an apostrophe", "/v1/channels", `{"it's SECRETVALUE":1}`},
		{"map key", "/v1/channels/dev/messages", `{"content":"x","metadata":{"SECRETKEY":1}}`},
		{"map key with an apostrophe", "/v1/channels/dev/messages", `{"content":"x","metadata":{"it's SECRETKEY":1}}`},
		{"map key with a backslash", "/v1/channels/dev/messages", `{"content":"x","metadata":{"a\\SECRETKEY":1}}`},
	}
	for _, c := range names {
		t.Run(c.name, func(t *testing.T) {
			check(t, e.rawAllowUnrouted("pat", newReq(t, "POST", c.path, strings.NewReader(c.body))), "SECRET")
		})
	}
}
