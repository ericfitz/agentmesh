package server

import (
	"errors"
	"net/http"
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
