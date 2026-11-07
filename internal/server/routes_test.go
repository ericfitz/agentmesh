package server

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/getkin/kin-openapi/openapi3"
)

// routeSiteNames are the selector names that register or build a route. Any
// reference counts, not only a call (ServeMux covers http.ServeMux{}, new(http.ServeMux) and a zero-value var): `f := m.HandleFunc; f(...)` and a method
// value passed along are selectors too.
var routeSiteNames = map[string]bool{
	"Handle": true, "HandleFunc": true, "NewServeMux": true,
	"HandlerFromMux": true, "ServeMux": true, "HandlerFromMuxWithBaseURL": true, "HandlerWithOptions": true,
}

// TestNoRoutesOutsideTheDocument pins that the server has no route the
// document does not generate: across the non-test files of internal/server,
// internal/server/cmd and internal/client/localmode, the only selector
// references to the names above are one http.NewServeMux and one
// gen.HandlerWithOptions in internal/server/server.go; an http.ServeMux
// composite literal, new(http.ServeMux) and a dot-import are refused outright.
// Limit: a handler that wraps server.New's result is outside the scan; handler
// presence is the compile-time StrictServerInterface and generate-check.
func TestNoRoutesOutsideTheDocument(t *testing.T) {
	allow := map[string]int{"internal/server/server.go:NewServeMux": 1, "internal/server/server.go:HandlerWithOptions": 1}
	got := map[string]int{}
	var positions []string
	fset := token.NewFileSet()
	for _, dir := range []string{".", "cmd", "../client/localmode"} {
		files, err := filepath.Glob(filepath.Join(dir, "*.go"))
		if err != nil {
			t.Fatal(err)
		}
		if len(files) == 0 {
			t.Fatalf("no Go files in %s", dir)
		}
		for _, f := range files {
			if strings.HasSuffix(f, "_test.go") {
				continue
			}
			src, err := os.ReadFile(f)
			if err != nil {
				t.Fatal(err)
			}
			file, err := parser.ParseFile(fset, f, src, parser.SkipObjectResolution)
			if err != nil {
				t.Fatal(err)
			}
			for _, imp := range file.Imports {
				if imp.Name != nil && imp.Name.Name == "." {
					t.Errorf("%s: dot-import of %s hides route registration from the scan", fset.Position(imp.Pos()), imp.Path.Value)
				}
			}
			rel := filepath.ToSlash(filepath.Join("internal/server", f))
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || !routeSiteNames[sel.Sel.Name] {
					return true
				}
				key := rel + ":" + sel.Sel.Name
				got[key]++
				positions = append(positions, fmt.Sprintf("%s: %s", fset.Position(sel.Pos()), key))
				return true
			})
		}
	}
	sort.Strings(positions)
	for key, n := range got {
		if allow[key] != n {
			t.Errorf("route site %s: %d, allowed %d\n%s", key, n, allow[key], strings.Join(positions, "\n"))
		}
	}
	for key, n := range allow {
		if _, seen := got[key]; !seen {
			t.Errorf("route site %s: 0, want %d (allowlist is stale)", key, n)
		}
	}
}

var routeSamples = strings.NewReplacer(
	"{channel}", "c1", "{scope}", "s1", "{identity}", "pat", "{session}", "sess1", "{id}", "1")

var routeMethods = []string{"GET", "POST", "PUT", "PATCH", "DELETE"}

// routeProbe builds the same request shape for every probe: no query, and a
// body only where the operation declares one.
func routeProbe(t *testing.T, method, path string, op *openapi3.Operation) *http.Request {
	t.Helper()
	url := "http://inproc" + routeSamples.Replace(path)
	if strings.ContainsAny(url, "{}") {
		t.Fatalf("path %s has an unsampled parameter", path)
	}
	var body *strings.Reader
	ctype := ""
	switch {
	case op != nil && op.OperationID == "token":
		body, ctype = strings.NewReader("grant_type=client_credentials"), "application/x-www-form-urlencoded"
	case op != nil && op.RequestBody != nil:
		body, ctype = strings.NewReader("{}"), "application/json"
	}
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequest(method, url, body)
		if err == nil {
			req.Header.Set("Content-Type", ctype)
		}
	} else {
		req, err = http.NewRequest(method, url, nil)
	}
	if err != nil {
		t.Fatal(err)
	}
	return req
}

// TestDeclaredMethodsRouted sends every documented (method, path) through
// server.New and asserts the answer is not the router's refusal. A 400 from
// the validator proves the router matched, not that the handler ran; the
// handler's presence is the compile-time StrictServerInterface. The token
// probe is weak (tokenRequestError answers 400 for any malformed form either
// way); the token route is pinned by auth_test.go (TestTokenEndpointPreHandlerRefusals
// and the exchange tests).
func TestDeclaredMethodsRouted(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.identity("root", true)
	n := 0
	for path, item := range Spec().Paths.Map() {
		for method, op := range item.Operations() {
			n++
			t.Run(lowerFirst(op.OperationID), func(t *testing.T) {
				resp := e.rawAllowUnrouted("root", routeProbe(t, method, path, op))
				if resp.StatusCode == http.StatusMethodNotAllowed {
					t.Fatalf("%s %s: 405", method, path)
				}
				if op.OperationID == "token" {
					return // the OAuth error object: any 4xx is routed
				}
				if resp.StatusCode == http.StatusNotFound {
					p := readProblem(t, resp)
					d := ""
					if p.Detail != nil {
						d = *p.Detail
					}
					if strings.Contains(d, "no matching operation was found") || strings.Contains(d, "method not allowed") {
						t.Fatalf("%s %s: router refusal: %s", method, path, d)
					}
				}
			})
		}
	}
	t.Run("count", func(t *testing.T) {
		if n != 57 {
			t.Fatalf("%d operations probed, want 57", n)
		}
	})
}

// TestUndeclaredMethodsRefused sends every method the document does not
// declare on a documented path and asserts the router's refusal.
func TestUndeclaredMethodsRefused(t *testing.T) {
	e := newEnv(t, envOptions{})
	e.identity("root", true)
	n := 0
	for path, item := range Spec().Paths.Map() {
		for _, method := range routeMethods {
			if item.GetOperation(method) != nil {
				continue
			}
			n++
			t.Run(method+" "+path, func(t *testing.T) {
				resp := e.rawAllowUnrouted("root", routeProbe(t, method, path, nil))
				if path == tokenPath {
					// The token endpoint answers in RFC 6749's shape from tokenRouteGuard
					// (server.go), before the router. The document leaves these methods
					// undeclared: OpenAPI cannot declare a response for a method that has
					// no operation (ADR 0002, Decision 84 audit).
					body, _ := io.ReadAll(resp.Body)
					want := `{"error":"invalid_request","error_description":"the token endpoint accepts POST only"}` + "\n"
					if resp.StatusCode != http.StatusMethodNotAllowed || string(body) != want {
						t.Fatalf("token path: got %d %q, want 405 %q", resp.StatusCode, body, want)
					}
					return
				}
				p := readProblem(t, resp)
				if resp.StatusCode != http.StatusNotFound || string(p.Code) != "not_found" {
					t.Fatalf("got %d %s, want 404 not_found", resp.StatusCode, p.Code)
				}
				if p.Detail == nil || *p.Detail != "method not allowed" {
					t.Fatalf("detail %v, want exactly %q", p.Detail, "method not allowed")
				}
			})
		}
	}
	t.Run("count", func(t *testing.T) {
		if want := len(Spec().Paths.Map())*len(routeMethods) - 57; n != want {
			t.Fatalf("%d undeclared probes, want %d", n, want)
		}
	})
}
