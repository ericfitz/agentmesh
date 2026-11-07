package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

const busImportPath = "github.com/ericfitz/agentmesh/internal/bus"

// dynamicCodeExceptions are the functions allowed to build a bus.Error whose
// Code is a conversion of a runtime value (not a constant), keyed by file
// (relative to the module root) and function name. Each needs a reason, and an
// entry that no longer matches anything fails the test.
var dynamicCodeExceptions = []struct{ file, fn, reason string }{
	{"internal/bus/remote/remote.go", "errorOf", "decodes the wire problem's code; Task 2 sets RetryAfter from the Retry-After header there"},
}

// TestRateLimitedSites refuses any construction of a rate_limited error
// outside RateLimited in internal/core/errors.go: the one constructor carries
// the limiter's wait (the server's Retry-After). Reads of the constant are
// not constructions. The walk covers internal/ and cmd/, resolves each file's
// local name for the bus package (aliases such as ab2bus), and flags:
//   - E, core.E, <bus>.Errorf or Errorf whose first argument is the code;
//   - a composite literal of bus.Error with Code set to the code;
//   - an assignment of the code to a .Code field;
//   - any "rate_limited" string literal outside internal/bus/errors.go and
//     internal/gen (covers bus.Code("rate_limited") and variables);
//   - a bus.Error literal whose Code is a runtime conversion <bus>.Code(x),
//     except the listed exceptions.
func TestRateLimitedSites(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	root := filepath.Join(filepath.Dir(thisFile), "..", "..")
	allowedCtor := filepath.Join(root, "internal", "core", "errors.go")
	constFile := filepath.Join(root, "internal", "bus", "errors.go")
	genDir := filepath.Join(root, "internal", "gen")
	usedExc := make([]bool, len(dynamicCodeExceptions))
	fset := token.NewFileSet()
	for _, top := range []string{"internal", "cmd"} {
		err := filepath.WalkDir(filepath.Join(root, top), func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path == genDir {
					return filepath.SkipDir
				}
				return nil
			}
			if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
				return nil
			}
			f, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				return err
			}
			rel, _ := filepath.Rel(root, path)
			rel = filepath.ToSlash(rel)
			inBus := f.Name.Name == "bus" && strings.HasSuffix(filepath.ToSlash(filepath.Dir(path)), "internal/bus")
			busNames := map[string]bool{}
			for _, im := range f.Imports {
				if p, _ := strconv.Unquote(im.Path.Value); p == busImportPath {
					name := "bus"
					if im.Name != nil {
						name = im.Name.Name
					}
					busNames[name] = true
				}
			}
			sel := func(e ast.Expr, member string) bool {
				x, ok := e.(*ast.SelectorExpr)
				if !ok || x.Sel.Name != member {
					return false
				}
				id, ok := x.X.(*ast.Ident)
				return ok && busNames[id.Name]
			}
			isCode := func(e ast.Expr) bool {
				switch x := e.(type) {
				case *ast.SelectorExpr:
					return sel(x, "CodeRateLimited")
				case *ast.Ident:
					return inBus && x.Name == "CodeRateLimited"
				case *ast.BasicLit:
					return x.Kind == token.STRING && x.Value == `"rate_limited"`
				}
				return false
			}
			typeIs := func(e ast.Expr, name string) bool {
				if id, ok := e.(*ast.Ident); ok {
					return inBus && id.Name == name
				}
				return sel(e, name)
			}
			report := func(pos token.Pos, what string) {
				t.Errorf("%s: %s; use core.RateLimited(wait, ...)", fset.Position(pos), what)
			}
			for _, decl := range f.Decls {
				fnName := ""
				if fd, ok := decl.(*ast.FuncDecl); ok {
					fnName = fd.Name.Name
					if fnName == "RateLimited" && path == allowedCtor {
						continue
					}
				}
				ast.Inspect(decl, func(n ast.Node) bool {
					switch x := n.(type) {
					case *ast.CallExpr:
						name := ""
						switch fn := x.Fun.(type) {
						case *ast.Ident:
							name = fn.Name
						case *ast.SelectorExpr:
							if id, ok := fn.X.(*ast.Ident); ok {
								name = id.Name + "." + fn.Sel.Name
								if fn.Sel.Name == "Errorf" && busNames[id.Name] {
									name = "Errorf"
								}
							}
						}
						switch name {
						case "E", "core.E", "Errorf":
							if len(x.Args) > 0 && isCode(x.Args[0]) {
								report(x.Pos(), "rate_limited constructed outside core.RateLimited")
							}
						}
					case *ast.CompositeLit:
						if !typeIs(x.Type, "Error") {
							break
						}
						for _, el := range x.Elts {
							kv, ok := el.(*ast.KeyValueExpr)
							if !ok {
								continue
							}
							if k, ok := kv.Key.(*ast.Ident); !ok || k.Name != "Code" {
								continue
							}
							if isCode(kv.Value) {
								report(x.Pos(), "bus.Error literal with the rate_limited code")
							} else if c, ok := kv.Value.(*ast.CallExpr); ok && typeIs(c.Fun, "Code") {
								excused := false
								for i, e := range dynamicCodeExceptions {
									if e.file == rel && e.fn == fnName {
										usedExc[i], excused = true, true
									}
								}
								if !excused {
									report(x.Pos(), "bus.Error literal with a runtime-converted code could be rate_limited")
								}
							}
						}
					case *ast.AssignStmt:
						for i, l := range x.Lhs {
							if s, ok := l.(*ast.SelectorExpr); ok && s.Sel.Name == "Code" && i < len(x.Rhs) && isCode(x.Rhs[i]) {
								report(x.Pos(), "rate_limited assigned to a Code field")
							}
						}
					case *ast.BasicLit:
						if x.Kind == token.STRING && x.Value == `"rate_limited"` && path != constFile {
							report(x.Pos(), `"rate_limited" literal`)
						}
					}
					return true
				})
			}
			return nil
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	for i, e := range dynamicCodeExceptions {
		if !usedExc[i] {
			t.Errorf("stale exception %s %s (%s): no matching construction", e.file, e.fn, e.reason)
		}
	}
}
