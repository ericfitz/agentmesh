package core

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRateLimitedSites refuses any construction of a rate_limited error
// outside RateLimited in internal/core/errors.go: the one constructor carries
// the limiter's wait (the server's Retry-After). Reads of the constant are
// not constructions.
func TestRateLimitedSites(t *testing.T) {
	_, thisFile, _, _ := runtime.Caller(0)
	internal := filepath.Join(filepath.Dir(thisFile), "..")
	allowed := filepath.Join(internal, "core", "errors.go")
	isCode := func(e ast.Expr, inBus bool) bool {
		switch x := e.(type) {
		case *ast.SelectorExpr:
			id, ok := x.X.(*ast.Ident)
			return ok && id.Name == "bus" && x.Sel.Name == "CodeRateLimited"
		case *ast.Ident:
			return inBus && x.Name == "CodeRateLimited"
		}
		return false
	}
	callee := func(e ast.Expr) string {
		switch f := e.(type) {
		case *ast.Ident:
			return f.Name
		case *ast.SelectorExpr:
			if id, ok := f.X.(*ast.Ident); ok {
				return id.Name + "." + f.Sel.Name
			}
		}
		return ""
	}
	fset := token.NewFileSet()
	err := filepath.WalkDir(internal, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			return err
		}
		inBus := f.Name.Name == "bus"
		report := func(pos token.Pos) {
			t.Errorf("%s: rate_limited constructed outside core.RateLimited; use core.RateLimited(wait, ...)", fset.Position(pos))
		}
		for _, decl := range f.Decls {
			if fd, ok := decl.(*ast.FuncDecl); ok && fd.Name.Name == "RateLimited" && path == allowed {
				continue
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CallExpr:
					switch callee(x.Fun) {
					case "E", "core.E", "bus.Errorf", "Errorf":
						if len(x.Args) > 0 && isCode(x.Args[0], inBus) {
							report(x.Pos())
						}
					}
				case *ast.CompositeLit:
					switch callee(x.Type) {
					case "bus.Error", "Error":
						for _, el := range x.Elts {
							if kv, ok := el.(*ast.KeyValueExpr); ok {
								if k, ok := kv.Key.(*ast.Ident); ok && k.Name == "Code" && isCode(kv.Value, inBus) {
									report(x.Pos())
								}
							}
						}
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
