package reliability

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestOrdinaryRuntimeHasNoDirectOutboundNetworkAPI(t *testing.T) {
	root := repositoryRoot(t)
	allowed := filepath.Clean(filepath.Join(root, "internal", "intelligence", "refresh.go"))
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || filepath.Clean(path) == allowed {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if err != nil {
			return err
		}
		for _, imp := range file.Imports {
			name := strings.Trim(imp.Path.Value, `"`)
			if name == "net/http" {
				t.Errorf("ordinary runtime file imports HTTP client package %q: %s", name, relative(root, path))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestHostMutationAPIsAreConfinedToExplicitOutputOrIntelligenceMaintenance(t *testing.T) {
	root := repositoryRoot(t)
	allowed := map[string]bool{
		filepath.Clean(filepath.Join(root, "internal", "app", "app.go")):                  true,
		filepath.Clean(filepath.Join(root, "internal", "intelligence", "local_store.go")): true,
		filepath.Clean(filepath.Join(root, "internal", "intelligence", "refresh.go")):     true,
	}
	mutating := map[string]bool{
		"WriteFile": true, "Create": true, "CreateTemp": true, "Remove": true, "RemoveAll": true,
		"Rename": true, "Mkdir": true, "MkdirAll": true, "Chmod": true, "Chown": true, "Lchown": true,
	}
	err := filepath.WalkDir(filepath.Join(root, "internal"), func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || allowed[filepath.Clean(path)] {
			return nil
		}
		file, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(file, func(n ast.Node) bool {
			sel, ok := n.(*ast.SelectorExpr)
			if !ok || !mutating[sel.Sel.Name] {
				return true
			}
			id, ok := sel.X.(*ast.Ident)
			if ok && id.Name == "os" {
				t.Errorf("host mutation API os.%s is outside explicit output/intelligence-maintenance boundary: %s", sel.Sel.Name, relative(root, path))
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func repositoryRoot(t *testing.T) string {
	t.Helper()
	_, file, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("runtime.Caller failed")
	}
	return filepath.Clean(filepath.Join(filepath.Dir(file), "..", ".."))
}

func relative(root, path string) string {
	if rel, err := filepath.Rel(root, path); err == nil {
		return rel
	}
	return path
}
