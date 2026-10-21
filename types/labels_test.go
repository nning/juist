package types

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"
)

var labelLike = regexp.MustCompile(`^juist( [a-z0-9 ]+ v[0-9]+ ?|/[a-z0-9-]+/v[0-9]+)\x00?$`)

func TestLabelsAreDistinctAndLiveInOneFile(t *testing.T) {
	f, err := parser.ParseFile(token.NewFileSet(), "labels.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]string{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		v, _ := strconv.Unquote(vs.Values[0].(*ast.BasicLit).Value)
		key := strings.TrimSpace(v)
		if other, dup := seen[key]; dup {
			t.Errorf("%s and %s are one label, %q", other, vs.Names[0], v)
		}
		seen[key] = vs.Names[0].Name
		if !labelLike.MatchString(v) || strings.Contains(v, "\x00") {
			t.Errorf("%s = %q is not a label as this test finds them", vs.Names[0], v)
		}
		return true
	})

	err = filepath.WalkDir("..", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() && (strings.HasPrefix(d.Name(), ".") && d.Name() != ".." || d.Name() == "website" || d.Name() == "build" || d.Name() == "android") {
			return filepath.SkipDir
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") || path == filepath.Join("..", "types", "labels.go") {
			return nil
		}
		f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
		if err != nil {
			return err
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if lit, ok := n.(*ast.BasicLit); ok && lit.Kind == token.STRING {
				if v, _ := strconv.Unquote(lit.Value); labelLike.MatchString(v) {
					t.Errorf("%s: label %q outside types/labels.go", path, v)
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}
