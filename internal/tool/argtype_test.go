package tool

import (
	"encoding/json"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A dispatch crosses the host→sandbox boundary as JSON (§12.3), and encoding/json decodes
// every number into float64. An int written by a handler therefore comes back as float64,
// and a direct .(int) assertion fails — IN THE SANDBOX, which is production. It succeeds in
// unit tests, which never serialize, so nothing catches it.
func TestArgInt_SurvivesTheSandboxBoundary(t *testing.T) {
	orig := Args{"depth": 3, "timeout": 60, "rate_limit": 150}
	b, err := json.Marshal(orig)
	if err != nil {
		t.Fatal(err)
	}
	var wire Args
	if err := json.Unmarshal(b, &wire); err != nil {
		t.Fatal(err)
	}
	// The bug, stated: this is what every wrapper used to do.
	if _, ok := wire["depth"].(int); ok {
		t.Fatal("premise changed: JSON now round-trips int as int, and this guard is obsolete")
	}
	for k, want := range map[string]int{"depth": 3, "timeout": 60, "rate_limit": 150} {
		got, ok := ArgInt(wire, k)
		if !ok || got != want {
			t.Errorf("ArgInt(%q) = %d, %v; want %d, true — the value a handler set must survive "+
				"the boundary, or the tool silently uses its default", k, got, ok, want)
		}
	}
}

// A fractional float is REFUSED rather than truncated. 2.7 is not something a caller meant
// as a count, and silently making it 2 repeats this bug's defining feature: a value quietly
// becoming something other than what was written.
func TestArgInt_RefusesAFractionalValue(t *testing.T) {
	if _, ok := ArgInt(Args{"depth": 2.7}, "depth"); ok {
		t.Error("2.7 must not silently become 2")
	}
	if got, ok := ArgInt(Args{"depth": 3.0}, "depth"); !ok || got != 3 {
		t.Errorf("a whole float is a legitimate JSON int: got %d, %v", got, ok)
	}
}

func TestArgInt_AbsentAndWrongTypeAreNotZero(t *testing.T) {
	if _, ok := ArgInt(Args{}, "depth"); ok {
		t.Error("an absent key must report not-found, not 0")
	}
	if _, ok := ArgInt(Args{"depth": "three"}, "depth"); ok {
		t.Error("a string must not be read as an int")
	}
}

// THE CLASS GUARD. Fixing six call sites does not stop the seventh, and the seventh will
// look exactly as correct as these did: `args["x"].(int)` is idiomatic Go and passes review.
// It is only wrong because of where these args have been.
func TestNoWrapperAssertsIntDirectlyOnArgs(t *testing.T) {
	root := ".."
	var offenders []string
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			ta, ok := n.(*ast.TypeAssertExpr)
			if !ok || ta.Type == nil {
				return true
			}
			id, ok := ta.Type.(*ast.Ident)
			if !ok || (id.Name != "int" && id.Name != "int64") {
				return true
			}
			// Only flag assertions on an index into something called args.
			idx, ok := ta.X.(*ast.IndexExpr)
			if !ok {
				return true
			}
			if x, ok := idx.X.(*ast.Ident); ok && strings.Contains(strings.ToLower(x.Name), "args") {
				offenders = append(offenders, fset.Position(ta.Pos()).String())
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("%d direct int assertion(s) on tool args: %v\n\n"+
			"Args crosses the sandbox as JSON, so an int arrives as float64 and this assertion "+
			"fails in production while passing every unit test. Use tool.ArgInt. The last one cost "+
			"a 96%% crawl-surface loss on every sandboxed web scan.", len(offenders), offenders)
	}
}
