package platformapi

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// No ingest door may discard a compliance-posture write.
//
// Sixteen of them did, identically — `_ = d.GRC.Apply(ctx, tenantID, f)` — while the scan door
// (runner.processFinding) treats the same call as FATAL and aborts. The same operation cannot be
// load-bearing on one door and ignorable on sixteen.
//
// What a dropped Apply costs is the failure mode the compliance layer exists to prevent: the finding
// is stored and visible, and the control gap it should have opened never opens, so the posture shows
// no gap for a real finding. That is false-compliant arriving through the ingest door — the same
// place the L1.5 chain was once skipped on these very handlers, which is what makes a seventeenth
// door writing the same line entirely plausible.
func TestNoIngestDoorDiscardsAPostureWrite(t *testing.T) {
	var offenders []string
	err := filepath.Walk(".", func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		src, rerr := os.ReadFile(path)
		if rerr != nil {
			return nil
		}
		f, perr := parser.ParseFile(token.NewFileSet(), path, src, 0)
		if perr != nil {
			return nil
		}
		ast.Inspect(f, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok || len(as.Lhs) != 1 {
				return true
			}
			id, ok := as.Lhs[0].(*ast.Ident)
			if !ok || id.Name != "_" {
				return true
			}
			call, ok := as.Rhs[0].(*ast.CallExpr)
			if !ok {
				return true
			}
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok || sel.Sel.Name != "Apply" {
				return true
			}
			// d.GRC.Apply / s.GRC.Apply — the receiver is itself a selector ending in GRC.
			if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "GRC" {
				offenders = append(offenders, path)
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(offenders) > 0 {
		t.Errorf("%d file(s) discard a compliance-posture write: %v\n\n"+
			"Use Deps.foldIntoPosture, which logs what it could not apply. A silently dropped Apply "+
			"leaves the finding visible and its control gap closed — the posture then reports no gap "+
			"for a real finding, which is the false-compliant failure the compliance layer exists to "+
			"prevent.", len(offenders), offenders)
	}
}
