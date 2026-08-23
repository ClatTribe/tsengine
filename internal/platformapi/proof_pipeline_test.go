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

// proof_pipeline_test.go is the ADR 0029 D1b guard: EVERY code path that writes a finding to the
// store must run the L1.5 chain and fold the result into the compliance posture.
//
// # Why a guard and not three fixes
//
// Counted before this landed, nineteen doors wrote findings. Sixteen enriched and folded. Three did
// not, in two different ways:
//
//   - pentest_discover.go did NEITHER — so a vulnerability the agent actually EXPLOITED opened no
//     control gap and the posture read clean for it, on the highest-evidence class in the product.
//   - saassync.go (both handlers), tlsscan.go and replay.go enriched and never folded.
//
// The saassync case is the one that makes the argument for a guard rather than three fixes:
// saasposture.go folds the SAME AssessGitHubOrg output when it arrives as a posted snapshot, and
// saassync.go did not when it arrived from a live sync. The identical finding opened a control gap
// through one door and not the other, decided by which button the customer pressed. No amount of
// reading one file finds that; it is only visible by comparing all nineteen, which is what this test
// does on every run.
//
// # What it checks, and the two ways it refuses to be vacuous
//
// Function-level, over the package's own source: a function that calls `Store.PutFinding` must also
// call `enrichFindings` and `d.foldIntoPosture`. Exemptions are named, justified and ASSERTED USED —
// a stale exemption is the same silent-guard failure as a missing check (§14.2 rule 6). And the
// writer count has a floor, so a rename of PutFinding that made this test match nothing would fail
// loudly rather than pass at 100%.

// exemptWriters are the finding-writing functions that legitimately do NOT enrich-and-fold, each with
// the reason. Keyed "file.go:FuncName". Adding an entry is a deliberate act with an argument attached.
var exemptWriters = map[string]string{
	// Re-stores a finding that is ALREADY in the store, to attach the proof a demonstration produced.
	// Its control gap opened when it was first written; folding again would assert a second gap for
	// one finding.
	"pentest_feedback.go:applyPentestProof": "updates an already-stored finding; it folded on first write",

	// A reinstatement folds (see l15audit.go) but deliberately does not re-enrich: the chain is what
	// dismissed the finding, and re-running it would re-apply the judgement the human just reversed.
	"l15audit.go:handleL15Reinstate": "human override of the chain; re-enriching would undo the reversal",
}

// minFindingWriters is the floor. If a refactor renames PutFinding or moves the writes out of this
// package, this test would otherwise match nothing and pass — a guard that cannot see its subject
// reporting success. Raise it when doors are added; never lower it silently.
const minFindingWriters = 20

func TestEveryFindingWriterEnrichesAndFolds(t *testing.T) {
	files := packageSourceFiles(t)
	if len(files) == 0 {
		t.Fatal("found no non-test source files to inspect — the guard cannot see its subject")
	}

	seen := 0
	usedExemptions := map[string]bool{}

	for _, path := range files {
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", path, err)
		}
		base := filepath.Base(path)

		for _, decl := range f.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Body == nil || !callsMethod(fn.Body, "PutFinding") {
				continue
			}
			seen++
			key := base + ":" + fn.Name.Name
			if reason, exempt := exemptWriters[key]; exempt {
				usedExemptions[key] = true
				if strings.TrimSpace(reason) == "" {
					t.Errorf("%s is exempt with an empty reason — an exemption without an argument is a hole", key)
				}
				continue
			}
			if !callsFunc(fn.Body, "enrichFindings") {
				t.Errorf("%s writes a finding to the store and never calls enrichFindings.\n"+
					"Without the L1.5 chain the finding carries no threat intel, no exploitability, no "+
					"corroboration and NO COMPLIANCE MAPPING (ADR 0029 D1a). Add the call, or add a "+
					"justified entry to exemptWriters.", key)
			}
			if !callsMethod(fn.Body, "foldIntoPosture") {
				t.Errorf("%s writes a finding to the store and never folds it into the compliance posture.\n"+
					"The control gap the finding implies will not open, so the posture reads clean for a real "+
					"finding — false-compliant through the ingest door (ADR 0029 D1a). Add "+
					"d.foldIntoPosture, or add a justified entry to exemptWriters.", key)
			}
		}
	}

	if seen < minFindingWriters {
		t.Errorf("only %d finding-writing functions found, expected at least %d.\n"+
			"Either doors were removed (lower the floor deliberately) or the write call was renamed and "+
			"this guard is now inspecting nothing while reporting success.", seen, minFindingWriters)
	}
	for key := range exemptWriters {
		if !usedExemptions[key] {
			t.Errorf("exemption %q matched no function. A stale exemption hides the next real one — "+
				"delete it or fix the key.", key)
		}
	}
}

// packageSourceFiles lists the package's non-test .go files.
func packageSourceFiles(t *testing.T) []string {
	t.Helper()
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package dir: %v", err)
	}
	var out []string
	for _, e := range entries {
		n := e.Name()
		if e.IsDir() || !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
			continue
		}
		out = append(out, n)
	}
	return out
}

// callsMethod reports whether the body contains a call to a selector ending in `.name`
// (d.foldIntoPosture, d.Store.PutFinding, …).
func callsMethod(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if sel, ok := call.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == name {
			found = true
		}
		return !found
	})
	return found
}

// callsFunc reports whether the body contains a call to a bare package-level function `name(...)`.
func callsFunc(body *ast.BlockStmt, name string) bool {
	found := false
	ast.Inspect(body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == name {
			found = true
		}
		return !found
	})
	return found
}
