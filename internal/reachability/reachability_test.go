package reachability

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writeRepo materializes a small Go module on disk so the extractor runs against
// REAL source (parsed with go/parser), not a hand-built graph.
//
// Topology:
//
//	main.main        → util.Process → util.helper → vuln.Bad()        (REACHABLE)
//	main.main        → safe.Fine()                                    (not vulnerable)
//	main.deadCode    → vuln.NeverReached()   (deadCode is unexported, never called → UNREACHABLE / dead)
//	util.Audit (exported) → vuln.AuditBad()  (library entrypoint → REACHABLE)
//	(no one)         → ghost.Boom()          (package not imported at all → UNUSED)
func writeRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, content string) {
		p := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o750); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write("go.mod", "module example.com/app\n\ngo 1.22\n")
	write("main.go", `package main

import (
	"example.com/app/internal/util"
	"github.com/safe/lib"
	"github.com/evil/vuln"
)

func main() {
	util.Process()
	lib.Fine()
}

func deadCode() { vuln.NeverReached() }
`)
	write("internal/util/util.go", `package util

import "github.com/evil/vuln"

func Process() { helper() }
func helper()  { vuln.Bad() }
func Audit()   { vuln.AuditBad() }
`)
	return root
}

func TestReachable_TransitivePath(t *testing.T) {
	g, err := Extract(writeRepo(t))
	if err != nil {
		t.Fatal(err)
	}
	v := Analyze(g, "github.com/evil/vuln", []string{"Bad"})
	if !v.Reachable {
		t.Fatalf("vuln.Bad should be reachable; verdict=%+v", v)
	}
	// main must be recognized as an entrypoint that can reach the vuln.
	if !contains(v.EntryReached, "main") {
		t.Errorf("main should be among reaching entrypoints: %v", v.EntryReached)
	}
	// the cited path must trace to the real call site (shortest-from-any-entrypoint).
	got := strings.Join(v.Path, " → ")
	for _, want := range []string{"internal/util/helper", "github.com/evil/vuln.Bad (vulnerable)"} {
		if !strings.Contains(got, want) {
			t.Errorf("path missing %q; got: %s", want, got)
		}
	}
}

func contains(xs []string, x string) bool {
	for _, s := range xs {
		if s == x {
			return true
		}
	}
	return false
}

func TestUnreachable_DeadCode(t *testing.T) {
	g, _ := Extract(writeRepo(t))
	// vuln.NeverReached is only called by main.deadCode, which is unexported and
	// never called → no entrypoint path → NOT reachable (correctly deprioritized).
	v := Analyze(g, "github.com/evil/vuln", []string{"NeverReached"})
	if v.Reachable {
		t.Fatalf("NeverReached is in dead code; should NOT be reachable: %+v", v)
	}
	if !v.Imported {
		t.Errorf("NeverReached IS called (in dead code) — Imported should be true")
	}
}

func TestReachable_ExportedLibraryEntrypoint(t *testing.T) {
	g, _ := Extract(writeRepo(t))
	// util.Audit is exported → a library entrypoint → vuln.AuditBad is reachable.
	v := Analyze(g, "github.com/evil/vuln", []string{"AuditBad"})
	if !v.Reachable {
		t.Fatalf("AuditBad reachable via exported util.Audit; got %+v", v)
	}
}

func TestUnused_PackageNotImported(t *testing.T) {
	g, _ := Extract(writeRepo(t))
	v := Analyze(g, "github.com/ghost/pkg", nil)
	if v.Reachable || v.Imported {
		t.Fatalf("ghost pkg is never imported; should be unused: %+v", v)
	}
}

func TestTriage_PrioritizesReachable(t *testing.T) {
	g, _ := Extract(writeRepo(t))
	findings := []SCAFinding{
		{ID: "CVE-1", CVE: "CVE-2026-1", Package: "github.com/evil/vuln", Symbols: []string{"Bad"}, Severity: "high"},
		{ID: "CVE-2", CVE: "CVE-2026-2", Package: "github.com/evil/vuln", Symbols: []string{"NeverReached"}, Severity: "critical"},
		{ID: "CVE-3", CVE: "CVE-2026-3", Package: "github.com/ghost/pkg", Severity: "critical"},
	}
	res := TriageSCA(g, findings)
	want := map[string]string{"CVE-1": "reachable", "CVE-2": "deprioritized", "CVE-3": "unused"}
	for _, r := range res {
		if got := r.Priority; got != want[r.Finding.ID] {
			t.Errorf("%s: priority=%q, want %q", r.Finding.ID, got, want[r.Finding.ID])
		}
	}
	out := Render(res)
	t.Log("\n" + out)
	if !strings.Contains(out, "1 REACHABLE") {
		t.Errorf("summary wrong:\n%s", out)
	}
	// the critical-but-unreachable CVE must NOT be flagged reachable — the whole point.
	if strings.Contains(out, "CVE-2") && strings.Contains(out, "⚠ REACHABLE github.com/evil/vuln  (CVE-2026-2") {
		t.Error("a critical CVE in dead code was wrongly elevated")
	}
}

// Reachability over the tsengine repo itself must not panic and should find the
// graph non-empty (smoke test against real, large source).
func TestExtract_SelfSmoke(t *testing.T) {
	// walk up to the module root
	root, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	g, err := Extract(root)
	if err != nil {
		t.Fatalf("extract self: %v", err)
	}
	if len(g.Funcs) < 100 {
		t.Errorf("expected many functions in the tsengine repo, got %d", len(g.Funcs))
	}
	if g.Module == "" {
		t.Error("module path not read from go.mod")
	}
}
