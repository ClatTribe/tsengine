package reachability

import (
	"fmt"
	"sort"
	"strings"
)

// Verdict is the grounded reachability result for one (package, symbols) query.
type Verdict struct {
	Package       string   `json:"package"`
	Symbols       []string `json:"symbols,omitempty"`
	Imported      bool     `json:"imported"`  // the vulnerable symbol is called somewhere
	Reachable     bool     `json:"reachable"` // an app entrypoint can reach it
	EntryReached  []string `json:"entry_reached,omitempty"`
	DirectHitters []string `json:"direct_hitters,omitempty"` // funcs that call the vuln symbol
	Path          []string `json:"path,omitempty"`           // entrypoint → … → vuln symbol (the evidence)
	Lang          string   `json:"lang,omitempty"`           // extractor provenance
	Fidelity      Fidelity `json:"fidelity,omitempty"`       // how precise this verdict is (a coarse-tier negative is soft, §10)
}

// Analyze decides whether an application entrypoint (package-main `main`, or any
// exported function — a library's surface) has a call path to vulnPkg's symbols.
// Empty symbols ⇒ any symbol from the package. pkg-match is by module prefix, so a
// finding on "github.com/foo/bar" matches calls into "github.com/foo/bar/sub".
func Analyze(g *Graph, vulnPkg string, symbols []string) Verdict {
	symSet := map[string]bool{}
	for _, s := range symbols {
		symSet[s] = true
	}
	match := func(e ExtRef) bool {
		return pkgMatch(e.ImportPath, vulnPkg) && (len(symSet) == 0 || symSet[e.Symbol])
	}
	v := Verdict{Package: vulnPkg, Symbols: symbols, Lang: g.Lang, Fidelity: g.Fidelity}

	// direct hitters: functions whose body calls a matching external symbol.
	hitters := map[FuncID]bool{}
	for id, f := range g.Funcs {
		for _, e := range f.ExternalCalls {
			if match(e) {
				hitters[id] = true
				break
			}
		}
	}
	if len(hitters) == 0 {
		return v // not imported / not called at all — strongest "not reachable"
	}
	v.Imported = true
	for id := range hitters {
		v.DirectHitters = append(v.DirectHitters, string(id))
	}
	sort.Strings(v.DirectHitters)

	// reverse reachability: which functions can (transitively) reach a hitter.
	callers := map[FuncID][]FuncID{}
	for id, f := range g.Funcs {
		for _, c := range f.LocalCalls {
			callers[c] = append(callers[c], id)
		}
	}
	reaching := map[FuncID]bool{}
	queue := make([]FuncID, 0, len(hitters))
	for h := range hitters {
		reaching[h] = true
		queue = append(queue, h)
	}
	for len(queue) > 0 {
		n := queue[0]
		queue = queue[1:]
		for _, c := range callers[n] {
			if !reaching[c] {
				reaching[c] = true
				queue = append(queue, c)
			}
		}
	}

	// entrypoints among the reaching set.
	for id := range reaching {
		f := g.Funcs[id]
		if f.IsMain || f.Exported {
			v.EntryReached = append(v.EntryReached, string(id))
		}
	}
	sort.Strings(v.EntryReached)
	v.Reachable = len(v.EntryReached) > 0

	if v.Reachable {
		v.Path = shortestPath(g, v.EntryReached, hitters, match)
	}
	return v
}

// shortestPath does a multi-source BFS from the (sorted) reaching entrypoints over
// LocalCalls to the nearest hitter, then appends the MATCHING external symbol — the
// evidence (not just the hitter's first external call).
func shortestPath(g *Graph, entries []string, hitters map[FuncID]bool, match func(ExtRef) bool) []string {
	parent := map[FuncID]FuncID{}
	visited := map[FuncID]bool{}
	var queue []FuncID
	for _, e := range entries {
		id := FuncID(e)
		visited[id] = true
		queue = append(queue, id)
	}
	var target FuncID
	found := false
	for len(queue) > 0 && !found {
		n := queue[0]
		queue = queue[1:]
		if hitters[n] {
			target = n
			found = true
			break
		}
		f := g.Funcs[n]
		if f == nil {
			continue
		}
		callees := append([]FuncID(nil), f.LocalCalls...)
		sort.Slice(callees, func(i, j int) bool { return callees[i] < callees[j] })
		for _, c := range callees {
			if !visited[c] {
				visited[c] = true
				parent[c] = n
				queue = append(queue, c)
			}
		}
	}
	if !found {
		return nil
	}
	// reconstruct
	var rev []FuncID
	for n := target; ; {
		rev = append(rev, n)
		p, ok := parent[n]
		if !ok {
			break
		}
		n = p
	}
	out := make([]string, 0, len(rev)+1)
	for i := len(rev) - 1; i >= 0; i-- {
		out = append(out, string(rev[i]))
	}
	// append the MATCHING external call as the terminal evidence node
	if f := g.Funcs[target]; f != nil {
		for _, e := range f.ExternalCalls {
			if match(e) {
				out = append(out, e.ImportPath+"."+e.Symbol+" (vulnerable)")
				break
			}
		}
	}
	return out
}

func pkgMatch(importPath, vulnPkg string) bool {
	return importPath == vulnPkg || strings.HasPrefix(importPath, vulnPkg+"/")
}

// --- SCA triage ---

// SCAFinding is one dependency vulnerability to triage (from trivy/grype/osv).
type SCAFinding struct {
	ID        string   `json:"id"`
	CVE       string   `json:"cve,omitempty"`
	Package   string   `json:"package"`           // the vulnerable import/module path
	Symbols   []string `json:"symbols,omitempty"` // vulnerable functions; empty ⇒ any
	Severity  string   `json:"severity,omitempty"`
	Ecosystem string   `json:"ecosystem,omitempty"` // npm | pip | go | … — routes to the language graph (TriageMulti)
}

// TriageResult pairs a finding with its reachability verdict + a priority call.
type TriageResult struct {
	Finding  SCAFinding `json:"finding"`
	Verdict  Verdict    `json:"verdict"`
	Priority string     `json:"priority"` // reachable | deprioritized | unused
}

// TriageSCA runs reachability for each finding and assigns a priority: a vulnerable
// dependency whose function the app never calls is DEPRIORITIZED (present but
// unreachable); one with a real call path stays/elevates.
func TriageSCA(g *Graph, findings []SCAFinding) []TriageResult {
	out := make([]TriageResult, 0, len(findings))
	for _, f := range findings {
		out = append(out, triageOne(g, f))
	}
	return out
}

// triageOne is the per-finding reachability → priority decision shared by TriageSCA
// (single graph) and TriageMulti (per-ecosystem graph).
func triageOne(g *Graph, f SCAFinding) TriageResult {
	v := Analyze(g, f.Package, f.Symbols)
	pr := "deprioritized"
	switch {
	case v.Reachable:
		pr = "reachable"
	case !v.Imported:
		pr = "unused" // dependency present but the vulnerable symbol is never called
	}
	return TriageResult{Finding: f, Verdict: v, Priority: pr}
}

// Render formats a triage report.
func Render(results []TriageResult) string {
	var b strings.Builder
	reach, dep, unused := 0, 0, 0
	for _, r := range results {
		switch r.Priority {
		case "reachable":
			reach++
		case "unused":
			unused++
		default:
			dep++
		}
	}
	fmt.Fprintf(&b, "=== SCA reachability triage ===\n")
	fmt.Fprintf(&b, "%d finding(s): %d REACHABLE, %d deprioritized (in dead code), %d unused (symbol never called)\n\n",
		len(results), reach, dep, unused)
	for _, r := range results {
		mark := map[string]string{"reachable": "⚠ REACHABLE", "deprioritized": "↓ deprioritized", "unused": "· unused"}[r.Priority]
		fmt.Fprintf(&b, "[%s] %s %s  (%s, sev=%s)\n", r.Finding.ID, mark, r.Finding.Package, r.Finding.CVE, r.Finding.Severity)
		if r.Priority == "reachable" {
			fmt.Fprintf(&b, "    path: %s\n", strings.Join(r.Verdict.Path, " → "))
		} else if r.Verdict.Imported {
			fmt.Fprintf(&b, "    called only from non-entrypoint (dead) code: %s\n", strings.Join(r.Verdict.DirectHitters, ", "))
		} else {
			fmt.Fprintf(&b, "    the vulnerable symbol is not called anywhere in this codebase\n")
		}
	}
	return b.String()
}
