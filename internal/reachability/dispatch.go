package reachability

import "strings"

// dispatch.go routes a polyglot repo: build one Graph per detected ecosystem, then triage
// each SCA finding against the graph for ITS ecosystem. This is the multi-language entry
// point; single-language callers keep using Extract + TriageSCA unchanged.

// ecosystemToLang maps an SCA finding's ecosystem (as trivy/grype/osv emit it) to the
// extractor Lang that owns it.
var ecosystemToLang = map[string]string{
	"go": "go", "gomod": "go", "golang": "go",
	"npm": "javascript", "yarn": "javascript", "pnpm": "javascript", "node": "javascript", "javascript": "javascript",
	"pip": "python", "pypi": "python", "poetry": "python", "python": "python",
}

// LangForEcosystem returns the extractor Lang for an SCA ecosystem string (case-insensitive),
// or "" when unknown.
func LangForEcosystem(ecosystem string) string {
	return ecosystemToLang[strings.ToLower(strings.TrimSpace(ecosystem))]
}

// BuildGraphs runs every extractor whose Detect fires on the repo and returns the graphs
// keyed by Lang. A repo with a package.json + requirements.txt gets both; a bare Go module
// gets one. An extractor that errors is skipped (best-effort — a broken JS tree never fails
// the Go graph).
func BuildGraphs(root string) map[string]*Graph {
	out := map[string]*Graph{}
	for _, ex := range Extractors() {
		if !ex.Detect(root) {
			continue
		}
		g, err := ex.Extract(root)
		if err != nil || g == nil {
			continue
		}
		out[ex.Lang()] = g
	}
	return out
}

// TriageMulti triages SCA findings across a polyglot repo. Each finding is analyzed against
// the graph for its own ecosystem; a finding whose ecosystem has no built graph (unknown
// language, or that manifest absent) is returned with an empty verdict + priority
// "unknown_ecosystem" — HONESTLY not-assessed, never silently called safe (§10).
func TriageMulti(graphs map[string]*Graph, findings []SCAFinding) []TriageResult {
	out := make([]TriageResult, 0, len(findings))
	for _, f := range findings {
		lang := LangForEcosystem(f.Ecosystem)
		g := graphs[lang]
		if lang == "" || g == nil {
			out = append(out, TriageResult{Finding: f, Priority: "unknown_ecosystem"})
			continue
		}
		out = append(out, triageOne(g, f))
	}
	return out
}
