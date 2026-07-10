package reachability

import "strings"

// dispatch.go routes a polyglot repo: build one Graph per detected ecosystem, then triage
// each SCA finding against the graph for ITS ecosystem. This is the multi-language entry
// point; single-language callers keep using Extract + TriageSCA unchanged.

// ecosystemToLang maps an SCA finding's ecosystem (as trivy/grype/osv emit it) to the
// extractor Lang that owns it.
var ecosystemToLang = map[string]string{
	"go": "go", "gomod": "go", "gomodules": "go", "golang": "go", "golangdep": "go",
	"npm": "javascript", "yarn": "javascript", "pnpm": "javascript", "node": "javascript", "javascript": "javascript", "typescript": "javascript",
	"pip": "python", "pypi": "python", "poetry": "python", "pipenv": "python", "python": "python",
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

// BuildGraphsOrGo is the CLI/triage helper: BuildGraphs, but if no extractor detected a
// manifest (e.g. a Go source dir with no go.mod), it falls back to a forced Go extraction
// so a single-language Go triage still works — preserving the pre-multi-language behavior.
func BuildGraphsOrGo(root string) map[string]*Graph {
	graphs := BuildGraphs(root)
	if len(graphs) == 0 {
		if g, err := extractGo(root); err == nil && g != nil {
			graphs["go"] = g
		}
	}
	return graphs
}

// TriageMulti triages SCA findings across a polyglot repo. Each finding is analyzed against
// the graph for its own ecosystem; a finding whose ecosystem has no built graph (unknown
// language, or that manifest absent) is returned with an empty verdict + priority
// "unknown_ecosystem" — HONESTLY not-assessed, never silently called safe (§10).
func TriageMulti(graphs map[string]*Graph, findings []SCAFinding) []TriageResult {
	out := make([]TriageResult, 0, len(findings))
	for _, f := range findings {
		g := graphForFinding(graphs, f)
		if g == nil {
			out = append(out, TriageResult{Finding: f, Priority: "unknown_ecosystem"})
			continue
		}
		out = append(out, triageOne(g, f))
	}
	return out
}

// graphForFinding picks the graph a finding triages against: by its ecosystem when set;
// else, when the finding carries no ecosystem AND the repo is single-language, the sole
// graph (unambiguous — preserves back-compat for ecosystem-less SCA inputs). Multi-language
// repo + no ecosystem is genuinely ambiguous → nil (reported unknown_ecosystem, §10).
func graphForFinding(graphs map[string]*Graph, f SCAFinding) *Graph {
	if lang := LangForEcosystem(f.Ecosystem); lang != "" {
		return graphs[lang]
	}
	if f.Ecosystem == "" && len(graphs) == 1 {
		for _, only := range graphs {
			return only
		}
	}
	return nil
}
