package repository

import (
	"strings"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// PlanEscalation is the repository conditional-depth stage
// (asset.EscalationPlanner). Depth tools fire only on a signal:
//
//   - a semgrep INJECTION-class finding (taint-shaped) → CodeQL on that
//     language. semgrep's pattern match found a candidate; CodeQL confirms
//     it with interprocedural taint/dataflow (the recall lever past
//     semgrep's pattern ceiling). One CodeQL run per language, not per
//     finding (deduped) — CodeQL is slow.
//   - a finding in a MOBILE file → mobsfscan over the tree (mobile-specific
//     SAST semgrep's general packs miss).
func (h *Handler) PlanEscalation(_ types.Asset, _ []string, findings []types.Finding) []asset.Dispatch {
	var out []asset.Dispatch
	langSeen := map[string]bool{}
	mobsfFired := false
	govulnFired := false

	codeql, hasCodeQL := tool.Get("codeql")
	mob, hasMob := tool.Get("mobsfscan")
	gov, hasGov := tool.Get("govulncheck")

	for _, f := range findings {
		if hasCodeQL && isInjectionFinding(f) {
			if lang := codeqlLangForPath(f.Endpoint); lang != "" && !langSeen[lang] {
				langSeen[lang] = true
				out = append(out, asset.Dispatch{Tool: codeql, Args: tool.Args{
					"target": WorkspacePath, "language": lang,
				}, EscalatedFrom: "semgrep-injection→codeql"})
			}
		}
		if hasMob && !mobsfFired && isMobileFinding(f) {
			mobsfFired = true
			out = append(out, asset.Dispatch{Tool: mob, Args: tool.Args{"target": WorkspacePath},
				EscalatedFrom: "mobile→mobsfscan"})
		}
		// Go project → reachability-aware SCA. govulncheck reports only the
		// CVEs whose vulnerable symbol is actually called, separating the
		// reachable (real) SCA findings from the unreachable (FP) majority.
		if hasGov && !govulnFired && isGoProjectFinding(f) {
			govulnFired = true
			out = append(out, asset.Dispatch{Tool: gov, Args: tool.Args{"target": WorkspacePath},
				EscalatedFrom: "go-project→govulncheck"})
		}
	}
	return out
}

// isGoProjectFinding reports whether a finding indicates a Go project — a Go
// source file, or an SCA finding located in a Go module manifest. The signal
// that warrants the (Go-toolchain-heavy) reachability pass.
func isGoProjectFinding(f types.Finding) bool {
	p := strings.ToLower(f.Endpoint)
	return strings.HasSuffix(p, ".go") || strings.Contains(p, "go.mod") || strings.Contains(p, "go.sum")
}

// injectionCWEs are the taint-class CWEs worth a CodeQL dataflow confirm.
var injectionCWEs = map[string]bool{
	"CWE-89": true, "CWE-79": true, "CWE-78": true, "CWE-22": true,
	"CWE-94": true, "CWE-611": true, "CWE-918": true, "CWE-90": true,
	"CWE-643": true, "CWE-502": true, "CWE-91": true, "CWE-98": true,
}

func isInjectionFinding(f types.Finding) bool {
	if f.Tool != "semgrep" {
		return false
	}
	for _, c := range f.CWE {
		if injectionCWEs[c] {
			return true
		}
	}
	return false
}

// codeqlLangForPath maps a finding's file path to a CodeQL language, or ""
// for a language CodeQL doesn't analyze here.
func codeqlLangForPath(endpoint string) string {
	p := strings.ToLower(endpoint)
	switch {
	case strings.HasSuffix(p, ".java"), strings.HasSuffix(p, ".kt"):
		return "java" // CodeQL analyzes Kotlin under the java extractor
	case strings.HasSuffix(p, ".py"):
		return "python"
	case strings.HasSuffix(p, ".js"), strings.HasSuffix(p, ".jsx"),
		strings.HasSuffix(p, ".ts"), strings.HasSuffix(p, ".tsx"):
		return "javascript"
	case strings.HasSuffix(p, ".go"):
		return "go"
	case strings.HasSuffix(p, ".rb"):
		return "ruby"
	case strings.HasSuffix(p, ".cs"):
		return "csharp"
	case strings.HasSuffix(p, ".c"), strings.HasSuffix(p, ".cc"),
		strings.HasSuffix(p, ".cpp"), strings.HasSuffix(p, ".h"):
		return "cpp"
	}
	return ""
}

// mobileMarkers identify a mobile project from a finding's file path.
var mobileMarkers = []string{
	"androidmanifest.xml", "build.gradle", "info.plist", ".xcodeproj",
	".kt", ".swift", "/android/", "/ios/",
}

func isMobileFinding(f types.Finding) bool {
	p := strings.ToLower(f.Endpoint)
	for _, m := range mobileMarkers {
		if strings.Contains(p, m) {
			return true
		}
	}
	return false
}
