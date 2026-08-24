package runner

import (
	"strings"

	"github.com/ClatTribe/tsengine/internal/reachability"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// reachability.go is ADR 0029 D2a: the code surface's validation rung.
//
// # Why this exists
//
// A dependency scanner tells you a vulnerable package is PRESENT. That is a fact about the lockfile,
// not about the application, and it is the single largest source of noise this product handles — most
// of a repository's CVE list is code nothing calls. `internal/reachability` answers the next
// question, "does THIS code reach it from an entrypoint", and until now it answered it only for
// someone running the CLI by hand. The platform, which is where customers actually are, had no rung
// above "a scanner said so" for code.
//
// # The seam
//
// The platform already shallow-clones every repository asset to a host temp dir and bind-mounts it
// read-only into the sandbox (cmd/platform). The tree is therefore on disk for exactly the window a
// scan runs in, which is the window this needs. Nothing is fetched, cloned or kept.
//
// # What the annotation may and may not say (§10)
//
//   - It NEVER touches Severity or VerificationStatus. Reachability proves a path exists in the
//     code; it does not prove the vulnerability is exploitable, and "verified" in this codebase means
//     a predicate ran against the thing itself. Silently down-ranking a finding because a call graph
//     could not see a path would be the worst version of this feature.
//   - It records the FIDELITY TIER with every verdict, because a coarse-tier "not reachable" is a
//     SOFT negative — `import_use` cannot see cross-file dynamic dispatch — and a reader who cannot
//     tell the tiers apart will act on the weak one as if it were the strong one.
//   - Our scanners emit no vulnerable-symbol names, so the question actually answered is "is this
//     PACKAGE reachable", not "is the vulnerable function reachable". That is a weaker claim and the
//     annotation says so rather than letting the stronger reading stand.
//   - No graph, no package, or an ecosystem we cannot route: the finding is returned UNCHANGED. An
//     absent annotation is not a claim; a wrong one is.

// Reachability annotation keys, on the finding's ToolArgs.
const (
	// ReachabilityKey is the verdict: reachable | deprioritized | unused | unknown_ecosystem.
	ReachabilityKey = "reachability"
	// ReachabilityFidelityKey is how precise that verdict is — call_graph or import_use.
	ReachabilityFidelityKey = "reachability_fidelity"
	// ReachabilityPathKey is the entrypoint → … → package path, when one was found. The evidence.
	ReachabilityPathKey = "reachability_path"
	// ReachabilityScopeKey records WHAT was asked, so nobody reads a package-level answer as a
	// function-level one.
	ReachabilityScopeKey = "reachability_scope"
)

// maxPathHops bounds the recorded evidence path. A deep call chain is evidence; the whole chain
// rendered into a map value is a wall.
const maxPathHops = 12

// TriageReachability annotates the SCA findings in a scan with a reachability verdict computed over
// the repository at root. Non-SCA findings and anything it cannot route are returned untouched.
//
// It is best-effort by construction: every failure path returns the findings unchanged rather than
// annotating them with a guess.
func TriageReachability(root string, findings []types.Finding) []types.Finding {
	if strings.TrimSpace(root) == "" || len(findings) == 0 {
		return findings
	}

	// Collect the SCA findings first, so a repo with none never pays for graph construction.
	type target struct {
		idx int
		sca reachability.SCAFinding
	}
	var targets []target
	for i, f := range findings {
		pkg, eco, ok := scaPackage(f)
		if !ok {
			continue
		}
		targets = append(targets, target{idx: i, sca: reachability.SCAFinding{
			ID: f.ID, CVE: cveOf(f), Package: pkg, Ecosystem: eco, Severity: string(f.Severity),
			// Symbols deliberately empty: no scanner we wrap reports the vulnerable function, and
			// inventing one would make the verdict answer a question nobody asked.
		}})
	}
	if len(targets) == 0 {
		return findings
	}

	// An EMPTY graph is not an answer. BuildGraphsOrGo falls back to the Go extractor for any
	// directory, so a tree we could not read — wrong language, failed clone, an empty dir — comes back
	// as a graph with no functions in it, against which EVERY dependency is trivially "unused". That
	// reads as a clean bill of health for a repository nobody analysed, so the emptiness has to be
	// checked rather than the map length (a test caught this asserting exactly that case).
	graphs := map[string]*reachability.Graph{}
	for lang, g := range reachability.BuildGraphsOrGo(root) {
		if g != nil && len(g.Funcs) > 0 {
			graphs[lang] = g
		}
	}
	if len(graphs) == 0 {
		return findings // we could not read the tree; that is not a verdict
	}

	scas := make([]reachability.SCAFinding, 0, len(targets))
	for _, t := range targets {
		scas = append(scas, t.sca)
	}
	results := reachability.TriageMulti(graphs, scas)
	if len(results) != len(targets) {
		return findings // shape mismatch: refuse rather than misalign verdicts onto findings
	}

	out := make([]types.Finding, len(findings))
	copy(out, findings)
	for i, res := range results {
		f := out[targets[i].idx]
		if f.ToolArgs == nil {
			f.ToolArgs = map[string]string{}
		} else {
			f.ToolArgs = cloneArgs(f.ToolArgs) // never mutate the caller's map
		}
		f.ToolArgs[ReachabilityKey] = res.Priority
		f.ToolArgs[ReachabilityScopeKey] = "package"
		if fid := string(res.Verdict.Fidelity); fid != "" {
			f.ToolArgs[ReachabilityFidelityKey] = fid
		}
		if p := res.Verdict.Path; len(p) > 0 {
			if len(p) > maxPathHops {
				p = append(append([]string{}, p[:maxPathHops]...), "…")
			}
			f.ToolArgs[ReachabilityPathKey] = strings.Join(p, " → ")
		}
		f.Description = strings.TrimSpace(f.Description + "\n\n" + reachabilityNote(res))
		out[targets[i].idx] = f
	}
	return out
}

// reachabilityNote is the sentence a human reads. It states the verdict, what was actually asked,
// and — where it matters — why the answer is weaker than it looks.
func reachabilityNote(res reachability.TriageResult) string {
	const scope = "This checks whether the PACKAGE is reachable, not the specific vulnerable " +
		"function: the scanner did not report one."
	switch res.Priority {
	case "reachable":
		s := "Reachability: your code can reach this dependency from an entrypoint."
		if p := res.Verdict.Path; len(p) > 0 {
			s += " Path: " + strings.Join(p, " → ") + "."
		}
		return s + " " + scope
	case "unknown_ecosystem":
		return "Reachability: not analysed — we could not tell which language graph this dependency " +
			"belongs to, so no reachability claim is made either way."
	case "deprioritized", "unused":
		s := "Reachability: no call path was found from an entrypoint to this dependency, so it is " +
			"likely lower priority than its severity suggests."
		if res.Verdict.Fidelity == reachability.FidelityImportUse {
			s += " TREAT THIS AS A SOFT NEGATIVE: this language is analysed at import-and-call-site " +
				"level, which cannot see dynamic dispatch across files, so an unseen path is possible."
		}
		return s + " The finding is unchanged — this is a priority signal, not a dismissal. " + scope
	default:
		return "Reachability: " + res.Priority + ". " + scope
	}
}

// scaPackage extracts the dependency coordinate and ecosystem from a finding, and reports whether
// this is a dependency finding at all. Each scanner records it differently; guessing from the title
// would pick up SAST and IaC findings that name a package in passing.
func scaPackage(f types.Finding) (pkg, ecosystem string, ok bool) {
	switch f.Tool {
	case "osv-scanner":
		// osv-scanner puts the package coordinate in the endpoint and names the ecosystem outright.
		return strings.TrimSpace(f.Endpoint), f.ToolArgs["ecosystem"], strings.TrimSpace(f.Endpoint) != ""
	case "grype":
		p := strings.TrimSpace(f.ToolArgs["pkg"])
		return p, f.ToolArgs["pkg_type"], p != ""
	case "trivy":
		// trivy also reports OS packages and IaC misconfigurations. Only application dependencies
		// have a call graph to be reachable in; an OS package does not, and answering for one would
		// be a category error rather than a near miss.
		if f.ToolArgs["pkg_class"] != "lang-pkgs" {
			return "", "", false
		}
		p := strings.TrimSpace(f.ToolArgs["pkg"])
		// trivy names no ecosystem string; an empty one routes to the sole graph in a single-language
		// repo and is reported unknown_ecosystem in a polyglot one, which is the honest split.
		return p, "", p != ""
	default:
		return "", "", false
	}
}

// cveOf pulls a CVE id out of a finding's rule id, for the triage record. Absent is fine.
func cveOf(f types.Finding) string {
	for _, s := range []string{f.RuleID, f.Title} {
		if i := strings.Index(strings.ToUpper(s), "CVE-"); i >= 0 {
			end := i
			for end < len(s) && (s[end] == '-' || s[end] >= '0' && s[end] <= '9' ||
				s[end] >= 'A' && s[end] <= 'Z' || s[end] >= 'a' && s[end] <= 'z') {
				end++
			}
			return strings.ToUpper(s[i:end])
		}
	}
	return ""
}

func cloneArgs(in map[string]string) map[string]string {
	out := make(map[string]string, len(in)+4)
	for k, v := range in {
		out[k] = v
	}
	return out
}
