package hooks

import (
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// cvePattern (declared in threat_intel.go, same package) extracts a CVE
// id from a rule_id like "trivy::CVE-2016-2779".

// Corroborator implements hook 5 of CLAUDE.md §11. When two or more
// DISTINCT tools flag the same (endpoint, CWE) pair, that's cross-source
// agreement — strong evidence the finding is real. Each participating
// finding gets a corroborated_by list naming the other tools' rule_ids.
//
// This is a finalize hook because it needs to see the whole set. It
// runs BEFORE cross_tool_merge so the agreement signal is captured
// before any deduplication.
type Corroborator struct{}

// NewCorroborator constructs the hook.
func NewCorroborator() *Corroborator { return &Corroborator{} }

func (*Corroborator) Name() string { return "corroborator" }

// Finalize attaches corroborated_by to findings that agree across tools.
func (h *Corroborator) Finalize(findings []types.Finding) ([]types.Finding, []types.AuditEntry) {
	// Group finding indices by corroboration key (endpoint + sorted CWE).
	groups := map[string][]int{}
	for i, f := range findings {
		k := corroborationKey(f)
		if k == "" {
			continue
		}
		groups[k] = append(groups[k], i)
	}

	var audit []types.AuditEntry
	for _, idxs := range groups {
		if len(idxs) < 2 {
			continue
		}
		// Distinct tools only — two findings from the same tool on the
		// same surface aren't independent corroboration.
		tools := map[string]struct{}{}
		for _, i := range idxs {
			tools[findings[i].Tool] = struct{}{}
		}
		if len(tools) < 2 {
			continue
		}
		// Attach each finding's siblings' rule_ids.
		for _, i := range idxs {
			var others []string
			for _, j := range idxs {
				if j == i {
					continue
				}
				others = append(others, findings[j].RuleID)
			}
			sort.Strings(others)
			findings[i].CorroboratedBy = mergeUnique(findings[i].CorroboratedBy, others)
		}
		audit = append(audit, types.AuditEntry{
			Action: "annotate",
			Rule:   "corroborator::cross-tool-agreement",
			Reason: "agreement across tools: " + strings.Join(sortedKeys(tools), ", "),
		})
	}
	return findings, audit
}

// corroborationKey identifies "the same issue" across tools:
//
//   - If the rule_id carries a CVE, the CVE id IS the identity — two
//     scanners reporting CVE-2016-2779 corroborate even if they format
//     the package endpoint differently (trivy vs grype). This is the
//     common case for SCA / container CVE scanning.
//   - Otherwise fall back to (endpoint | sorted CWEs) — the web/DAST
//     case where nuclei + dalfox flag the same URL+weakness. Findings
//     with neither a CVE nor an (endpoint, CWE) pair don't corroborate
//     (too weak a signal alone).
func corroborationKey(f types.Finding) string {
	if cve := cvePattern.FindString(f.RuleID); cve != "" {
		return "cve:" + cve
	}
	if f.Endpoint == "" || len(f.CWE) == 0 {
		return ""
	}
	cwes := append([]string(nil), f.CWE...)
	sort.Strings(cwes)
	return "ep:" + strings.ToLower(f.Endpoint) + "|" + strings.Join(cwes, ",")
}

func sortedKeys(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
