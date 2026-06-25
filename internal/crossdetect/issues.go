package crossdetect

import (
	"regexp"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Issue is a unified, de-duplicated risk: the same underlying weakness reported
// by one or more scanners across the tenant's surfaces, collapsed into a single
// row. This is the "one issue, many signals" model — a CVE that trivy, grype,
// AND govulncheck all flag is ONE issue confirmed by three sources, not three
// rows of noise.
type Issue struct {
	Key        string   `json:"key"`           // the dedup key (CVE, else rule_id|endpoint)
	Title      string   `json:"title"`         // a representative title
	Severity   string   `json:"severity"`      // the worst severity across the group
	CVE        string   `json:"cve,omitempty"` // the CVE, when the group is keyed by one
	Endpoint   string   `json:"endpoint,omitempty"`
	Tools      []string `json:"tools"`       // distinct scanners that reported it (the corroboration)
	Count      int      `json:"count"`       // how many raw findings collapsed in
	Confirmed  bool     `json:"confirmed"`   // ≥2 independent tools agree
	FindingIDs []string `json:"finding_ids"` // the raw findings this issue rolls up
	// Runtime correlation (ADR-0007 Phase 0): this issue's endpoint is ALSO being
	// attacked in production per an in-app-firewall signal — observed-in-the-wild,
	// the strongest exploitability evidence. Set by AnnotateRuntime.
	Attacked    bool `json:"attacked,omitempty"`
	AttackCount int  `json:"attack_count,omitempty"`
	// Data-tier prioritization (PrioritizeByDataTier): DataTier is the customer-data
	// sensitivity of the asset this issue was attributed to (1 = customer data … 3 = low);
	// RiskRank is the tier-adjusted priority (severity × tier) the issue list is sorted by.
	// Both omitempty — zero until an owner tiers the asset and the issue is attributable.
	DataTier int `json:"data_tier,omitempty"`
	RiskRank int `json:"risk_rank,omitempty"`
	// Live-exploitable fusion (the ACSP "distinguish theoretical from active/reachable/exploitable"
	// lens — set by AnnotateLiveRisk). Live = this issue is genuinely live, not just present:
	// observed under attack, OR internet-exposed AND on an attack path to a crown jewel, OR
	// internet-exposed + serious + corroborated. Exposed/InAttackPath are the grounded sub-signals;
	// LiveReason is the plain-English why. All omitempty — zero until the signals are present.
	Live         bool   `json:"live,omitempty"`
	LiveReason   string `json:"live_reason,omitempty"`
	Exposed      bool   `json:"exposed,omitempty"`
	InAttackPath bool   `json:"in_attack_path,omitempty"`
}

var cveRe = regexp.MustCompile(`CVE-\d{4}-\d{4,7}`)

// UnifiedIssues collapses a tenant's flat finding list into de-duplicated issues.
// Findings sharing a CVE (across any scanner / surface) merge into one issue;
// otherwise they key on rule_id|endpoint. Grounded: an issue only claims the
// tools that actually reported it, and "confirmed" means ≥2 independent scanners
// genuinely agreed — never inflated.
func UnifiedIssues(findings []types.Finding) []Issue {
	groups := map[string]*Issue{}
	var order []string

	for _, f := range findings {
		key, cve := dedupKey(f)
		g := groups[key]
		if g == nil {
			g = &Issue{Key: key, Title: firstNonEmpty(f.Title, f.RuleID), CVE: cve, Endpoint: f.Endpoint, Severity: string(f.Severity)}
			groups[key] = g
			order = append(order, key)
		}
		g.Count++
		g.FindingIDs = appendUniqueStr(g.FindingIDs, f.ID)
		// Normalize the tool name (lower + trim) so casing/whitespace variants of the same
		// scanner ("Trivy" vs "trivy ") count as ONE tool — else they'd falsely flip Confirmed
		// (≥2 independent tools) on a single tool's output.
		if t := strings.ToLower(strings.TrimSpace(f.Tool)); t != "" {
			g.Tools = appendUniqueStr(g.Tools, t)
		}
		if sevRank(string(f.Severity)) < sevRank(g.Severity) {
			g.Severity = string(f.Severity)
			if f.Title != "" {
				g.Title = f.Title
			}
		}
	}

	out := make([]Issue, 0, len(order))
	for _, k := range order {
		g := groups[k]
		sort.Strings(g.Tools)
		g.Confirmed = len(g.Tools) >= 2
		out = append(out, *g)
	}
	// Worst severity first; within a severity, the most-corroborated first.
	sort.SliceStable(out, func(i, j int) bool {
		if si, sj := sevRank(out[i].Severity), sevRank(out[j].Severity); si != sj {
			return si < sj
		}
		return len(out[i].Tools) > len(out[j].Tools)
	})
	return out
}

// dedupKey returns the grouping key for a finding and the CVE if it has one. A
// CVE bridges across scanners + surfaces (the whole point of dedup); otherwise
// we fall back to the rule + location, which is conservative (won't merge
// genuinely different issues).
func dedupKey(f types.Finding) (key, cve string) {
	// Look for the CVE in the rule, title AND description — different scanners surface the same
	// CVE in different fields (one in the title, another only in the body). Searching all three
	// lets the same CVE from two tools merge into one issue instead of two (correlation FN fix).
	if m := cveRe.FindString(f.RuleID + " " + f.Title + " " + f.Description); m != "" {
		return "cve|" + strings.ToUpper(m), strings.ToUpper(m)
	}
	return "rule|" + strings.ToLower(f.RuleID) + "|" + strings.ToLower(f.Endpoint), ""
}

// sevRank mirrors the engine severity order (lower = worse).
func sevRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	case "info":
		return 4
	}
	return 5
}

func appendUniqueStr(xs []string, v string) []string {
	for _, x := range xs {
		if x == v {
			return xs
		}
	}
	return append(xs, v)
}
