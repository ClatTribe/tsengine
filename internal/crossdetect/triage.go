package crossdetect

import (
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// triage.go computes the AUTO-TRIAGE FUNNEL — the quantified "how much noise the engine
// removed automatically before a human had to look" metric. It is the deterministic analogue
// of the funnel a scaling security team publishes (e.g. "71% of SAST auto-triaged"): of all
// raw findings, how many were dropped by exclusion rules, collapsed as duplicates, or
// suppressed (accepted-risk), leaving only the actionable issues a human triages. Grounded —
// every count comes from the same dedup/exclusion/suppression machinery the issues view uses,
// never an estimate.

// TriageFunnel is the auto-triage breakdown for a tenant's current findings.
type TriageFunnel struct {
	RawFindings      int     `json:"raw_findings"`      // every finding the scanners produced
	Excluded         int     `json:"excluded"`          // dropped by custom exclusion rules
	Deduped          int     `json:"deduped"`           // collapsed as duplicates of another (cross-tool merge)
	Suppressed       int     `json:"suppressed"`        // raw findings behind ignored / accepted-risk issues
	ActionableIssues int     `json:"actionable_issues"` // unified issues a human still triages
	ConfirmedIssues  int     `json:"confirmed_issues"`  // of those, multi-tool-confirmed (≥2 scanners)
	AutoTriaged      int     `json:"auto_triaged"`      // excluded + deduped + suppressed
	AutoTriageRate   float64 `json:"auto_triage_rate"`  // auto_triaged / raw_findings (0..1)
}

// TriageStats computes the funnel from a tenant's raw findings, its exclusion rules, and the
// set of suppressed (ignored) issue keys. The arithmetic is exact and self-consistent:
// raw = excluded + deduped + suppressed + (raw behind actionable issues).
func TriageStats(findings []types.Finding, excl []platform.ExclusionRule, ignoredKeys map[string]bool) TriageFunnel {
	f := TriageFunnel{RawFindings: len(findings)}

	kept := ApplyExclusions(findings, excl)
	f.Excluded = f.RawFindings - len(kept)

	issues := UnifiedIssues(kept)
	// Each kept finding belongs to exactly one issue, so (kept − issues) is the duplicate
	// count collapsed by the cross-tool merge.
	f.Deduped = len(kept) - len(issues)

	for _, is := range issues {
		if ignoredKeys[is.Key] {
			f.Suppressed += is.Count // the raw findings behind a suppressed issue
			continue
		}
		f.ActionableIssues++
		if is.Confirmed {
			f.ConfirmedIssues++
		}
	}

	f.AutoTriaged = f.Excluded + f.Deduped + f.Suppressed
	if f.RawFindings > 0 {
		f.AutoTriageRate = float64(f.AutoTriaged) / float64(f.RawFindings)
	}
	return f
}
