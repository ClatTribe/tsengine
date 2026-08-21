package bench

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// Score is the outcome of scoring one scan against one fixture.
type Score struct {
	Fixture            string   `json:"fixture"`
	Metric             string   `json:"metric"`
	RawFindings        int      `json:"raw_findings"`
	EnrichedCount      int      `json:"enriched_findings"`
	DetectionRecall    float64  `json:"detection_recall"`
	Matched            []string `json:"matched,omitempty"`
	Missed             []string `json:"missed,omitempty"`
	FalsePositives     []string `json:"false_positives,omitempty"`
	FalsePositiveCount int      `json:"false_positive_count"`
	EnrichmentCov      float64  `json:"enrichment_coverage"`
	Pass               bool     `json:"pass"`
	FailReason         string   `json:"fail_reason,omitempty"`

	// Truncated mirrors types.Scan.Partial: the scan hit its deadline and the
	// finding set is whatever had landed by then.
	Truncated bool `json:"truncated,omitempty"`
	// ToolsFailed names tools that were dispatched and produced no result. Same
	// consequence as truncation: the finding set is incomplete.
	ToolsFailed []string `json:"tools_failed,omitempty"`
	// Unmeasured means the verdict was WITHHELD because truncation could have
	// manufactured it. Distinct from Pass=false: a fail is a statement about the
	// product, this is a statement about the run. See withholdIfTruncated.
	Unmeasured       bool   `json:"unmeasured,omitempty"`
	UnmeasuredReason string `json:"unmeasured_reason,omitempty"`
}

// ScoreScan evaluates a scan against a fixture. Detection is scored on
// findings_raw (L1's job — the security-engineer dashboard). Enrichment
// coverage is scored on findings_enriched (L1.5's job).
//
// The detected set is the union of finding rule_ids; a must_find entry
// matches if it's a substring of any rule_id. This is deliberately
// generic — a CVE id is a substring of "<tool>::<cve>", a rule name is a
// substring of its namespaced rule_id, etc. — so the scorer never needs
// to know what kind of target it's looking at. All SUT-specific values
// live in fixture data, never here (enforced by guard_test.go).
func ScoreScan(f *Fixture, scan *types.Scan) Score {
	s := Score{
		Fixture:       f.Name,
		Metric:        f.Metric,
		RawFindings:   len(scan.FindingsRaw),
		EnrichedCount: len(scan.FindingsEnriched),
	}

	detected := ruleIDSet(scan.FindingsRaw)

	// Detection recall over must_find.
	for _, want := range f.MustFind {
		if anyContains(detected, want) {
			s.Matched = append(s.Matched, want)
		} else {
			s.Missed = append(s.Missed, want)
		}
	}
	if len(f.MustFind) > 0 {
		s.DetectionRecall = float64(len(s.Matched)) / float64(len(f.MustFind))
	} else {
		s.DetectionRecall = 1.0 // nothing required → trivially complete
	}

	// False positives over must_not_find (specific rule_ids that must not appear).
	for _, bad := range f.MustNotFind {
		if anyContains(detected, bad) {
			s.FalsePositives = append(s.FalsePositives, bad)
		}
	}

	// Severity-gated false positives (FP-control / benign fixtures): on a
	// target that should be clean, any raw finding at or above the fixture's
	// FP severity floor is an unexpected actionable alarm. Robust where
	// MaxFindings is brittle — a clean target may legitimately emit info notes.
	if f.MaxSeverity != "" {
		floor := f.MaxSeverity.Rank()
		for _, fnd := range scan.FindingsRaw {
			if fnd.Severity.Rank() >= floor {
				s.FalsePositives = append(s.FalsePositives, fmt.Sprintf("%s [%s]", fnd.RuleID, fnd.Severity))
			}
		}
	}
	s.FalsePositiveCount = len(s.FalsePositives)

	s.EnrichmentCov = enrichmentCoverage(scan.FindingsEnriched)

	s.Truncated = scan.Partial
	for _, tf := range scan.ToolsFailed {
		s.ToolsFailed = append(s.ToolsFailed, tf.Tool)
	}
	s.Pass, s.FailReason = passes(f, s)
	withholdIfIncomplete(f, &s)
	return s
}

// withholdIfIncomplete refuses the verdicts an incomplete run could have manufactured.
//
// This exists because it happened. An api-asset run was recorded as a recall of
// 0.000 with a FAIL verdict and very nearly reached the scoreboard as a
// capability result. The scan had printed partial=true; re-run with a budget it
// could finish in, the same target on the same image found the required finding
// and scored 1.000. Nothing was wrong with the engine — the clock ran out
// mid-tool, and the scorer had no idea the run had been cut off.
//
// The rule is NOT "a truncated scan cannot be scored", because truncation is
// DIRECTIONAL: a scan that stops early can only ever have FEWER findings than one
// that finishes. So each metric has exactly one verdict truncation can fake, and
// only that one is withheld:
//
//   - must_find_recall: a FAIL is suspect (the missing finding may simply not have
//     landed yet) — a PASS is real, since it found what was required despite being
//     cut short.
//   - fp_rate: a PASS is suspect (the false positive may not have landed yet) — a
//     FAIL is real, since the alarm did fire.
//
// Withholding both directions would throw away sound results; withholding neither
// is how a clock gets published as a capability. An Unmeasured score is not a
// fail: it says the run cannot answer the question, which is the same distinction
// the ip/naabu row makes between "we looked and found nothing" and "we could not
// look".
func withholdIfIncomplete(f *Fixture, s *Score) {
	// TWO CAUSES, ONE CONSEQUENCE. A scan that hit its deadline and a scan whose
	// tool crashed are different events with the same effect on the numbers: the
	// finding set is short by an unknown amount. The second is not hypothetical —
	// a sandbox image built without an asset's toolset stubs the missing binary to
	// exit 127, so an ip-asset run in a container/repository/web/api image fails
	// naabu and scores 0.000 while the port is wide open and nmap can see it.
	// Handling only the deadline would leave that one to be caught by a human
	// reading the log, which is how it was caught the first time.
	var cause string
	switch {
	case s.Truncated:
		cause = "scan hit its deadline (partial)"
	case len(s.ToolsFailed) > 0:
		cause = fmt.Sprintf("tool(s) dispatched but produced no result: %s", strings.Join(s.ToolsFailed, ", "))
	default:
		return
	}
	switch {
	case !s.Pass && s.DetectionRecall < f.PassRecall:
		s.Unmeasured = true
		s.UnmeasuredReason = fmt.Sprintf("%s, so recall %.2f is a LOWER BOUND — the missed "+
			"item(s) %q may never have had the chance to appear. Fix the run before treating "+
			"this as a detection gap.", cause, s.DetectionRecall, strings.Join(s.Missed, ", "))
	case s.Pass && f.MaxSeverity != "":
		s.Unmeasured = true
		s.UnmeasuredReason = cause + ", so a clean FP-control result proves nothing — an alarm " +
			"at or above the severity floor may never have had the chance to fire."
	}
	// An unmeasured run is never a pass. It is not a fail either, and the verdict
	// line says so — but nothing downstream may read it as a green tick, because
	// the whole point is that this run cannot answer the question.
	if s.Unmeasured {
		s.Pass = false
	}
}

func passes(f *Fixture, s Score) (bool, string) {
	if s.DetectionRecall < f.PassRecall {
		return false, fmt.Sprintf("recall %.2f < required %.2f (missed: %s)",
			s.DetectionRecall, f.PassRecall, strings.Join(s.Missed, ", "))
	}
	if len(s.FalsePositives) > 0 {
		return false, "false positives: " + strings.Join(s.FalsePositives, ", ")
	}
	if f.MaxFindings != nil && s.RawFindings > *f.MaxFindings {
		return false, fmt.Sprintf("%d findings exceeds max %d", s.RawFindings, *f.MaxFindings)
	}
	return true, ""
}

// enrichmentCoverage is the fraction of enriched findings carrying at
// least one L1.5 annotation. It's the headline L1.5-lift metric: with
// TSENGINE_L15_DISABLED=1 it collapses to 0 (CLAUDE.md §14.1).
func enrichmentCoverage(findings []types.Finding) float64 {
	if len(findings) == 0 {
		return 0
	}
	annotated := 0
	for _, f := range findings {
		if f.SurfacePriority != nil || f.Exploitability != nil ||
			f.ThreatIntel != nil || f.Compliance != nil || len(f.CorroboratedBy) > 0 {
			annotated++
		}
	}
	return float64(annotated) / float64(len(findings))
}

func ruleIDSet(findings []types.Finding) []string {
	out := make([]string, 0, len(findings))
	for _, f := range findings {
		out = append(out, f.RuleID)
	}
	sort.Strings(out)
	return out
}

func anyContains(haystacks []string, needle string) bool {
	for _, h := range haystacks {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}
