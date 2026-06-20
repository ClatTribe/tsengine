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

	s.Pass, s.FailReason = passes(f, s)
	return s
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
