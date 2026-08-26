package codesweep

import (
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Findings converts a sweep Result into dashboard findings. Exported from the
// package (moved from platformapi) so BOTH the on-demand endpoint and the
// repository scan-path stage (ADR 0032 D1) project results identically — two
// converters would drift, and a drift in the coverage-disclosure half is exactly
// how a capped sweep starts reading as an exhaustive one.
//
// Unchanged semantics: only Vulnerable candidates become findings; every finding
// is VerificationPatternMatch with the rung stated in prose; a capped sweep emits
// a coverage:: disclosure naming what was not swept.
func Findings(res Result, repo string, now time.Time) []types.Finding {
	var out []types.Finding
	for i, c := range res.Candidates {
		if !c.Vulnerable {
			continue
		}
		out = append(out, types.Finding{
			ID:       fmt.Sprintf("codesweep-%03d", i+1),
			RuleID:   "codesweep::" + strings.ToLower(strings.TrimSpace(c.CWE)),
			Tool:     "codesweep",
			Severity: types.Severity(strings.ToLower(strings.TrimSpace(c.Severity))),
			CWE:      []string{c.CWE},
			Title:    c.Title,
			Endpoint: c.Path,
			// The rung is stated in the text as well as the field, because a reader sees the text.
			Description: c.Rationale + "\n\nProposed by the AI code engineer reading this file, not by " +
				"a scanner: the cited location was confirmed to exist, and nothing was executed to " +
				"prove the weakness is reachable. Treat it as a lead to confirm.",
			// pattern_match, never verified: in this codebase "verified" means a predicate RAN.
			VerificationStatus: types.VerificationPatternMatch,
			DiscoveredAt:       now,
			ToolArgs:           map[string]string{"repo": repo, "evidence": strings.Join(c.Evidence, ", ")},
		})
	}
	// A capped sweep is not an exhaustive one, and the difference is invisible in a result list.
	if res.Planned > res.Ran {
		out = append(out, types.Finding{
			ID:       "codesweep-coverage",
			RuleID:   asset.CoverageRulePrefix + "codesweep-partial",
			Tool:     "codesweep",
			Severity: types.SeverityInfo,
			Title:    fmt.Sprintf("codesweep was capped: %d of %d planned question(s) ran", res.Ran, res.Planned),
			Description: fmt.Sprintf(
				"Only %d of %d planned question(s) ran before the cap. The un-run questions are "+
					"DISCLOSED here rather than silently dropped — this scan is NOT an exhaustive "+
					"review of the flagged files.",
				res.Ran, res.Planned),
			DiscoveredAt: now,
			ToolArgs:     map[string]string{"repo": repo, "planned": fmt.Sprint(res.Planned), "ran": fmt.Sprint(res.Ran)},
		})
	}
	return out
}
