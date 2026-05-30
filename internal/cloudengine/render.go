package cloudengine

import (
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// RenderAssessment formats the dual-view assessment for the terminal: the
// "engineer says" attack paths (with impact, validation rung, remediation) and
// the FP-reduction (prowler findings downgraded as config-bad-but-inert).
func RenderAssessment(a *types.AIAssessment) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== AI Cloud Security Engineer — assessment ===\n")
	fmt.Fprintf(&b, "snapshot: %s\n", a.SnapshotHash)
	fmt.Fprintf(&b, "attack paths (real impact): %d   |   prowler findings downgraded (inert): %d\n\n",
		len(a.Paths), len(a.Downgraded))

	for _, p := range a.Paths {
		fmt.Fprintf(&b, "[%s] impact=%.2f  rung=%d  conf=%.2f  status=%s\n",
			p.ID, p.RealImpact.Score, p.RungReached, p.Confidence, p.Verification)
		fmt.Fprintf(&b, "  path: %s\n", p.Narrative)
		if len(p.Corroborates) > 0 {
			fmt.Fprintf(&b, "  chains prowler findings: %s\n", strings.Join(p.Corroborates, ", "))
		}
		if p.Remediation != "" {
			fmt.Fprintf(&b, "  fix:  %s\n", p.Remediation)
		}
		if c := p.Compliance; c != nil {
			fmt.Fprintf(&b, "  violates: SOC2 %v · PCI %v · CIS-v8 %v · NIST-CSF %v\n",
				c.SOC2, c.PCI, c.CISv8, c.NISTCSF)
		}
		fmt.Fprintf(&b, "  evidence: %d step(s) replayable vs the snapshot\n\n", len(p.Evidence))
	}
	if len(a.Downgraded) > 0 {
		fmt.Fprintf(&b, "downgraded (config-bad but not on any reachable path): %s\n",
			strings.Join(a.Downgraded, ", "))
	}
	if len(a.PendingValidations) > 0 {
		fmt.Fprintf(&b, "pending human-gated active validation (rung 5): %d\n", len(a.PendingValidations))
	}
	return b.String()
}
