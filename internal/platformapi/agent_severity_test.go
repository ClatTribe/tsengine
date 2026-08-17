package platformapi

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/internal/codeagent"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The agent's PATH is grounded — validatePath proves every edge exists and ends at a crown jewel.
// Its SEVERITY is not: that is free text the model chose. An unrecognised value ("P1", "moderate",
// "sev1") ranks 0, which is BELOW info, and the consequence is not cosmetic:
//
//	Rank 0 < detect's threshold  =>  atOrAbove(high) is false  =>  NO incident opens, nobody is paged.
//
// So a proven route to a crown jewel could be silenced by a spelling. This asserts the CONSEQUENCE,
// not just the string: whatever the model writes, the finding must still cross the incident bar.
func TestAgentSeverity_InvalidCannotSilenceAProvenAttackPath(t *testing.T) {
	for _, modelWrote := range []string{"P1", "moderate", "sev1", "CRITICAL!", "", "  ", "urgent"} {
		t.Run("model wrote "+modelWrote, func(t *testing.T) {
			f := cloudIssueToFinding("f1", cloudagent.Issue{
				Target: "s3://crown", TargetName: "crown", Severity: modelWrote,
				Path: []string{"internet", "s3://crown"},
			})
			if !f.Severity.Valid() {
				t.Fatalf("stored severity %q is not a recognised severity — it ranks 0, below info", f.Severity)
			}
			// The real consequence: it must still open an incident.
			if f.Severity.Rank() < types.SeverityHigh.Rank() {
				t.Errorf("severity %q ranks %d, under the default incident threshold — a proven "+
					"attack path to a crown jewel would page nobody", f.Severity, f.Severity.Rank())
			}
		})
	}
}

// The neutral default on the CODE path is deliberate (never silently escalate an un-graded
// confirmation to High) — so assert it stays valid and mid-ranked rather than becoming High.
func TestAgentSeverity_CodePathKeepsItsNeutralDefault(t *testing.T) {
	for _, modelWrote := range []string{"", "P2", "kinda bad"} {
		f := codeIssueToFinding("f1", "repo/x", codeagent.CodeIssue{Severity: modelWrote, Title: "x"})
		if !f.Severity.Valid() {
			t.Fatalf("code finding severity %q is not recognised (ranks 0, below info)", f.Severity)
		}
		if f.Severity == types.SeverityHigh || f.Severity == types.SeverityCritical {
			t.Errorf("an un-graded confirmation was escalated to %q; the code path defaults neutral by design", f.Severity)
		}
	}
}
