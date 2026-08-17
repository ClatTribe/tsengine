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
		f := codeIssueToFinding("f1", "repo/x", "app/db.go:42", codeagent.CodeIssue{Severity: modelWrote, Title: "x"})
		if !f.Severity.Valid() {
			t.Fatalf("code finding severity %q is not recognised (ranks 0, below info)", f.Severity)
		}
		if f.Severity == types.SeverityHigh || f.Severity == types.SeverityCritical {
			t.Errorf("an un-graded confirmation was escalated to %q; the code path defaults neutral by design", f.Severity)
		}
	}
}

// "verified" is defined as independent method(s) ACTIVELY confirming a finding (re-fire via
// tool-replay), and the L1.5 confidence hook acts on that definition by flooring confidence at 0.95
// ("actively re-fired"). The two agents earn different tiers, and the distinction is the product's
// no-FP bar, so pin it:
//
//   - CLOUD: validatePath deterministically re-checks every edge against the inventory and requires a
//     crown-jewel endpoint. An evaluator confirms it, not the model → verified.
//   - CODE:  evidenceGrounded proves the agent READ real source at real path:line, but exploitability
//     is the model's judgment, re-confirmed by nothing → corroborated.
//
// Claiming "verified" for the code path would inflate a model judgement to 0.95+ confidence on a
// label it did not earn.
func TestAgentFindings_VerificationTierMatchesWhatWasProven(t *testing.T) {
	cloud := cloudIssueToFinding("f1", cloudagent.Issue{
		Target: "s3://crown", Severity: "high", Path: []string{"internet", "s3://crown"},
	})
	if cloud.VerificationStatus != types.VerificationVerified {
		t.Errorf("cloud attack path = %q, want verified — every edge is deterministically re-checked",
			cloud.VerificationStatus)
	}

	code := codeIssueToFinding("f2", "repo/x", "app/db.go:42", codeagent.CodeIssue{
		Severity: "high", Title: "sqli", Exploitable: true,
		Evidence: []string{"app/db.go:42"},
	})
	if code.VerificationStatus == types.VerificationVerified {
		t.Error("code assessment claims VERIFIED, but nothing actively re-confirmed exploitability — " +
			"that inflates a model judgement to the 0.95 confidence floor reserved for re-fired findings")
	}
	if code.VerificationStatus != types.VerificationCorroborated {
		t.Errorf("code assessment = %q, want corroborated (the L1 hit + an independent read of the "+
			"real source agreeing, with nothing re-fired)", code.VerificationStatus)
	}
}

// A finding's ENDPOINT is its identity (detect.Key = RuleID|Endpoint), so it must be deterministic.
// If it came from the agent's free-text FixLocation, the same vulnerability re-assessed later — with
// the location phrased differently — would get a DIFFERENT key, and two things break silently:
//
//   - the incident churns: the old one resolves and a new one opens, re-paging the on-call;
//   - retest.Verify sees the old key ABSENT and reports the fix CONFIRMED, while the vulnerability
//     is still sitting there.
//
// So identity comes from the scanner's endpoint; the model's phrasing stays descriptive.
func TestCodeFindingIdentity_IsStableAcrossModelPhrasing(t *testing.T) {
	l1 := "app/db.go:42" // what the scanner produced — the same on every run
	var keys []string
	for _, modelSaid := range []string{"app/db.go:42", "app/db.go:41", "internal/app/db.go:42", ""} {
		f := codeIssueToFinding("f1", "repo/x", l1, codeagent.CodeIssue{
			FindingID: "sem-1", Severity: "high", Title: "sqli", Exploitable: true,
			FixLocation: modelSaid, Evidence: []string{"app/db.go:42"},
		})
		keys = append(keys, string(f.RuleID)+"|"+f.Endpoint)
	}
	for i := 1; i < len(keys); i++ {
		if keys[i] != keys[0] {
			t.Fatalf("identity moved with the model's wording: %q vs %q — the incident would churn and "+
				"retest would report a phantom fix", keys[i], keys[0])
		}
	}
	if keys[0] != "codeagent::confirmed-exploitable::sem-1|app/db.go:42" {
		t.Errorf("unexpected key %q — identity should be the scanner's endpoint", keys[0])
	}
}

// Two DIFFERENT proven routes to the SAME crown jewel must not collapse into one finding. detect.Key
// is RuleID|Endpoint and the endpoint is the crown jewel, so with a constant rule id the second route
// silently masked the first in incidents and unified issues — the customer would see one attack path
// and fix it, while a second proven route to the same asset stayed open and invisible.
//
// The route must also stay STABLE across runs: same route, same key, or every scan churns the
// incident (the agent's own ai-NNN counter is per-run sequential and would do exactly that).
func TestCloudFindingIdentity_DistinctRoutesStayDistinctAndStable(t *testing.T) {
	crown := "arn:aws:s3:::crown"
	viaEC2 := cloudagent.Issue{Target: crown, Severity: "high",
		Path: []string{"internet", "i-web", "role/app", crown}}
	viaKey := cloudagent.Issue{Target: crown, Severity: "high",
		Path: []string{"internet", "repo/leaked-key", "role/ci", crown}}

	key := func(is cloudagent.Issue) string {
		f := cloudIssueToFinding("x", is)
		return string(f.RuleID) + "|" + f.Endpoint
	}

	if key(viaEC2) == key(viaKey) {
		t.Fatalf("two distinct routes to %s share one key %q — the second masks the first and a proven "+
			"attack path disappears from incidents", crown, key(viaEC2))
	}
	// Stability: the same route re-recorded (a later scan, a new ai-NNN id) keeps its identity.
	if key(viaEC2) != key(viaEC2) {
		t.Error("identity is not deterministic for the same route")
	}
	again := cloudagent.Issue{Target: crown, Severity: "critical", // severity may change; route did not
		Path: []string{"internet", "i-web", "role/app", crown}}
	if key(again) != key(viaEC2) {
		t.Errorf("the same route changed identity across runs (%q vs %q) — every scan would resolve and "+
			"reopen the incident", key(again), key(viaEC2))
	}
}
