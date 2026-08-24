package platformapi

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/webagent"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// proof_pipeline_behaviour_test.go is the other half of ADR 0029 D1: the structural guard next door
// proves every door CALLS the pipeline; these prove the pipeline does the right thing to the one
// finding class that was skipping it.

// TestProvenExploitGetsItsComplianceMapping is the defect, stated as a test.
//
// A SQL injection the agent actually demonstrated maps to CWE-89, and CWE-89 has a real control nexus
// in every framework that cares about injection. Before this, the finding was stored raw, so
// compliance.map (hook 7) never ran and the control gap never opened — the posture read clean for a
// vulnerability we had just exploited.
func TestProvenExploitGetsItsComplianceMapping(t *testing.T) {
	t.Setenv("TSENGINE_L15_DISABLED", "")
	raw := webFindingToTypes(webagent.Finding{
		ID: "f1", Class: "sqli", Route: "https://app.example.com/search?q=1",
		Rationale: "boolean differential reached the database", Verified: true,
	}, time.Now().UTC())

	if len(raw.CWE) == 0 {
		t.Fatal("precondition: a converted agent finding must carry its CWE, else nothing downstream can map it")
	}
	if raw.Compliance != nil {
		t.Fatalf("precondition: the raw finding should carry no control mapping, got %+v", raw.Compliance)
	}

	got := enrichFindings([]types.Finding{raw})
	if len(got) != 1 {
		t.Fatalf("enrichment must not drop a proven exploit, got %d findings", len(got))
	}
	if c := got[0].Compliance; c == nil || len(c.SOC2)+len(c.NIST80053)+len(c.CISv8)+len(c.ISO27001) == 0 {
		t.Error("a proven SQL injection (CWE-89) came out of the L1.5 chain with NO control mapping.\n" +
			"That is the false-compliant mode ADR 0029 D1a exists to close: the finding is stored and " +
			"visible, and the control gap it should open never opens.")
	}
}

// TestEnrichmentNeverDowngradesAProvenExploit is ADR 0029 D1c.
//
// The chain's confidence hook runs last and stamps verification_status and a confidence scalar on
// everything. A demonstration that actually fired against the live target is the strongest evidence
// this system produces, and the chain must not lower it on the way past — a corroboration heuristic
// does not get to overrule an exploit that worked.
func TestEnrichmentNeverDowngradesAProvenExploit(t *testing.T) {
	t.Setenv("TSENGINE_L15_DISABLED", "")
	proven := webFindingToTypes(webagent.Finding{
		ID: "f2", Class: "sqli", Route: "https://app.example.com/search?q=1",
		Rationale: "boolean differential reached the database", Verified: true,
	}, time.Now().UTC())
	if proven.VerificationStatus != types.VerificationVerified {
		t.Fatalf("precondition: a Verified agent finding must convert to verified, got %q", proven.VerificationStatus)
	}

	got := enrichFindings([]types.Finding{proven})[0]

	if got.VerificationStatus != types.VerificationVerified {
		t.Errorf("the chain downgraded a demonstrated exploit from verified to %q — "+
			"a heuristic must never overrule a predicate that fired", got.VerificationStatus)
	}
	// The chain's own scale caps at 0.99 and floors a verified finding at 0.95, so the exploit must
	// land at the TOP of that band rather than at the unknown-tool default.
	if got.Confidence < 0.95 {
		t.Errorf("a demonstrated exploit came out at confidence %.2f; verified findings floor at 0.95", got.Confidence)
	}
}

// TestUnprovenLeadIsNotTreatedAsProven is the negative that makes the one above mean something.
//
// The same producer emits LEADS it could not demonstrate. If the base confidence for the offensive
// agent were set so high that an unproven lead also came out near-certain, the scale would say
// nothing — which is exactly what would have happened had the fix been "floor everything from this
// tool", instead of giving the tool an honest base.
func TestUnprovenLeadIsNotTreatedAsProven(t *testing.T) {
	t.Setenv("TSENGINE_L15_DISABLED", "")
	lead := webFindingToTypes(webagent.Finding{
		ID: "f3", Class: "sqli", Route: "https://app.example.com/search?q=1",
		Rationale: "parameter looks injectable; no demonstration succeeded", Verified: false,
	}, time.Now().UTC())
	if lead.VerificationStatus == types.VerificationVerified {
		t.Fatal("precondition: an unproven lead must not convert to verified")
	}

	got := enrichFindings([]types.Finding{lead})[0]

	if got.VerificationStatus == types.VerificationVerified {
		t.Error("the chain promoted an UNPROVEN lead to verified — nothing but a demonstration may do that")
	}
	if got.Confidence >= 0.95 {
		t.Errorf("an unproven lead came out at confidence %.2f, inside the verified band. "+
			"A lead and a demonstrated exploit from the same producer must be distinguishable.", got.Confidence)
	}
	// ...and the other direction, which is what makes the confidence-table entry load-bearing rather
	// than decorative. A mutation run proved the entry changed nothing observable while the only
	// assertion here was the ceiling: the verified branch floors a PROVEN finding at 0.95 regardless
	// of base, so the table entry is visible ONLY on an unproven lead. Without it "web-investigate" is
	// an unknown tool at the 0.50 default — below semgrep, for a producer that only reports what a
	// predicate let through.
	if got.Confidence < 0.80 {
		t.Errorf("an unproven lead from the offensive agent came out at confidence %.2f — the "+
			"unknown-tool default. The agent is a known producer and needs an honest base in "+
			"toolBaseConfidence (ADR 0029 D1c).", got.Confidence)
	}
}
