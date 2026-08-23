package platformapi

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func deniedIssue() cloudagent.Issue {
	return cloudagent.Issue{
		Target: "arn:aws:s3:::crown", Severity: "critical",
		AuthorizationCoverage: "1/2",
		ProofPlan: &cloudagent.AuthorizationProofPlan{
			Status: cloudagent.PathDenied, Confirmed: 1, Required: 2,
			Checks: []cloudagent.RequiredCheck{
				{From: "ec2", To: "role", Kind: "assume_role", Status: cloudagent.HopConfirmed},
				{From: "role", To: "arn:aws:s3:::crown", Kind: "has_access", Status: cloudagent.HopDenied,
					Detail: "explicit deny (DenyExports)"},
			},
		},
	}
}

// A path the provider REFUSED is a state the rung line could not previously express, because the
// ratio it read had no way to represent a denial. It is the state that matters most: rendering
// "1/2 confirmed" presents authoritative evidence AGAINST the path as partial progress toward it.
func TestAuthorizationRungLine_ARefusedPathSaysSo(t *testing.T) {
	desc := cloudIssueToFinding("f1", deniedIssue(), nil).Description
	if !strings.Contains(desc, "REFUSED") {
		t.Fatalf("a provider refusal is not stated:\n%s", desc)
	}
	if strings.Contains(desc, "provider-confirmed authorization") {
		t.Fatalf("a refused path is described as confirmed:\n%s", desc)
	}
	// C3: a deny is authoritative for that tuple and route only. Claiming the target is unreachable
	// would be the same overclaim pointed the other way.
	if !strings.Contains(desc, "another path") {
		t.Errorf("the refusal does not say it proves nothing about alternative routes:\n%s", desc)
	}
}

// A refusal must not be filed as "corroborated". That tier means two independent assessments AGREE —
// here they DISAGREE: our graph says the route exists, the provider says a required hop is shut.
// Reporting disagreement as corroboration inverts the ladder.
func TestVerificationStatus_ARefusedPathIsNotCorroborated(t *testing.T) {
	got := cloudIssueToFinding("f1", deniedIssue(), nil).VerificationStatus
	if got == types.VerificationCorroborated {
		t.Fatal("a path the provider refused was filed as corroborated — that reports disagreement as agreement")
	}
	if got != types.VerificationPatternMatch {
		t.Fatalf("verification = %q, want pattern_match (the floor)", got)
	}
}

// The mirror: a genuinely partial proof — some hops confirmed, none denied — is still corroborated
// and still says "PARTIAL". Trading a false confirmation for never reporting real partial evidence
// is the same failure reversed.
func TestVerificationStatus_APartialProofIsStillCorroborated(t *testing.T) {
	is := cloudagent.Issue{
		Target: "arn:aws:s3:::crown", Severity: "critical", AuthorizationCoverage: "1/2",
		ProofPlan: &cloudagent.AuthorizationProofPlan{Status: cloudagent.PathPartial, Confirmed: 1, Required: 2},
	}
	f := cloudIssueToFinding("f1", is, nil)
	if f.VerificationStatus != types.VerificationCorroborated {
		t.Fatalf("verification = %q, want corroborated", f.VerificationStatus)
	}
	if !strings.Contains(f.Description, "PARTIAL") {
		t.Errorf("a partial proof stopped saying so:\n%s", f.Description)
	}
}
