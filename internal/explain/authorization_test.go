package explain

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

const provenPhrase = "we proved it is exploitable"

func reasons(e Explanation) string { return strings.Join(e.Because, " | ") }

// A cloud attack path can reach types.VerificationVerified honestly — the provider's own policy
// simulator was called per hop and allowed every one. That is CONFIRMED ACCESS. It is not an
// exploit: nothing was sent to the target, no access was used, and network reachability, credential
// acquisition and unsupplied session context all stay unproven (ADR 0024 C1).
//
// Saying it in the words reserved for a captured proof-of-concept is the overclaim this guard
// exists to prevent, and the assessor allowlist did not catch it because a cloud path is not an
// assessor — it gets translated normally, only its urgency SENTENCE differs.
func TestUrgency_ProviderConfirmedAuthorizationIsNotADemonstratedExploit(t *testing.T) {
	e := Explain(types.Finding{
		Tool: "cloudagent", RuleID: "cloudpath::internet->role->s3", Severity: types.SeverityCritical,
		Endpoint: "arn:aws:s3:::customer-exports", Title: "customer-exports — reachable attack path",
		VerificationStatus: types.VerificationVerified,
	}, Context{})

	if strings.Contains(reasons(e), provenPhrase) {
		t.Fatalf("a provider AUTHORIZATION confirmation is rendered as a demonstrated exploit: %q", reasons(e))
	}
	if !strings.Contains(reasons(e), "policy simulator") {
		t.Fatalf("the confirmation is real evidence and must still be stated, in its own words: %q", reasons(e))
	}
	// The rank does not move. An authority confirming an attacker holds every permission on a route
	// to a crown jewel is not next week's problem; only the wording changes.
	if e.Urgency != UrgencyNow {
		t.Fatalf("urgency = %q, want %q — softening the claim must not soften the priority", e.Urgency, UrgencyNow)
	}
}

// The floor, and the case that was actually shipping: a path resting on our own inventory, which
// after the R1 fix no longer even reaches the verified tier. Belt and braces — if a future change
// re-stamps it verified, this still refuses the exploit wording.
func TestUrgency_ConfigPossibleCloudPathClaimsNothing(t *testing.T) {
	for _, st := range []types.VerificationState{
		types.VerificationPatternMatch, types.VerificationCorroborated, types.VerificationVerified,
	} {
		e := Explain(types.Finding{
			Tool: "cloudagent", Severity: types.SeverityCritical, Endpoint: "arn:aws:s3:::crown",
			Title: "crown — reachable attack path", VerificationStatus: st,
		}, Context{})
		if strings.Contains(reasons(e), provenPhrase) {
			t.Fatalf("status %q: cloud path claims a demonstrated exploit: %q", st, reasons(e))
		}
	}
}

// The control, and the thing this must not break. A real exploit still says so — trading a false
// proof claim for never making a true one is the same failure pointed the other way.
func TestUrgency_ARealExploitStillSaysItWasProven(t *testing.T) {
	e := Explain(types.Finding{
		Tool: "pentest", RuleID: "pentest::sqli-boolean", Severity: types.SeverityCritical,
		Endpoint: "https://api.example.com/v2/search?q=", Title: "SQL injection — exploitation-proven",
		VerificationStatus: types.VerificationVerified,
	}, Context{})
	if !strings.Contains(reasons(e), provenPhrase) {
		t.Fatalf("the pentester ran the exploit and the explanation no longer says so: %q", reasons(e))
	}
}
