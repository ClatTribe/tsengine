package platformapi

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudagent"
)

// The AI Cloud Engineer computes which rung of the verification ladder each path stands on
// (ADR 0024 P1). Both fields were dropped when the Issue became a stored Finding, so the strongest
// evidence this agent can produce never left the agent struct — the store, issues, incidents, GRC
// and the UI all saw a provider-confirmed path and a purely config-possible one as identical.
func TestCloudIssueToFinding_CarriesTheAuthorizationRung(t *testing.T) {
	is := cloudagent.Issue{
		Target: "arn:aws:iam::1:role/admin", TargetName: "admin", Severity: "high",
		Path:              []string{"a", "b"},
		ProviderConfirmed: true, AuthorizationCoverage: "2/2",
	}
	f := cloudIssueToFinding("f-1", is)

	var raw map[string]any
	if err := json.Unmarshal(f.RawOutput, &raw); err != nil {
		t.Fatalf("raw output must stay valid JSON: %v", err)
	}
	if raw["provider_confirmed"] != true {
		t.Errorf("the persisted finding must carry provider_confirmed, got %v", raw["provider_confirmed"])
	}
	if raw["authorization_coverage"] != "2/2" {
		t.Errorf("the persisted finding must carry the hop coverage, got %v", raw["authorization_coverage"])
	}
	// The machine-readable half is not enough: a human reads the description.
	if !strings.Contains(f.Description, "provider-confirmed authorization") {
		t.Errorf("description must state the rung, got: %s", f.Description)
	}
	if !strings.Contains(f.Description, "not exploitability") {
		t.Errorf("a provider-confirmed path must still disclaim exploitability (C1), got: %s", f.Description)
	}
}

// A PARTIAL proof is the case that most needs saying: real evidence, but not the complete claim.
// Collapsing it into a bare "not confirmed" loses it; rendering it as confirmed overclaims it.
func TestCloudIssueToFinding_PartialProofStaysVisibleAndIsNotAConfirmation(t *testing.T) {
	is := cloudagent.Issue{Target: "t", Severity: "high", ProviderConfirmed: false, AuthorizationCoverage: "2/5"}
	f := cloudIssueToFinding("f-2", is)
	if !strings.Contains(f.Description, "PARTIAL") || !strings.Contains(f.Description, "2/5") {
		t.Fatalf("a partial proof must be stated with its real coverage, got: %s", f.Description)
	}
	if strings.Contains(f.Description, "provider-confirmed authorization (") {
		t.Errorf("a partial proof must NOT read as a complete confirmation, got: %s", f.Description)
	}
}

// No dry-run ran. "We could not look" must not render as "we looked and it is closed" — and must not
// render as nothing either, because silence is read as the stronger claim.
func TestCloudIssueToFinding_ConfigPossibleSaysSoAndIsNotADenial(t *testing.T) {
	f := cloudIssueToFinding("f-3", cloudagent.Issue{Target: "t", Severity: "high"})
	if !strings.Contains(f.Description, "config-possible") {
		t.Fatalf("an unprobed path must say it is config-possible, got: %s", f.Description)
	}
	if !strings.Contains(f.Description, "not the same as the path being denied") {
		t.Errorf("absence of a provider confirmation is not evidence of closure (§10), got: %s", f.Description)
	}
}

// The class-level property: the three rungs must be DISTINGUISHABLE in the rendered prose. Rendering
// any two alike is the defect itself — it is how a partial or unproven claim acquires the authority
// of a confirmed one.
func TestAuthorizationRungLine_ThreeRungsRenderDifferently(t *testing.T) {
	confirmed := authorizationRungLine(cloudagent.Issue{ProviderConfirmed: true, AuthorizationCoverage: "3/3"})
	partial := authorizationRungLine(cloudagent.Issue{AuthorizationCoverage: "1/3"})
	none := authorizationRungLine(cloudagent.Issue{})
	for _, s := range []string{confirmed, partial, none} {
		if strings.TrimSpace(s) == "" {
			t.Fatal("every rung must render something; silence is read as the strongest claim")
		}
	}
	if confirmed == partial || partial == none || confirmed == none {
		t.Fatalf("the three rungs must be distinguishable:\n confirmed=%q\n partial=%q\n none=%q", confirmed, partial, none)
	}
	// A zero-hop path has nothing to be partial about: it is unprobed, not partially proven.
	if got := authorizationRungLine(cloudagent.Issue{AuthorizationCoverage: "0/0"}); got != none {
		t.Errorf("0/0 must read as unprobed, not as a partial proof: %s", got)
	}
}
