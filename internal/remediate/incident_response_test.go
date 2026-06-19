package remediate

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// A critical incident drafts a T3 breach-disclosure that requires a human signature, and
// the draft is grounded (cites the real rule + finding) and clearly marked unverified.
func TestProposeIncidentResponse_CriticalDraftsT3(t *testing.T) {
	inc := platform.Incident{
		ID: "inc-1", TenantID: "t", RuleID: "nuclei::rce", Title: "RCE on /api/exec",
		Severity: "critical", FindingID: "f-9", OpenedAt: time.Unix(1700000000, 0).UTC(),
	}
	act, ok := ProposeIncidentResponse(inc, func() string { return "1" })
	if !ok {
		t.Fatal("a critical incident should draft a response")
	}
	if act.Kind != platform.ActDraftNotification || act.Tier != platform.TierIrreversible {
		t.Fatalf("must be a T3 ActDraftNotification, got %s tier %d", act.Kind, act.Tier)
	}
	if !act.NeedsHumanSignature() {
		t.Error("a breach-disclosure draft must require a human signature")
	}
	draft, _ := act.Payload["draft"].(string)
	for _, want := range []string{"DRAFT", "SIGN", "nuclei::rce", "f-9", "do NOT send unverified"} {
		if !strings.Contains(draft, want) {
			t.Errorf("draft missing %q:\n%s", want, draft)
		}
	}
}

// Non-critical incidents do NOT trigger breach comms — they flow through normal remediation.
func TestProposeIncidentResponse_NonCriticalSkips(t *testing.T) {
	for _, sev := range []string{"high", "medium", "low", "info", ""} {
		if _, ok := ProposeIncidentResponse(platform.Incident{TenantID: "t", Severity: sev}, nil); ok {
			t.Errorf("a %q incident must not draft a breach disclosure", sev)
		}
	}
}
