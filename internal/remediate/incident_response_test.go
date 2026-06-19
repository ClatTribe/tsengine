package remediate

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// byKind returns the first action of a kind, for assertions over the response set.
func byKind(acts []platform.Action, kind string) (platform.Action, bool) {
	for _, a := range acts {
		if a.Kind == kind {
			return a, true
		}
	}
	return platform.Action{}, false
}

// A critical incident yields BOTH a gated containment runbook AND a T3 breach-disclosure
// that requires a human signature; the draft is grounded (cites the real rule + finding).
func TestProposeIncidentResponse_CriticalDraftsT3(t *testing.T) {
	inc := platform.Incident{
		ID: "inc-1", TenantID: "t", RuleID: "nuclei::rce", Title: "RCE on /api/exec",
		Key: "nuclei::rce|https://api.northwind.io/api/exec", Severity: "critical", FindingID: "f-9",
		OpenedAt: time.Unix(1700000000, 0).UTC(),
	}
	acts, ok := ProposeIncidentResponse(inc, func() string { return "1" })
	if !ok || len(acts) != 2 {
		t.Fatalf("a critical incident should yield containment + disclosure, got ok=%v n=%d", ok, len(acts))
	}
	act, found := byKind(acts, platform.ActDraftNotification)
	if !found || act.Tier != platform.TierIrreversible || !act.NeedsHumanSignature() {
		t.Fatalf("must include a T3 breach draft requiring a human signature, got %+v", act)
	}
	draft, _ := act.Payload["draft"].(string)
	for _, want := range []string{"DRAFT", "SIGN", "nuclei::rce", "f-9", "do NOT send unverified"} {
		if !strings.Contains(draft, want) {
			t.Errorf("draft missing %q:\n%s", want, draft)
		}
	}
}

// The containment action is gated (tier-2 → human approves before anything happens), names
// the affected entity from the incident key, and chooses a class-appropriate runbook.
func TestProposeIncidentResponse_CriticalContains(t *testing.T) {
	cases := []struct{ rule, key, wantStep string }{
		{"operate::admin-without-mfa", "operate::admin-without-mfa|ana@northwind.io", "Suspend the affected account"},
		{"prowler::s3-public-bucket", "prowler::s3-public-bucket|arn:aws:s3:::invoices", "Restrict the exposed resource"},
		{"nuclei::sqli", "nuclei::sqli|https://api/search", "Block the affected endpoint"},
	}
	for _, c := range cases {
		acts, ok := ProposeIncidentResponse(platform.Incident{
			TenantID: "t", RuleID: c.rule, Key: c.key, Severity: "critical", FindingID: "f-1", Title: "x",
		}, func() string { return "1" })
		if !ok {
			t.Fatalf("%s: expected a response", c.rule)
		}
		con, found := byKind(acts, platform.ActFileTicket)
		if !found {
			t.Fatalf("%s: expected a containment action", c.rule)
		}
		if con.Tier != platform.GateTier || !con.NeedsApproval() {
			t.Errorf("%s: containment must be human-gated (tier %d), got tier %d", c.rule, platform.GateTier, con.Tier)
		}
		if con.Payload["remediation_type"] != "containment" {
			t.Errorf("%s: containment payload missing remediation_type, got %+v", c.rule, con.Payload)
		}
		runbook, _ := con.Payload["runbook"].(string)
		if !strings.Contains(runbook, c.wantStep) {
			t.Errorf("%s: runbook %q should contain %q", c.rule, runbook, c.wantStep)
		}
		// the entity from the key must be named in the runbook
		if ep := c.key[strings.Index(c.key, "|")+1:]; !strings.Contains(runbook, ep) {
			t.Errorf("%s: runbook should name the entity %q: %s", c.rule, ep, runbook)
		}
	}
}

// Non-critical incidents do NOT trigger incident-response actions — they flow through the
// normal per-finding remediation path.
func TestProposeIncidentResponse_NonCriticalSkips(t *testing.T) {
	for _, sev := range []string{"high", "medium", "low", "info", ""} {
		if _, ok := ProposeIncidentResponse(platform.Incident{TenantID: "t", Severity: sev}, nil); ok {
			t.Errorf("a %q incident must not trigger incident response", sev)
		}
	}
}
