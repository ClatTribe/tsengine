package remediate

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func workspaceAsset() platform.Asset {
	return platform.Asset{TenantID: "t1", ConnectionID: "conn-okta", Type: "workspace", Target: "acme-okta",
		Meta: map[string]string{"provider": platform.ConnOkta}}
}

// A stale Okta account has a LIVE write path (connector.Okta.Apply suspends it), so it is
// proposed as a tier-2 ActApplyConfig — a gated auto-remediation the human approves, not a
// runbook ticket. This is the non-tech autonomous-with-approval loop (GAP-1).
func TestPropose_OktaStaleAccountIsGatedMutation(t *testing.T) {
	f := types.Finding{ID: "op-7", RuleID: "operate::stale-account", Severity: types.SeverityHigh,
		Title: "Stale active account: bob@acme.com", Endpoint: "bob@acme.com"}
	act, ok := Propose(f, workspaceAsset(), func() string { return "1" })
	if !ok {
		t.Fatal("stale-account should produce an action")
	}
	if act.Kind != platform.ActApplyConfig || act.Tier != tierApplyConfig {
		t.Fatalf("a live identity mutation must be a tier-2 ActApplyConfig, got %s tier %d", act.Kind, act.Tier)
	}
	if !act.NeedsApproval() {
		t.Error("a live account suspend must be human-gated")
	}
	if act.ConnectionID != "conn-okta" {
		t.Errorf("gated action must route to the Okta connection, got %q", act.ConnectionID)
	}
	if act.Payload["remediation_type"] != "account_suspend" || act.Payload["target"] != "bob@acme.com" {
		t.Errorf("payload must carry the machine-readable suspend + target: %+v", act.Payload)
	}
}

// The SAME stale-account finding on a provider with no live suspend path (Google
// Workspace today) stays a tier-1 runbook ticket — no falsely-confident gated mutation
// that would error after a human approves it.
func TestPropose_StaleAccountStaysTicketWithoutLivePath(t *testing.T) {
	gw := platform.Asset{TenantID: "t1", ConnectionID: "conn-gw", Type: "workspace", Target: "acme.com",
		Meta: map[string]string{"provider": platform.ConnGWorkspace}}
	f := types.Finding{ID: "op-8", RuleID: "operate::stale-account", Severity: types.SeverityHigh,
		Title: "Stale active account: bob@acme.com", Endpoint: "bob@acme.com"}
	act, ok := Propose(f, gw, func() string { return "1" })
	if !ok || act.Kind != platform.ActFileTicket || act.Tier != 1 {
		t.Fatalf("without a live write path the suspend must stay a tier-1 ticket, got %s tier %d", act.Kind, act.Tier)
	}
	// the structured fields still ride along so it promotes the moment GWorkspace suspend lands
	if act.Payload["remediation_type"] != "account_suspend" {
		t.Errorf("ticket should still carry the machine-readable remediation: %+v", act.Payload)
	}
}

// A DMARC finding becomes a ticket carrying the EXACT TXT record to publish.
func TestPropose_DMARCFindingGivesExactRecord(t *testing.T) {
	f := types.Finding{ID: "op-1", RuleID: "operate::dmarc-not-enforced", Severity: types.SeverityHigh,
		Title: "DMARC not enforced: acme.com", Endpoint: "acme.com"}
	act, ok := Propose(f, workspaceAsset(), func() string { return "1" })
	if !ok || act.Kind != platform.ActFileTicket {
		t.Fatalf("workspace finding should produce a ticket, got %+v ok=%v", act, ok)
	}
	if act.FindingID != "op-1" || act.ConnectionID != "conn-okta" {
		t.Errorf("action must cite the finding + connection: %+v", act)
	}
	if act.Payload["remediation_type"] != "dmarc_publish" || act.Payload["target"] != "acme.com" {
		t.Errorf("structured remediation fields wrong: %+v", act.Payload)
	}
	summary, _ := act.Payload["summary"].(string)
	if !strings.Contains(summary, "_dmarc.acme.com") || !strings.Contains(summary, "v=DMARC1; p=reject") {
		t.Errorf("summary should contain the exact DMARC record:\n%s", summary)
	}
}

// An admin-without-MFA finding names the offending admin and the concrete action.
func TestPropose_AdminMFAFindingNamesEntity(t *testing.T) {
	f := types.Finding{ID: "op-2", RuleID: "operate::admin-without-mfa", Severity: types.SeverityCritical,
		Title: "Admin without MFA", Endpoint: "ceo@acme.com"}
	act, ok := Propose(f, workspaceAsset(), nil)
	if !ok {
		t.Fatal("admin-without-mfa should produce an action")
	}
	if act.Payload["remediation_type"] != "mfa_enforce" || act.Payload["target"] != "ceo@acme.com" {
		t.Errorf("should target the named admin with an MFA enforce: %+v", act.Payload)
	}
	if !strings.Contains(act.Title, "ceo@acme.com") {
		t.Errorf("title should name the admin: %q", act.Title)
	}
}

// Each operate rule has a runbook (so no identity finding degrades to a generic ticket).
func TestIdentityRunbook_CoversEveryOperateRule(t *testing.T) {
	rules := []string{
		"operate::admin-without-mfa", "operate::user-without-mfa", "operate::dmarc-not-enforced",
		"operate::spf-dkim-missing", "operate::oauth-admin-scope", "operate::oauth-unverified-app",
		"operate::stale-account", "operate::excess-super-admins",
	}
	for _, rule := range rules {
		if _, ok := identityRunbook(rule, "x"); !ok {
			t.Errorf("no runbook for %s", rule)
		}
	}
}

// An unknown workspace rule falls back to the generic review ticket (never crashes).
func TestPropose_UnknownWorkspaceRuleFallsBack(t *testing.T) {
	f := types.Finding{ID: "op-9", RuleID: "operate::some-future-rule", Severity: types.SeverityLow, Title: "New check"}
	act, ok := Propose(f, workspaceAsset(), nil)
	if !ok || act.Kind != platform.ActFileTicket {
		t.Fatalf("unknown workspace rule should still produce a ticket, got %+v", act)
	}
	if _, hasType := act.Payload["remediation_type"]; hasType {
		t.Error("the generic fallback ticket should not carry a remediation_type")
	}
}
