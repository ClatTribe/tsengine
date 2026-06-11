package remediate

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func workspaceAsset() platform.Asset {
	return platform.Asset{TenantID: "t1", ConnectionID: "conn-okta", Type: "workspace", Target: "acme-okta"}
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
