package remediate

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A leaver's still-enabled account is the same reversible lifecycle transition as a stale account —
// suspend — so on an IdP with a live write path it is a HITL-gated tier-2 mutation, not a ticket.
func TestPropose_HRISLeaverIsGatedSuspendOnLiveIdP(t *testing.T) {
	f := types.Finding{ID: "hris-1", RuleID: "hris::leaver-with-active-account", Severity: types.SeverityCritical,
		Title: "Former employee still has an active account: alice@acme.com", Endpoint: "alice@acme.com"}
	act, ok := Propose(f, workspaceAsset(), func() string { return "1" })
	if !ok {
		t.Fatal("a leaver finding must produce an action")
	}
	if act.Kind != platform.ActApplyConfig || act.Tier != tierApplyConfig || !act.NeedsApproval() {
		t.Fatalf("live IdP → gated tier-2 suspend, got %s tier %d", act.Kind, act.Tier)
	}
	if act.Payload["remediation_type"] != "account_suspend" || act.Payload["target"] != "alice@acme.com" || act.ConnectionID != "conn-okta" {
		t.Errorf("payload/routing: %+v conn=%s", act.Payload, act.ConnectionID)
	}
	if !contains(act.Payload["summary"], "no longer employed") {
		t.Errorf("the runbook must say WHY (HR says they left): %v", act.Payload["summary"])
	}
}

// An account with no HR record is NOT a suspend: nobody has said the person left. It is a ticket
// asking for an owner, on every provider.
func TestPropose_HRISUnknownAccountIsATicketNeverASuspend(t *testing.T) {
	f := types.Finding{ID: "hris-2", RuleID: "hris::account-without-hr-record", Severity: types.SeverityLow,
		Title: "Account has no HR record: svc@acme.com", Endpoint: "svc@acme.com"}
	act, ok := Propose(f, workspaceAsset(), func() string { return "1" })
	if !ok {
		t.Fatal("must produce a runbook ticket")
	}
	if act.Kind != platform.ActFileTicket || act.Payload["remediation_type"] != "record_owner" {
		t.Errorf("no-record is a record-an-owner ticket, got %s %+v", act.Kind, act.Payload)
	}
}

func contains(v any, s string) bool {
	str, _ := v.(string)
	return len(str) > 0 && len(s) > 0 && (len(str) >= len(s)) && (func() bool {
		for i := 0; i+len(s) <= len(str); i++ {
			if str[i:i+len(s)] == s {
				return true
			}
		}
		return false
	})()
}
