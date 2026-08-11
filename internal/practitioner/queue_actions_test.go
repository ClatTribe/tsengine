package practitioner

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The desk aggregated the four judgement ceremonies but not the one a practitioner meets MOST often —
// "should this fix be applied?". These pin the fifth.

func TestQueue_IncludesPendingRemediationApprovals(t *testing.T) {
	got := Queue([]TenantData{{
		TenantID: "t1", TenantName: "Acme",
		Actions: []platform.Action{
			{ID: "a1", Kind: platform.ActOpenPR, Title: "fix SQL injection", Status: platform.ActPendingApproval, Tier: 2,
				Diff: "--- a/x.go\n+++ b/x.go\n@@ -1 +1 @@\n-bad\n+good\n"},
		},
	}})
	if len(got) != 1 {
		t.Fatalf("want 1 queued item, got %d", len(got))
	}
	if got[0].Kind != "action" || got[0].ItemID != "a1" {
		t.Errorf("got %+v, want the remediation queued as kind=action", got[0])
	}
	// The diff rides along so the desk can show WHAT is being approved, not just its title.
	if got[0].Diff == "" {
		t.Error("the diff must reach the desk — approving a change you cannot see is a signature, not a review")
	}
}

// A sent-back action is still waiting on a human-driven outcome (a revised proposal), so it stays
// visible. Dropping it would make the work disappear from the only place anyone is looking.
func TestQueue_IncludesChangesRequested(t *testing.T) {
	got := Queue([]TenantData{{
		TenantID: "t1",
		Actions: []platform.Action{
			{ID: "a1", Kind: platform.ActOpenPR, Title: "fix", Status: platform.ActChangesRequested,
				Feedback: "parameterise the ORDER BY too"},
		},
	}})
	if len(got) != 1 {
		t.Fatalf("want the sent-back action still queued, got %d items", len(got))
	}
	if got[0].Feedback == "" {
		t.Error("the reviewer's note must ride along so a returned proposal reads as a thread")
	}
}

// A queue that lists settled work is a queue people stop reading.
func TestQueue_ExcludesSettledAndNotYetGatedActions(t *testing.T) {
	for _, st := range []string{
		platform.ActProposed, // not gated yet — the agent's turn, not a human's
		platform.ActApproved,
		platform.ActApplied,
		platform.ActRejected,
	} {
		got := Queue([]TenantData{{TenantID: "t1", Actions: []platform.Action{{ID: "a1", Status: st}}}})
		if len(got) != 0 {
			t.Errorf("status %q produced %d queue items, want 0 — it is not awaiting a person", st, len(got))
		}
	}
}

// Tier 3 cannot auto-apply and needs a NAMED signature; the desk should say so rather than showing it
// as an ordinary approval.
func TestQueue_IrreversibleActionIsLabelledForSignature(t *testing.T) {
	got := Queue([]TenantData{{
		TenantID: "t1",
		Actions:  []platform.Action{{ID: "a1", Kind: platform.ActDraftNotification, Title: "breach note", Status: platform.ActPendingApproval, Tier: platform.TierIrreversible}},
	}})
	if len(got) != 1 {
		t.Fatalf("want 1 item, got %d", len(got))
	}
	if got[0].Detail == "" || got[0].Detail == "fix awaiting your approval" {
		t.Errorf("detail = %q, want it to flag the named-signature requirement", got[0].Detail)
	}
}

// Scope still filters: a vCISO-scoped practitioner owns judgement, not the remediation queue.
func TestQueue_ScopeStillFiltersActions(t *testing.T) {
	data := []TenantData{{
		TenantID: "t1", Scope: []string{"vciso"},
		Actions: []platform.Action{{ID: "a1", Status: platform.ActPendingApproval}},
		Risks:   []platform.Risk{{ID: "r1", Title: "risk", Status: platform.RiskOpen}},
	}}
	got := Queue(data)
	for _, it := range got {
		if it.Kind == "action" {
			t.Error("a vciso-scoped practitioner should not be handed the remediation queue")
		}
	}
	if len(got) != 1 || got[0].Kind != "risk" {
		t.Errorf("got %+v, want only the risk item in vciso scope", got)
	}
}

// The security scope is the hands-on half: remediation + pentest sign-off, not the vCISO ceremonies.
func TestQueue_SecurityScopeGetsActions(t *testing.T) {
	got := Queue([]TenantData{{
		TenantID: "t1", Scope: []string{"security"},
		Actions: []platform.Action{{ID: "a1", Title: "fix", Status: platform.ActPendingApproval}},
		Risks:   []platform.Risk{{ID: "r1", Title: "risk", Status: platform.RiskOpen}},
	}})
	if len(got) != 1 || got[0].Kind != "action" {
		t.Errorf("got %+v, want only the remediation in security scope", got)
	}
}
