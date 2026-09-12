package platform

import "testing"

// The per-application tier's cap is a PURCHASED COUNT, which a plan string cannot carry — so it is
// read through the tenant. The bare Entitlements("audit") must fail CLOSED (zero targets), because a
// caller that forgot EntitlementsFor would otherwise let an unpaid engagement scan.
func TestEntitlements_AuditTierCapIsThePurchasedCount(t *testing.T) {
	bare := Entitlements(PlanAudit)
	if bare.Plan != PlanAudit || bare.MaxAssets != 0 {
		t.Fatalf("bare audit entitlements must allow no targets: %+v", bare)
	}
	if !bare.AIEnabled || !bare.AutonomousPentest || bare.ContinuousMonitoring || !bare.HumanInLoopApply {
		t.Errorf("an audit needs the engine and the pentester, not a heartbeat: %+v", bare)
	}
	for _, alias := range []string{"audit", "per-app", "per-application", " Audit "} {
		if c, err := ValidatePlan(alias); err != nil || c != PlanAudit {
			t.Errorf("ValidatePlan(%q) = %q, %v", alias, c, err)
		}
		if NormalizePlan(alias) != PlanAudit {
			t.Errorf("NormalizePlan(%q) != audit", alias)
		}
	}
	got := EntitlementsFor(Tenant{Plan: PlanAudit, AuditApplications: 4})
	if got.MaxAssets != 4 {
		t.Errorf("four applications purchased → four targets, got %d", got.MaxAssets)
	}
	if got := EntitlementsFor(Tenant{Plan: PlanAudit, AuditApplications: -2}); got.MaxAssets != 0 {
		t.Errorf("a negative count is not a cap: %d", got.MaxAssets)
	}
	// The count is ignored on every other tier — it is the audit SKU's number, nobody else's.
	if got := EntitlementsFor(Tenant{Plan: PlanGrowth, AuditApplications: 4}); got.MaxAssets != Entitlements(PlanGrowth).MaxAssets {
		t.Errorf("Core's cap must not read the audit count: %d", got.MaxAssets)
	}
	if got := EntitlementsFor(Tenant{Plan: PlanFree, AuditApplications: 99}); got.MaxAssets != Entitlements(PlanFree).MaxAssets {
		t.Errorf("Free's cap must not read the audit count: %d", got.MaxAssets)
	}
}

// Nothing is due before acceptance — the tenders' own term, computed from status so it cannot drift.
func TestAuditOrder_AmountDueOnlyAfterAcceptance(t *testing.T) {
	o := AuditOrder{PriceINR: AuditListPriceINR}
	for _, s := range []AuditOrderStatus{AuditOrderOpen, AuditOrderCertified} {
		o.Status = s
		if o.AmountDueINR() != 0 {
			t.Errorf("%s: nothing is due before the buyer accepts, got %d", s, o.AmountDueINR())
		}
	}
	for _, s := range []AuditOrderStatus{AuditOrderAccepted, AuditOrderInvoiced} {
		o.Status = s
		if o.AmountDueINR() != AuditListPriceINR {
			t.Errorf("%s: the full price is due, got %d", s, o.AmountDueINR())
		}
	}
}
