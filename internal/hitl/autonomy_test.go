package hitl

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func grantAll(called *int) func(context.Context, platform.Action) (string, bool) {
	return func(context.Context, platform.Action) (string, bool) {
		*called++
		return "earned autonomy: waf_rule for nuclei::sqli (allowed by owner@acme.com on 2026-09-11)", true
	}
}

// A granted tier-2 action applies without queueing, and the grant is the recorded approver.
func TestEarnedAutonomy_AppliesTier2WithTheGrantAsApprover(t *testing.T) {
	ctx := context.Background()
	app := &recordingApplier{}
	d, _, st := newDesk(app)
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	n := 0
	d.Autonomy = grantAll(&n)
	got, err := d.Submit(ctx, platform.Action{ID: "a1", TenantID: "t1", Tier: platform.GateTier})
	if err != nil || got.Status != platform.ActApplied || len(app.applied) != 1 {
		t.Fatalf("granted tier-2 action did not apply: %+v err=%v", got, err)
	}
	if got.Approver == "" || got.Approver == autoApprover {
		t.Errorf("the approver must name the grant, got %q", got.Approver)
	}
}

// T3 never consults the grant; the kill-switch beats it; without a grant tier 2 still queues.
func TestEarnedAutonomy_NeverForT3_NeverWhileHalted(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name   string
		tier   int
		halted bool
		hook   bool
	}{
		{"t3", platform.TierIrreversible, false, true},
		{"halted", platform.GateTier, true, true},
		{"no grant", platform.GateTier, false, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			app := &recordingApplier{}
			d, _, st := newDesk(app)
			_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", AgentsHalted: tc.halted})
			n := 0
			if tc.hook {
				d.Autonomy = grantAll(&n)
			}
			got, _ := d.Submit(ctx, platform.Action{ID: "a1", TenantID: "t1", Tier: tc.tier})
			if got.Status != platform.ActPendingApproval || len(app.applied) != 0 {
				t.Fatalf("must queue for a human: %+v applied=%v", got, app.applied)
			}
			if tc.tier == platform.TierIrreversible && n != 0 {
				t.Error("the grant was even consulted for a T3 action")
			}
		})
	}
}
