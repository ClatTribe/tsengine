package grc

import (
	"context"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A gap opened by a finding must CLEAR (flip to Met) once that finding is remediated (gone from the
// current set), and PERSIST while the finding is still present. This is the false-NON-compliant guard:
// without Reconcile, grc.Apply (upsert-only) would leave the gap forever after the fix.
func TestReconcile_ClearsRemediatedGapKeepsLiveOne(t *testing.T) {
	g := &GRC{Store: store.NewMemory()}
	ctx := context.Background()

	fixed := types.Finding{ID: "f-fixed", Title: "SQLi", Severity: types.SeverityHigh,
		Compliance: &types.Compliance{SOC2: []string{"CC6.1"}}, DiscoveredAt: time.Now().UTC()}
	live := types.Finding{ID: "f-live", Title: "XSS", Severity: types.SeverityHigh,
		Compliance: &types.Compliance{SOC2: []string{"CC7.1"}}, DiscoveredAt: time.Now().UTC()}
	for _, f := range []types.Finding{fixed, live} {
		if err := g.Apply(ctx, "t1", f); err != nil {
			t.Fatal(err)
		}
	}
	// both controls are gaps now
	if cs, _ := g.Posture(ctx, "t1", FrameworkSOC2); gapCount(cs) != 2 {
		t.Fatalf("expected 2 gaps before remediation, got %d", gapCount(cs))
	}

	// next scan: f-fixed is gone, f-live remains
	res, err := g.Reconcile(ctx, "t1", []types.Finding{live})
	if err != nil {
		t.Fatal(err)
	}
	if res.Cleared != 1 || res.Refreshed != 1 {
		t.Errorf("want cleared=1 refreshed=1, got %+v", res)
	}
	cs, _ := g.Posture(ctx, "t1", FrameworkSOC2)
	gaps, met := 0, 0
	for _, c := range cs {
		switch {
		case c.State == platform.ControlGap && c.ControlID == "CC7.1":
			gaps++
		case c.State == platform.ControlMet && c.ControlID == "CC6.1":
			met++
		}
	}
	if gaps != 1 || met != 1 {
		t.Errorf("after reconcile want CC7.1 gap + CC6.1 met, got %+v", cs)
	}
}

// A control a human attested (or marked exception) must NOT be flipped by Reconcile — HITL judgment stands.
func TestReconcile_LeavesNonGapStatesUntouched(t *testing.T) {
	g := &GRC{Store: store.NewMemory()}
	ctx := context.Background()
	g.Store.UpsertControlState(ctx, platform.ControlState{
		TenantID: "t1", Framework: FrameworkSOC2, ControlID: "CC1.1",
		State: platform.ControlMet, UpdatedAt: time.Now().UTC()})
	if _, err := g.Reconcile(ctx, "t1", nil); err != nil {
		t.Fatal(err)
	}
	cs, _ := g.Posture(ctx, "t1", FrameworkSOC2)
	if len(cs) != 1 || cs[0].State != platform.ControlMet {
		t.Errorf("a Met control must be left untouched, got %+v", cs)
	}
}

func gapCount(cs []platform.ControlState) int {
	n := 0
	for _, c := range cs {
		if c.State == platform.ControlGap {
			n++
		}
	}
	return n
}
