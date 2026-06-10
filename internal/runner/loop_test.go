package runner

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// loopScanner returns one finding that carries a SOC2 compliance mapping (so GRC has
// something to record) on a cloud asset (so the proposed fix is tier-2 / gated).
type loopScanner struct{}

func (loopScanner) Scan(_ context.Context, a platform.Asset) ([]types.Finding, error) {
	return []types.Finding{{
		ID: "f1", Title: "Public bucket", Severity: types.SeverityHigh, Tool: "prowler",
		Compliance: &types.Compliance{SOC2: []string{"CC6.1"}},
	}}, nil
}

// loopApplier records applies (so we can assert the gated action did NOT auto-apply).
type loopApplier struct{ applied int }

func (l *loopApplier) Apply(context.Context, platform.Action) error { l.applied++; return nil }

func TestFullLoop_ScanProposesGatesAndRecordsCompliance(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	app := &loopApplier{}
	g := &grc.GRC{Store: st}
	desk := &hitl.Desk{Store: st, Apply: app}

	n := 0
	svc := &Service{
		Store:      st,
		Connectors: connector.NewRegistry(fakeConn{}),
		Tokens:     fakeTokens{},
		Scanner:    loopScanner{},
		NewID:      func() string { n++; return itoa(n) },
		GRC:        g,
		Desk:       desk,
		Propose: func(f types.Finding, a platform.Asset) (platform.Action, bool) {
			// a cloud config change → tier-2 gated action
			return platform.Action{
				ID: "act-" + f.ID, TenantID: a.TenantID, FindingID: f.ID,
				Kind: platform.ActApplyConfig, Tier: 2, Status: platform.ActProposed,
			}, true
		},
	}

	// scan one cloud asset directly via OnTrigger after seeding it
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "cloud_account", Target: "aws:1"})
	if _, err := svc.OnTrigger(ctx, connector.Trigger{TenantID: "t1", AssetTarget: "aws:1", Kind: platform.TriggerManual}); err != nil {
		t.Fatal(err)
	}

	// 1) the finding was folded into the compliance system-of-record
	soc2, _ := g.Posture(ctx, "t1", grc.FrameworkSOC2)
	if len(soc2) != 1 || soc2[0].ControlID != "CC6.1" || soc2[0].State != platform.ControlGap {
		t.Errorf("GRC not updated by the loop: %+v", soc2)
	}

	// 2) a remediation was proposed and GATED (tier-2 queued, not auto-applied)
	pend, _ := st.PendingApprovals(ctx, "t1")
	if len(pend) != 1 {
		t.Fatalf("want 1 pending (gated) action, got %d", len(pend))
	}
	if app.applied != 0 {
		t.Errorf("a tier-2 fix must NOT auto-apply, applied=%d", app.applied)
	}
}
