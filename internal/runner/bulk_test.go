package runner

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/hitl"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// twoFindingScanner returns two SCA findings in the same package (one fix unit).
type twoFindingScanner struct{}

func (twoFindingScanner) Scan(_ context.Context, a platform.Asset) ([]types.Finding, error) {
	pkg := map[string]string{"pkg": "lodash", "installed_version": "4.17.0", "fixed_version": "4.17.21"}
	return []types.Finding{
		{ID: "f1", RuleID: "trivy::CVE-1", Severity: types.SeverityHigh, ToolArgs: pkg},
		{ID: "f2", RuleID: "trivy::CVE-2", Severity: types.SeverityHigh, ToolArgs: pkg},
	}, nil
}

// TestBulkProposerSupersedesPerFinding asserts that when ProposeBatch is set, the runner
// uses it (one action over both findings) and does NOT call the per-finding Propose.
func TestBulkProposerSupersedesPerFinding(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	desk := &hitl.Desk{Store: st, Apply: &loopApplier{}}

	perFindingCalls := 0
	n := 0
	svc := &Service{
		Store:      st,
		Connectors: connector.NewRegistry(fakeConn{}),
		Tokens:     fakeTokens{},
		Scanner:    twoFindingScanner{},
		NewID:      func() string { n++; return itoa(n) },
		Desk:       desk,
		Propose: func(f types.Finding, a platform.Asset) (platform.Action, bool) {
			perFindingCalls++
			return platform.Action{ID: "act-" + f.ID, TenantID: a.TenantID, FindingID: f.ID, Kind: platform.ActOpenPR, Tier: 2}, true
		},
		ProposeBatch: func(fs []types.Finding, a platform.Asset) []platform.Action {
			ids := []string{}
			for _, f := range fs {
				ids = append(ids, f.ID)
			}
			return []platform.Action{{ID: "bulk-1", TenantID: a.TenantID, FindingID: fs[0].ID, FindingIDs: ids, Kind: platform.ActOpenPR, Tier: 2}}
		},
	}

	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "repository", Target: "acme/app"})
	if _, err := svc.OnTrigger(ctx, connector.Trigger{TenantID: "t1", AssetTarget: "acme/app", Kind: platform.TriggerManual}); err != nil {
		t.Fatal(err)
	}

	if perFindingCalls != 0 {
		t.Errorf("per-finding Propose must NOT be called when ProposeBatch is set, got %d calls", perFindingCalls)
	}
	pend, _ := st.PendingApprovals(ctx, "t1")
	if len(pend) != 1 {
		t.Fatalf("want exactly 1 bulk action queued (not 2 per-finding), got %d", len(pend))
	}
	if len(pend[0].FindingIDs) != 2 {
		t.Errorf("the bulk action should cite both findings, got %v", pend[0].FindingIDs)
	}
}
