package scheduler

import (
	"context"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// countScanner counts how many assets it scanned.
type countScanner struct{ scans int }

func (c *countScanner) Scan(_ context.Context, a platform.Asset) ([]types.Finding, error) {
	c.scans++
	return []types.Finding{{ID: "f-" + a.Target}}, nil
}

func TestTick_RescansEveryTenantsAssets(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	// two tenants, 2 + 1 assets
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t2"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "repository", Target: "r1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a2", TenantID: "t1", Type: "repository", Target: "r2"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a3", TenantID: "t2", Type: "repository", Target: "r3"})

	sc := &countScanner{}
	svc := &runner.Service{Store: st, Connectors: connector.NewRegistry(), Scanner: sc}
	s := &Scheduler{Store: st, Runner: svc, Interval: time.Hour}

	n, err := s.Tick(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if n != 3 || sc.scans != 3 {
		t.Fatalf("tick should scan all 3 assets across both tenants, got n=%d scans=%d", n, sc.scans)
	}
	// a second tick re-scans (continuous) → findings refreshed, not duplicated in the store
	_, _ = s.Tick(ctx)
	if sc.scans != 6 {
		t.Errorf("second tick should re-scan, total scans = %d", sc.scans)
	}
	fs, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(fs) != 2 { // r1, r2 upserted (not duplicated)
		t.Errorf("t1 should have 2 findings after re-scan (upsert), got %d", len(fs))
	}
}

func TestRun_DisabledWhenIntervalZero(t *testing.T) {
	s := &Scheduler{Interval: 0}
	if err := s.Run(context.Background()); err != nil {
		t.Errorf("a zero interval should disable the loop, got %v", err)
	}
}

func TestRun_FiresThenStopsOnCancel(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "repository", Target: "r1"})
	sc := &countScanner{}
	svc := &runner.Service{Store: st, Connectors: connector.NewRegistry(), Scanner: sc}
	s := &Scheduler{Store: st, Runner: svc, Interval: 50 * time.Millisecond}

	done := make(chan error, 1)
	go func() { done <- s.Run(ctx) }()
	time.Sleep(120 * time.Millisecond) // ~ initial fire + ~2 ticks
	cancel()
	if err := <-done; err != context.Canceled {
		t.Errorf("Run should stop with context.Canceled, got %v", err)
	}
	if sc.scans == 0 {
		t.Error("Run should have fired at least the initial scan")
	}
}
