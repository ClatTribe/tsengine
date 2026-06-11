package runner

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// togglingScanner returns a critical finding while Open is true, nothing once it flips —
// simulating an issue that appears in one monitoring pass and is fixed by the next.
type togglingScanner struct{ Open bool }

func (s *togglingScanner) Scan(context.Context, platform.Asset) ([]types.Finding, error) {
	if !s.Open {
		return nil, nil
	}
	return []types.Finding{{
		ID: "f1", RuleID: "operate::admin-without-mfa", Endpoint: "ceo@acme.com",
		Severity: types.SeverityCritical, Title: "Administrator without MFA",
	}}, nil
}

func openCount(t *testing.T, st store.Store) int {
	t.Helper()
	all, _ := st.ListIncidents(context.Background(), "t1")
	n := 0
	for _, i := range all {
		if i.Status == platform.IncidentOpen {
			n++
		}
	}
	return n
}

func TestRescanTenant_DrivesIncidentLifecycle(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "workspace", Target: "acme"})

	sc := &togglingScanner{Open: true}
	n := 0
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: sc, NewID: func() string { n++; return itoa(n) },
		Detector: &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }},
	}

	// pass 1: the issue is present → an incident opens
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	if openCount(t, st) != 1 {
		t.Fatalf("first monitoring pass should open one incident, got %d", openCount(t, st))
	}

	// pass 2: the issue is fixed → the incident resolves
	sc.Open = false
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	if openCount(t, st) != 0 {
		t.Errorf("once the issue is fixed, no incident should stay open, got %d", openCount(t, st))
	}
}

// Without a Detector wired, the loop behaves exactly as before (no incidents) — the
// detector is purely additive.
func TestRescanTenant_NoDetectorNoIncidents(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "workspace", Target: "acme"})
	svc := &Service{Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{}, Scanner: &togglingScanner{Open: true}, NewID: itoa1}
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	all, _ := st.ListIncidents(ctx, "t1")
	if len(all) != 0 {
		t.Errorf("no Detector → no incidents, got %d", len(all))
	}
}

func itoa1() string { return "x" }
