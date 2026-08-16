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

	// pass 2+3: the issue is fixed → the incident resolves once the absence PERSISTS. One absent
	// pass is held deliberately: a flaky scanner must not be able to report a live vulnerability
	// as remediated.
	sc.Open = false
	for i := 0; i < 2; i++ {
		if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
			t.Fatal(err)
		}
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

// degradedScanner reports the same finding as togglingScanner but, once Degrade is set, returns NO
// findings while reporting that a tool failed — precisely what a per-tool timeout produces.
type degradedScanner struct{ Degrade bool }

func (s *degradedScanner) Scan(ctx context.Context, a platform.Asset) ([]types.Finding, error) {
	f, _, err := s.ScanWithReport(ctx, a)
	return f, err
}

func (s *degradedScanner) ScanWithReport(context.Context, platform.Asset) ([]types.Finding, ScanReport, error) {
	if s.Degrade {
		// The scanner ran, found nothing, and lost a tool. Indistinguishable from "fixed" without
		// the ToolsFailed record.
		return nil, ScanReport{
			ToolsRan:    []string{"nuclei"},
			ToolsFailed: []types.ToolFailure{{Tool: "schemathesis", Reason: "context deadline exceeded"}},
		}, nil
	}
	return []types.Finding{{
		ID: "f1", RuleID: "operate::admin-without-mfa", Endpoint: "ceo@acme.com",
		Severity: types.SeverityCritical, Title: "Administrator without MFA",
	}}, ScanReport{ToolsRan: []string{"nuclei", "schemathesis"}}, nil
}

// TestRescanTenant_DegradedPassNeverResolves is the data-integrity guarantee.
//
// Detector.Reconcile resolves an incident whose issue is absent from the current findings — correct
// when the pass is authoritative. A pass that lost a tool to a wall-clock timeout is NOT
// authoritative: the finding is absent because nothing looked for it.
//
// Measured: four identical api scans of one unchanged target returned 1, 1, 11 and 11 findings
// because tools lost their timeout race under CPU load. Without this guard, the two low runs would
// have resolved every incident the high runs opened — telling the customer live vulnerabilities were
// fixed because a scanner timed out.
func TestRescanTenant_DegradedPassNeverResolves(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "workspace", Target: "acme"})

	sc := &degradedScanner{}
	n := 0
	svc := &Service{
		Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{},
		Scanner: sc, NewID: func() string { n++; return itoa(n) },
		Detector: &detect.Detector{Store: st, NewID: func() string { n++; return itoa(n) }},
	}

	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	if openCount(t, st) != 1 {
		t.Fatalf("first pass should open one incident, got %d", openCount(t, st))
	}

	// The vulnerability is UNCHANGED. Only the scan degraded.
	sc.Degrade = true
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	if openCount(t, st) != 1 {
		t.Errorf("a degraded pass must NOT resolve the incident — the finding is absent because a "+
			"tool timed out, not because anything was fixed. open=%d", openCount(t, st))
	}
}

// The guard must not break the real fix path: a CLEAN pass with no failed tools still resolves.
func TestRescanTenant_CleanPassStillResolves(t *testing.T) {
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
	if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
		t.Fatal(err)
	}
	sc.Open = false
	for i := 0; i < 2; i++ { // sustained absence, not a single quiet run
		if _, err := svc.RescanTenant(ctx, "t1"); err != nil {
			t.Fatal(err)
		}
	}
	if openCount(t, st) != 0 {
		t.Errorf("clean passes with no failed tools must still resolve a genuinely fixed issue, open=%d",
			openCount(t, st))
	}
}
