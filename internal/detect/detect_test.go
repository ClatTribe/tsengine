package detect

import (
	"context"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func newDetector(st Store) *Detector {
	n := 0
	return &Detector{Store: st, Now: func() time.Time { return time.Unix(1700000000, 0).UTC() },
		NewID: func() string { n++; return string(rune('a' + n)) }}
}

func crit(rule, endpoint string) types.Finding {
	return types.Finding{ID: "f-" + endpoint, RuleID: rule, Endpoint: endpoint, Severity: types.SeverityCritical, Title: rule}
}

func openIncidents(t *testing.T, st store.Store, tenant string) []platform.Incident {
	t.Helper()
	all, _ := st.ListIncidents(context.Background(), tenant)
	var open []platform.Incident
	for _, i := range all {
		if i.Status == platform.IncidentOpen {
			open = append(open, i)
		}
	}
	return open
}

func TestReconcile_OpensIncidentForNewCritical(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := newDetector(st)

	res, err := d.Reconcile(ctx, "t1", []types.Finding{crit("operate::admin-without-mfa", "ceo@acme.com")})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Opened) != 1 || len(res.Resolved) != 0 {
		t.Fatalf("a new critical should open exactly one incident, got %+v", res)
	}
	open := openIncidents(t, st, "t1")
	if len(open) != 1 || open[0].Key != "operate::admin-without-mfa|ceo@acme.com" {
		t.Fatalf("incident key wrong: %+v", open)
	}
}

func TestReconcile_Idempotent(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := newDetector(st)
	fs := []types.Finding{crit("operate::admin-without-mfa", "ceo@acme.com")}

	_, _ = d.Reconcile(ctx, "t1", fs)
	res, _ := d.Reconcile(ctx, "t1", fs) // same input again
	if len(res.Opened) != 0 || len(res.Resolved) != 0 {
		t.Fatalf("re-running with the same findings should be a no-op, got %+v", res)
	}
	if len(openIncidents(t, st, "t1")) != 1 {
		t.Error("the single incident should not duplicate")
	}
}

func TestReconcile_ResolvesWhenIssueGone(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := newDetector(st)
	fs := []types.Finding{crit("operate::admin-without-mfa", "ceo@acme.com")}

	_, _ = d.Reconcile(ctx, "t1", fs)
	// next pass: the issue is fixed → no findings
	res, _ := d.Reconcile(ctx, "t1", nil)
	if len(res.Resolved) != 1 {
		t.Fatalf("a disappeared issue should resolve its incident, got %+v", res)
	}
	if len(openIncidents(t, st, "t1")) != 0 {
		t.Error("no incident should remain open after the issue is fixed")
	}
}

func TestReconcile_ReopensAfterRegression(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := newDetector(st)
	fs := []types.Finding{crit("operate::admin-without-mfa", "ceo@acme.com")}

	_, _ = d.Reconcile(ctx, "t1", fs)    // open
	_, _ = d.Reconcile(ctx, "t1", nil)   // resolve
	res, _ := d.Reconcile(ctx, "t1", fs) // regression → a NEW incident
	if len(res.Opened) != 1 {
		t.Fatalf("a regression should open a fresh incident, got %+v", res)
	}
	if len(openIncidents(t, st, "t1")) != 1 {
		t.Error("exactly one open incident after the regression")
	}
}

func TestReconcile_BelowThresholdIgnored(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := newDetector(st) // default threshold = high
	low := types.Finding{ID: "f1", RuleID: "operate::spf-dkim-missing", Endpoint: "acme.com", Severity: types.SeverityMedium}

	res, _ := d.Reconcile(ctx, "t1", []types.Finding{low})
	if len(res.Opened) != 0 {
		t.Fatalf("a medium finding should not open an incident at the high threshold, got %+v", res)
	}
}

func TestReconcile_ThresholdConfigurable(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := newDetector(st)
	d.Threshold = types.SeverityMedium
	med := types.Finding{ID: "f1", RuleID: "operate::spf-dkim-missing", Endpoint: "acme.com", Severity: types.SeverityMedium, Title: "x"}

	res, _ := d.Reconcile(ctx, "t1", []types.Finding{med})
	if len(res.Opened) != 1 {
		t.Fatalf("at a medium threshold a medium finding should open an incident, got %+v", res)
	}
}

// Incidents are tenant-scoped: one tenant's findings never touch another's incidents.
func TestReconcile_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := newDetector(st)
	_, _ = d.Reconcile(ctx, "t1", []types.Finding{crit("r", "e")})
	_, _ = d.Reconcile(ctx, "t2", nil) // t2 empty pass must not resolve t1's incident
	if len(openIncidents(t, st, "t1")) != 1 {
		t.Error("t2's pass must not affect t1's incidents")
	}
}
