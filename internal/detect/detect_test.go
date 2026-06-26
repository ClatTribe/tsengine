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

	res, err := d.Reconcile(ctx, "t1", []types.Finding{crit("operate::admin-without-mfa", "ceo@acme.com")}, nil)
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

// The incident must carry the opening finding's FP-control signal (verification + confidence) so the alert
// can show confirmed-vs-unconfirmed and never present a low-confidence finding as a confident incident.
func TestReconcile_IncidentCarriesFPControlSignal(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := newDetector(st)

	f := crit("nuclei::sqli", "https://app/x?q=")
	f.VerificationStatus = "corroborated"
	f.Confidence = 0.82
	if _, err := d.Reconcile(ctx, "t1", []types.Finding{f}, nil); err != nil {
		t.Fatal(err)
	}
	open := openIncidents(t, st, "t1")
	if len(open) != 1 {
		t.Fatalf("want 1 incident, got %d", len(open))
	}
	if open[0].Verification != "corroborated" || open[0].Confidence != 0.82 {
		t.Fatalf("incident must carry the finding's verification+confidence, got verification=%q confidence=%v", open[0].Verification, open[0].Confidence)
	}
}

func TestReconcile_Idempotent(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := newDetector(st)
	fs := []types.Finding{crit("operate::admin-without-mfa", "ceo@acme.com")}

	_, _ = d.Reconcile(ctx, "t1", fs, nil)
	res, _ := d.Reconcile(ctx, "t1", fs, nil) // same input again
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

	_, _ = d.Reconcile(ctx, "t1", fs, nil)
	// next pass: the issue is fixed → no findings
	res, _ := d.Reconcile(ctx, "t1", nil, nil)
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

	_, _ = d.Reconcile(ctx, "t1", fs, nil)    // open
	_, _ = d.Reconcile(ctx, "t1", nil, nil)   // resolve
	res, _ := d.Reconcile(ctx, "t1", fs, nil) // regression → a NEW incident
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

	res, _ := d.Reconcile(ctx, "t1", []types.Finding{low}, nil)
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

	res, _ := d.Reconcile(ctx, "t1", []types.Finding{med}, nil)
	if len(res.Opened) != 1 {
		t.Fatalf("at a medium threshold a medium finding should open an incident, got %+v", res)
	}
}

// Incidents are tenant-scoped: one tenant's findings never touch another's incidents.
func TestReconcile_TenantIsolation(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := newDetector(st)
	_, _ = d.Reconcile(ctx, "t1", []types.Finding{crit("r", "e")}, nil)
	_, _ = d.Reconcile(ctx, "t2", nil, nil) // t2 empty pass must not resolve t1's incident
	if len(openIncidents(t, st, "t1")) != 1 {
		t.Error("t2's pass must not affect t1's incidents")
	}
}

// captureAlerter records every incident it was alerted about.
type captureAlerter struct{ alerts []platform.Incident }

func (c *captureAlerter) IncidentOpened(_ context.Context, i platform.Incident) error {
	c.alerts = append(c.alerts, i)
	return nil
}

func TestReconcile_AlertsOnOpenOnly(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := newDetector(st)
	al := &captureAlerter{}
	d.Alerter = al
	fs := []types.Finding{crit("operate::admin-without-mfa", "ceo@acme.com")}

	_, _ = d.Reconcile(ctx, "t1", fs, nil) // open → one alert
	if len(al.alerts) != 1 || al.alerts[0].Severity != "critical" {
		t.Fatalf("opening an incident should alert once with the severity, got %+v", al.alerts)
	}
	_, _ = d.Reconcile(ctx, "t1", fs, nil)  // idempotent → no new alert
	_, _ = d.Reconcile(ctx, "t1", nil, nil) // resolve → no alert (it's a heads-up for NEW issues)
	if len(al.alerts) != 1 {
		t.Errorf("only a newly-opened incident should alert; idempotent/resolve must not, got %d", len(al.alerts))
	}
}

// A failing alerter never breaks reconciliation (best-effort).
type failAlerter struct{}

func (failAlerter) IncidentOpened(context.Context, platform.Incident) error {
	return context.DeadlineExceeded
}

func TestReconcile_AlerterErrorIsSwallowed(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := newDetector(st)
	d.Alerter = failAlerter{}
	res, err := d.Reconcile(ctx, "t1", []types.Finding{crit("r", "e")}, nil)
	if err != nil {
		t.Fatalf("a failing alerter must not fail the pass, got %v", err)
	}
	if len(res.Opened) != 1 {
		t.Error("the incident should still open even if the alert failed")
	}
}

func TestReconcile_AttackedEscalatesBelowThreshold(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := newDetector(st) // default threshold = high
	// A MEDIUM finding — normally ignored at the high threshold — but it is under attack.
	low := types.Finding{ID: "f1", RuleID: "nuclei::xss", Endpoint: "https://app.acme.com/search", Severity: types.SeverityMedium, Title: "Reflected XSS"}
	attacked := map[string]bool{Key(low): true}

	res, err := d.Reconcile(ctx, "t1", []types.Finding{low}, attacked)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Opened) != 1 {
		t.Fatalf("an under-attack finding should open an incident regardless of severity, got %+v", res)
	}
	inc := res.Opened[0]
	if !inc.Attacked {
		t.Error("the incident should be marked Attacked")
	}
	if inc.Title[:1] != "[" {
		t.Errorf("the title should be prefixed with the under-attack marker, got %q", inc.Title)
	}

	// Without the attacked set, the same medium finding opens nothing.
	st2 := store.NewMemory()
	d2 := newDetector(st2)
	if res2, _ := d2.Reconcile(ctx, "t1", []types.Finding{low}, nil); len(res2.Opened) != 0 {
		t.Errorf("not-attacked medium finding must not open an incident, got %+v", res2)
	}
}

func TestEscalateOverdue_RealertsOverdueOnly(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	now := time.Unix(1700000000, 0).UTC()
	alerter := &captureAlerter{}
	d := &Detector{Store: st, Alerter: alerter, Now: func() time.Time { return now }}

	mk := func(id, key string, openedAgo, ackedAgo time.Duration) platform.Incident {
		inc := platform.Incident{ID: id, TenantID: "t1", Key: key, RuleID: "r", Title: key,
			Severity: "critical", Status: platform.IncidentOpen, OpenedAt: now.Add(-openedAgo)}
		if ackedAgo > 0 {
			inc.AcknowledgedAt = now.Add(-ackedAgo)
		}
		return inc
	}
	_ = st.PutIncident(ctx, mk("inc-1", "r|e1", 60*time.Minute, 0))              // overdue (open 60m, window 30m)
	_ = st.PutIncident(ctx, mk("inc-2", "r|e2", 5*time.Minute, 0))               // fresh (within window)
	_ = st.PutIncident(ctx, mk("inc-3", "r|e3", 60*time.Minute, 10*time.Minute)) // acked → skip

	esc, err := d.EscalateOverdue(ctx, "t1", 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(esc) != 1 || esc[0].ID != "inc-1" {
		t.Fatalf("only the overdue, unacked incident should escalate, got %+v", esc)
	}
	if len(alerter.alerts) != 1 || alerter.alerts[0].ID != "inc-1" {
		t.Fatalf("only inc-1 should re-alert, got %+v", alerter.alerts)
	}
	// LastEscalatedAt was stamped → an immediate second pass must not re-ping (≤ 1 per window)
	esc2, _ := d.EscalateOverdue(ctx, "t1", 30)
	if len(esc2) != 0 {
		t.Fatalf("should not re-escalate within the same window, got %+v", esc2)
	}
}

func TestEscalateOverdue_NoOpWhenWindowOff(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	now := time.Unix(1700000000, 0).UTC()
	d := &Detector{Store: st, Now: func() time.Time { return now }}
	_ = st.PutIncident(ctx, platform.Incident{ID: "inc-1", TenantID: "t1", Status: platform.IncidentOpen, OpenedAt: now.Add(-2 * time.Hour)})
	esc, err := d.EscalateOverdue(ctx, "t1", 0)
	if err != nil {
		t.Fatal(err)
	}
	if len(esc) != 0 {
		t.Fatalf("window off → no escalation, got %+v", esc)
	}
}

func TestReconcile_MaintenanceSuppressesOpensNotResolves(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := newDetector(st)
	d.Suppressed = func(context.Context, string, time.Time) bool { return true }

	// During maintenance: a new critical must NOT open an incident.
	res, err := d.Reconcile(ctx, "t1", []types.Finding{crit("rule::x", "a.com")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Opened) != 0 || len(openIncidents(t, st, "t1")) != 0 {
		t.Fatalf("maintenance window must suppress opening, got opened=%d", len(res.Opened))
	}

	// But an EXISTING open incident must still resolve when its issue disappears, even in maintenance.
	_ = st.PutIncident(ctx, platform.Incident{ID: "inc-1", TenantID: "t1", Key: "rule::y|b.com", Status: platform.IncidentOpen})
	res2, err := d.Reconcile(ctx, "t1", []types.Finding{}, nil) // issue gone
	if err != nil {
		t.Fatal(err)
	}
	if len(res2.Resolved) != 1 {
		t.Fatalf("resolves must still flow during maintenance, got %+v", res2.Resolved)
	}
}

func TestEscalateOverdue_NoPageDuringMaintenance(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	now := time.Unix(1700000000, 0).UTC()
	alerter := &captureAlerter{}
	d := &Detector{Store: st, Alerter: alerter, Now: func() time.Time { return now },
		Suppressed: func(context.Context, string, time.Time) bool { return true }}
	_ = st.PutIncident(ctx, platform.Incident{ID: "inc-1", TenantID: "t1", Status: platform.IncidentOpen, OpenedAt: now.Add(-2 * time.Hour)})

	esc, err := d.EscalateOverdue(ctx, "t1", 30)
	if err != nil {
		t.Fatal(err)
	}
	if len(esc) != 0 || len(alerter.alerts) != 0 {
		t.Fatalf("no escalation should fire during a maintenance window, got esc=%d alerts=%d", len(esc), len(alerter.alerts))
	}
}

// TestOpenFor_OpensWithoutResolving proves the event-driven ingest path: OpenFor opens incidents for
// present high findings but NEVER resolves an existing incident whose key is absent — so an
// identity/SaaS ingest can't wipe a scan incident it doesn't carry.
func TestOpenFor_OpensWithoutResolving(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := newDetector(st)

	// a scan incident already exists (from a web finding)
	if _, err := d.Reconcile(ctx, "t1", []types.Finding{crit("nuclei::sqli", "https://app/x")}, nil); err != nil {
		t.Fatal(err)
	}
	// an identity threat is ingested via OpenFor — carries NONE of the scan keys
	res, err := d.OpenFor(ctx, "t1", []types.Finding{crit("identitythreat::mfa_removed", "alice@acme.com")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Opened) != 1 {
		t.Fatalf("OpenFor should open the identity incident, got %+v", res)
	}
	if len(res.Resolved) != 0 {
		t.Fatalf("OpenFor must NEVER resolve — the scan incident's key is absent but must survive, got resolved=%+v", res.Resolved)
	}
	if n := len(openIncidents(t, st, "t1")); n != 2 {
		t.Fatalf("both the scan AND the identity incident must be open, got %d", n)
	}
}

// countingAlerter tallies how many incident-opened pages fire.
type countingAlerter struct{ n int }

func (c *countingAlerter) IncidentOpened(_ context.Context, _ platform.Incident) error {
	c.n++
	return nil
}

// TestAlertCap_BoundsPagingButOpensAll proves a bulk event opens every incident (all in the UI) but
// pages the on-call at most AlertCap times — no alert storm for a mid-size org.
func TestAlertCap_BoundsPagingButOpensAll(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	ca := &countingAlerter{}
	d := newDetector(st)
	d.Alerter = ca
	d.AlertCap = 5

	// 50 distinct high findings (e.g. 50 users lose MFA in one IdP export)
	var fs []types.Finding
	for i := 0; i < 50; i++ {
		fs = append(fs, types.Finding{ID: string(rune('A' + i)), RuleID: "identitythreat::mfa_removed",
			Endpoint: "user" + string(rune('0'+i)), Severity: types.SeverityHigh, Title: "mfa removed"})
	}
	res, err := d.OpenFor(ctx, "t1", fs, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Opened) != 50 {
		t.Fatalf("every incident must open (UI triage), got %d", len(res.Opened))
	}
	if ca.n != 5 {
		t.Fatalf("paging must be capped at AlertCap=5, got %d pages", ca.n)
	}
}
