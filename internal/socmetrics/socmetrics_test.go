package socmetrics

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestCompute(t *testing.T) {
	now := time.Date(2026, 6, 24, 12, 0, 0, 0, time.UTC)
	sla := &platform.SLAPolicy{Enabled: true, Targets: []platform.SLATarget{
		{Severity: "critical", AckHours: 1, ResolveHours: 4},
	}}
	mk := func(id, sev, status string, openedAgo time.Duration, acked, resolvedAfter time.Duration) platform.Incident {
		inc := platform.Incident{ID: id, TenantID: "t1", Severity: sev, Status: status, OpenedAt: now.Add(-openedAgo)}
		if acked > 0 {
			inc.AcknowledgedAt = inc.OpenedAt.Add(acked)
		}
		if status == platform.IncidentResolved {
			inc.ResolvedAt = inc.OpenedAt.Add(resolvedAfter)
		}
		return inc
	}

	incs := []platform.Incident{
		// open critical, acked 30m after open, opened 2h ago → tracked, NOT breached (resolve 4h) → compliant
		mk("a", "critical", platform.IncidentOpen, 2*time.Hour, 30*time.Minute, 0),
		// open critical, unacked, opened 10h ago → resolve-breached → tracked, non-compliant, breached
		mk("b", "critical", platform.IncidentOpen, 10*time.Hour, 0, 0),
		// resolved critical, resolved 3h after open (≤4h) → compliant
		mk("c", "critical", platform.IncidentResolved, 20*time.Hour, 1*time.Hour, 3*time.Hour),
		// resolved critical, resolved 9h after open (>4h) → non-compliant (historical miss)
		mk("d", "critical", platform.IncidentResolved, 30*time.Hour, 0, 9*time.Hour),
		// open medium (no SLA target) → not tracked; opened 9 days ago → aging >7d
		mk("e", "medium", platform.IncidentOpen, 9*24*time.Hour, 0, 0),
	}

	r := Compute(incs, sla, now)

	if r.OpenIncidents != 3 || r.ResolvedIncidents != 2 {
		t.Errorf("counts: open=%d resolved=%d want 3/2", r.OpenIncidents, r.ResolvedIncidents)
	}
	if r.Acknowledged != 1 || r.Unacknowledged != 2 {
		t.Errorf("ack: acked=%d unacked=%d want 1/2", r.Acknowledged, r.Unacknowledged)
	}
	if r.SLATracked != 4 { // a,b,c,d are critical; e is medium (untracked)
		t.Errorf("sla_tracked=%d want 4", r.SLATracked)
	}
	if r.SLACompliant != 2 { // a (open, ok) + c (resolved in time)
		t.Errorf("sla_compliant=%d want 2 (a,c)", r.SLACompliant)
	}
	if r.SLABreached != 1 { // b only (open + breached); d is resolved so not "currently breached"
		t.Errorf("sla_breached=%d want 1 (b)", r.SLABreached)
	}
	if r.SLACompliancePct != 50.0 { // 2/4
		t.Errorf("compliance_pct=%v want 50.0", r.SLACompliancePct)
	}
	// MTTR over c (3h) + d (9h) = 6.0
	if r.MTTRHours != 6.0 {
		t.Errorf("mttr=%v want 6.0", r.MTTRHours)
	}
	// MTTA over a (0.5h) + c (1h) = 0.75 → 0.8 rounded
	if r.MTTAHours != 0.8 {
		t.Errorf("mtta=%v want 0.8", r.MTTAHours)
	}
	if r.AgingOver7d != 1 {
		t.Errorf("aging_over_7d=%d want 1 (e)", r.AgingOver7d)
	}
}

func TestCompute_NoSLA(t *testing.T) {
	now := time.Now()
	r := Compute([]platform.Incident{{Severity: "high", Status: platform.IncidentOpen, OpenedAt: now}}, nil, now)
	if r.SLATracked != 0 || r.SLACompliancePct != 0 {
		t.Errorf("nil SLA → nothing tracked, got tracked=%d pct=%v", r.SLATracked, r.SLACompliancePct)
	}
	if r.OpenIncidents != 1 {
		t.Errorf("should still count open incidents, got %d", r.OpenIncidents)
	}
}
