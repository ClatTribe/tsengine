package platform

import (
	"testing"
	"time"
)

func TestSLAPolicy_Evaluate(t *testing.T) {
	base := time.Date(2026, 6, 24, 8, 0, 0, 0, time.UTC)
	pol := &SLAPolicy{Enabled: true, Targets: []SLATarget{
		{Severity: "critical", AckHours: 1, ResolveHours: 4},
		{Severity: "high", AckHours: 4, ResolveHours: 24},
	}}
	open := func(sev string) Incident { return Incident{Severity: sev, Status: IncidentOpen, OpenedAt: base} }

	t.Run("no target for severity → not tracked", func(t *testing.T) {
		if _, ok := pol.Evaluate(open("medium"), base.Add(100*time.Hour)); ok {
			t.Error("medium has no target — SLA should not apply")
		}
	})
	t.Run("disabled policy → not tracked", func(t *testing.T) {
		off := &SLAPolicy{Enabled: false, Targets: pol.Targets}
		if _, ok := off.Evaluate(open("critical"), base.Add(100*time.Hour)); ok {
			t.Error("disabled policy must not track SLA")
		}
	})
	t.Run("within both windows → no breach", func(t *testing.T) {
		b, ok := pol.Evaluate(open("critical"), base.Add(30*time.Minute))
		if !ok || b.AckBreached || b.ResolveBreached {
			t.Errorf("30m in, critical (1h ack/4h resolve) → no breach, got %+v ok=%v", b, ok)
		}
	})
	t.Run("past ack window, unacknowledged → ack breach", func(t *testing.T) {
		b, _ := pol.Evaluate(open("critical"), base.Add(2*time.Hour))
		if !b.AckBreached {
			t.Error("2h in with a 1h ack target and no ack → ack breach")
		}
		if b.ResolveBreached {
			t.Error("2h in with a 4h resolve target → not yet a resolve breach")
		}
	})
	t.Run("acknowledged → no ack breach even if late", func(t *testing.T) {
		inc := open("critical")
		inc.AcknowledgedAt = base.Add(90 * time.Minute) // acked after the 1h target, but acked
		b, _ := pol.Evaluate(inc, base.Add(3*time.Hour))
		if b.AckBreached {
			t.Error("an acknowledged incident has no ack breach")
		}
	})
	t.Run("past resolve window, still open → resolve breach", func(t *testing.T) {
		b, _ := pol.Evaluate(open("critical"), base.Add(5*time.Hour))
		if !b.ResolveBreached || !b.Breached() {
			t.Errorf("5h in with a 4h resolve target and still open → resolve breach, got %+v", b)
		}
	})
	t.Run("resolved → no resolve breach", func(t *testing.T) {
		inc := open("critical")
		inc.Status = IncidentResolved
		b, _ := pol.Evaluate(inc, base.Add(100*time.Hour))
		if b.ResolveBreached {
			t.Error("a resolved incident has no resolve breach")
		}
	})
	t.Run("0-hour clock is disabled", func(t *testing.T) {
		zero := &SLAPolicy{Enabled: true, Targets: []SLATarget{{Severity: "low", AckHours: 0, ResolveHours: 48}}}
		b, ok := zero.Evaluate(Incident{Severity: "low", Status: IncidentOpen, OpenedAt: base}, base.Add(100*time.Hour))
		if !ok || b.AckBreached {
			t.Errorf("ack_hours=0 disables the ack clock, got %+v ok=%v", b, ok)
		}
		if !b.ResolveBreached {
			t.Error("resolve_hours=48 still applies")
		}
	})
}
