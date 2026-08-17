package platform

import (
	"testing"
	"time"
)

func openedAgo(h int) time.Time { return time.Now().Add(-time.Duration(h) * time.Hour) }

// BOD 22-01: a KEV-listed incident gets the compressed remediation clock even
// though its severity tier allows much longer.
func TestSLA_KEVCompressesResolveClock(t *testing.T) {
	p := &SLAPolicy{
		Enabled:         true,
		Targets:         []SLATarget{{Severity: "medium", AckHours: 24, ResolveHours: 720}}, // 30 days
		KEVResolveHours: 336,                                                               // 14 days (BOD 22-01)
	}
	now := time.Now()
	inc := Incident{Severity: "medium", Status: IncidentOpen, OpenedAt: openedAgo(400), KEV: true}

	b, ok := p.Evaluate(inc, now)
	if !ok {
		t.Fatal("KEV incident should be SLA-tracked")
	}
	if !b.KEVAccelerated {
		t.Error("resolve deadline should be marked KEV-accelerated")
	}
	if !b.ResolveBreached {
		t.Errorf("400h open vs 336h KEV deadline must breach; due=%v", b.ResolveDueAt)
	}

	// The same incident WITHOUT the KEV flag is still inside its 720h tier.
	noKEV := inc
	noKEV.KEV = false
	b2, _ := p.Evaluate(noKEV, now)
	if b2.ResolveBreached || b2.KEVAccelerated {
		t.Errorf("non-KEV medium at 400h must not breach a 720h clock: %+v", b2)
	}
}

// The override may only TIGHTEN. A KEV window looser than the severity target
// must never relax the stricter clock.
func TestSLA_KEVNeverRelaxesATighterClock(t *testing.T) {
	p := &SLAPolicy{
		Enabled:         true,
		Targets:         []SLATarget{{Severity: "critical", ResolveHours: 24}},
		KEVResolveHours: 336, // looser than the critical tier
	}
	inc := Incident{Severity: "critical", Status: IncidentOpen, OpenedAt: openedAgo(48), KEV: true}
	b, ok := p.Evaluate(inc, time.Now())
	if !ok {
		t.Fatal("should be tracked")
	}
	if b.KEVAccelerated {
		t.Error("a looser KEV window must not be applied")
	}
	if !b.ResolveBreached {
		t.Error("the tighter 24h critical clock must still breach at 48h")
	}
}

// Being exploited in the wild is itself the deadline: the override applies even
// when the severity tier has no target at all.
func TestSLA_KEVAppliesWithNoSeverityTarget(t *testing.T) {
	p := &SLAPolicy{Enabled: true, Targets: []SLATarget{{Severity: "critical", ResolveHours: 24}}, KEVResolveHours: 336}
	inc := Incident{Severity: "low", Status: IncidentOpen, OpenedAt: openedAgo(400), KEV: true}
	b, ok := p.Evaluate(inc, time.Now())
	if !ok {
		t.Fatal("a KEV incident must be tracked even with no target for its severity")
	}
	if !b.KEVAccelerated || !b.ResolveBreached {
		t.Errorf("KEV deadline should apply and breach: %+v", b)
	}
	// No ack target exists for "low", so the ack clock stays untracked.
	if !b.AckDueAt.IsZero() || b.AckBreached {
		t.Errorf("ack clock should be untracked without a severity target: %+v", b)
	}
}

// §10: the override is driven by the real corpus-backed flag, and a resolved
// incident never breaches.
func TestSLA_KEVGroundedAndRespectsResolved(t *testing.T) {
	p := &SLAPolicy{Enabled: true, KEVResolveHours: 336}

	// No KEV flag, no severity target → not tracked at all (nothing invented).
	if _, ok := p.Evaluate(Incident{Severity: "high", Status: IncidentOpen, OpenedAt: openedAgo(999)}, time.Now()); ok {
		t.Error("without a KEV flag or a severity target there is nothing to track")
	}
	// Disabled policy → no override.
	off := &SLAPolicy{Enabled: false, KEVResolveHours: 336}
	if _, ok := off.Evaluate(Incident{Severity: "high", KEV: true, Status: IncidentOpen, OpenedAt: openedAgo(999)}, time.Now()); ok {
		t.Error("a disabled policy must not apply the KEV override")
	}
	// Resolved → met clock, no breach.
	res := Incident{Severity: "high", KEV: true, Status: IncidentResolved, OpenedAt: openedAgo(999)}
	b, ok := p.Evaluate(res, time.Now())
	if !ok {
		t.Fatal("tracked")
	}
	if b.ResolveBreached {
		t.Error("a resolved incident must never breach the resolve clock")
	}
}
