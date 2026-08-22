package platform

import (
	"testing"
	"time"
)

var opened = time.Date(2026, 8, 1, 0, 0, 0, 0, time.UTC)

func kevPolicy() *SLAPolicy {
	return &SLAPolicy{
		Enabled:                true,
		KEVResolveHours:        14 * 24,
		RansomwareResolveHours: 48,
		Targets:                []SLATarget{{Severity: "high", AckHours: 24, ResolveHours: 30 * 24}},
	}
}

func inc(kev, ransom bool, due time.Time) Incident {
	return Incident{Severity: "high", OpenedAt: opened, Status: IncidentOpen,
		KEV: kev, Ransomware: ransom, KEVDueAt: due}
}

func TestSLA_RansomwareTightensBeyondKEV(t *testing.T) {
	b, ok := kevPolicy().Evaluate(inc(true, true, time.Time{}), opened.Add(72*time.Hour))
	if !ok {
		t.Fatal("policy should evaluate")
	}
	want := opened.Add(48 * time.Hour)
	if !b.ResolveDueAt.Equal(want) {
		t.Fatalf("ransomware clock should win, got %v want %v", b.ResolveDueAt, want)
	}
	if !b.RansomwareAccelerated || b.KEVAccelerated {
		t.Fatal("the UI must be able to say WHY the deadline is this short, and it is not plain KEV")
	}
	if !b.ResolveBreached {
		t.Fatal("72h past a 48h deadline is a breach")
	}
}

func TestSLA_KEVWithoutRansomwareKeepsTheKEVClock(t *testing.T) {
	b, _ := kevPolicy().Evaluate(inc(true, false, time.Time{}), opened)
	if !b.KEVAccelerated || b.RansomwareAccelerated {
		t.Fatal("KEV alone must not claim ransomware urgency")
	}
	if !b.ResolveDueAt.Equal(opened.Add(14 * 24 * time.Hour)) {
		t.Fatalf("KEV window should apply, got %v", b.ResolveDueAt)
	}
}

// THE POINT OF AN ABSOLUTE DEADLINE. A KEV CVE catalogued months ago is ALREADY past
// its due date. Computing a window from when we happened to notice would restart a clock
// the government already ran out — telling a customer they have two weeks when the
// authority's answer is that they are months late.
func TestSLA_CISADueDateIsAbsoluteAndNotRestartedByOurDiscovery(t *testing.T) {
	past := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC) // long before OpenedAt
	b, _ := kevPolicy().Evaluate(inc(true, false, past), opened.Add(time.Hour))
	if !b.ResolveDueAt.Equal(past) {
		t.Fatalf("CISA's date must be used verbatim, got %v want %v", b.ResolveDueAt, past)
	}
	if !b.CISADeadline {
		t.Fatal("the breach must record that the deadline is the authority's, not ours")
	}
	if !b.ResolveBreached {
		t.Fatal("a deadline that passed before we noticed is still a breach — that is the honest answer")
	}
}

// It can only TIGHTEN: a CISA date further out than our computed clock must not relax it.
func TestSLA_CISADueDateNeverRelaxesATighterClock(t *testing.T) {
	far := opened.Add(365 * 24 * time.Hour)
	b, _ := kevPolicy().Evaluate(inc(true, true, far), opened)
	if !b.ResolveDueAt.Equal(opened.Add(48 * time.Hour)) {
		t.Fatalf("a distant CISA date must not loosen the ransomware clock, got %v", b.ResolveDueAt)
	}
	if b.CISADeadline {
		t.Fatal("the deadline did not come from CISA here")
	}
}

func TestSLA_DisabledPolicyIgnoresEveryExploitationSignal(t *testing.T) {
	p := kevPolicy()
	p.Enabled = false
	if _, ok := p.Evaluate(inc(true, true, opened.Add(-time.Hour)), opened); ok {
		t.Fatal("a disabled policy must not breach on any signal")
	}
}

func TestSLA_ResolvedIncidentNeverBreaches(t *testing.T) {
	i := inc(true, true, time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC))
	i.Status = IncidentResolved
	b, _ := kevPolicy().Evaluate(i, opened.Add(1000*time.Hour))
	if b.ResolveBreached {
		t.Fatal("a resolved incident is not in breach however late the deadline was")
	}
}
