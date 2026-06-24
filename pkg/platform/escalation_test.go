package platform

import (
	"testing"
	"time"
)

func TestEscalationPolicy_ChannelsFor(t *testing.T) {
	pol := &EscalationPolicy{
		Enabled: true,
		Tiers: []EscalationTier{
			{MinSeverity: "critical", Channels: []string{"pagerduty", "slack"}},
			{MinSeverity: "high", Channels: []string{"slack"}},
			{MinSeverity: "low", Channels: []string{"email"}},
		},
	}
	cases := []struct {
		sev     string
		want    []string
		matched bool
	}{
		{"critical", []string{"pagerduty", "slack"}, true}, // first tier
		{"high", []string{"slack"}, true},                  // second tier (critical floor not met)
		{"medium", []string{"email"}, true},                // falls through to the low tier (medium ≥ low)
		{"low", []string{"email"}, true},
		{"info", nil, false}, // below every floor
	}
	for _, c := range cases {
		got, m := pol.ChannelsFor(c.sev)
		if m != c.matched {
			t.Errorf("%s: matched=%v want %v", c.sev, m, c.matched)
		}
		if len(got) != len(c.want) {
			t.Errorf("%s: channels=%v want %v", c.sev, got, c.want)
			continue
		}
		for i := range got {
			if got[i] != c.want[i] {
				t.Errorf("%s: channel[%d]=%q want %q", c.sev, i, got[i], c.want[i])
			}
		}
	}
}

func TestEscalationPolicy_ChannelsFor_DisabledOrEmpty(t *testing.T) {
	if _, m := (*EscalationPolicy)(nil).ChannelsFor("critical"); m {
		t.Error("nil policy must not match")
	}
	if _, m := (&EscalationPolicy{Enabled: false, Tiers: []EscalationTier{{MinSeverity: "low", Channels: []string{"slack"}}}}).ChannelsFor("critical"); m {
		t.Error("disabled policy must not match")
	}
	if _, m := (&EscalationPolicy{Enabled: true}).ChannelsFor("critical"); m {
		t.Error("empty-tiers policy must not match")
	}
}

func TestIncident_Overdue(t *testing.T) {
	base := time.Date(2026, 6, 24, 10, 0, 0, 0, time.UTC)
	open := func() Incident { return Incident{Status: IncidentOpen, OpenedAt: base} }

	t.Run("window off → never overdue", func(t *testing.T) {
		if open().Overdue(0, base.Add(time.Hour)) {
			t.Error("ackWindowMins=0 must disable timed escalation")
		}
	})
	t.Run("within window → not yet", func(t *testing.T) {
		if open().Overdue(30, base.Add(20*time.Minute)) {
			t.Error("20m < 30m window — should not be overdue")
		}
	})
	t.Run("past window, never escalated → overdue", func(t *testing.T) {
		if !open().Overdue(30, base.Add(31*time.Minute)) {
			t.Error("31m > 30m window — should be overdue")
		}
	})
	t.Run("acknowledged → never overdue", func(t *testing.T) {
		inc := open()
		inc.AcknowledgedAt = base.Add(5 * time.Minute)
		if inc.Overdue(30, base.Add(2*time.Hour)) {
			t.Error("an acknowledged incident must not auto-escalate")
		}
	})
	t.Run("resolved → never overdue", func(t *testing.T) {
		inc := open()
		inc.Status = IncidentResolved
		if inc.Overdue(30, base.Add(2*time.Hour)) {
			t.Error("a resolved incident must not auto-escalate")
		}
	})
	t.Run("re-pings at most once per window", func(t *testing.T) {
		inc := open()
		inc.LastEscalatedAt = base.Add(31 * time.Minute)
		// 10 min after last escalation, still inside the next window → no re-ping
		if inc.Overdue(30, base.Add(41*time.Minute)) {
			t.Error("should not re-ping within a window of the last escalation")
		}
		// a full window after last escalation → re-ping
		if !inc.Overdue(30, base.Add(62*time.Minute)) {
			t.Error("should re-ping a full window after the last escalation")
		}
	})
}
