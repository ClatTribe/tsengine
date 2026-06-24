package platform

import "testing"

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
