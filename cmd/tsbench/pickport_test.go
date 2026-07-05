package main

import "testing"

// TestPickWebTargetPort: when a benchmark publishes MORE than one port (the info-disclosure+ssh class
// runs a web app on :80 AND an SSH server on :22; other benches add a DB), the harness must target the
// HTTP/web surface, never SSH/DB. Observed live: XBEN-042 published 22->51261 and 80->51262; composePort
// returned the FIRST (SSH), so the agent's HTTP probes hit the SSH banner (malformed-status error) and
// the web attack surface was out of scope — the benchmark was unsolvable for a harness reason, not a
// detection one.
func TestPickWebTargetPort(t *testing.T) {
	cases := []struct {
		name string
		pubs []composePub
		want string
	}{
		{"web+ssh, ssh first", []composePub{{51261, 22}, {51262, 80}}, "51262"},
		{"web+ssh, web first (order-independent)", []composePub{{51262, 80}, {51261, 22}}, "51262"},
		{"web+mysql", []composePub{{40001, 3306}, {40002, 5000}}, "40002"},
		{"ssh + non-standard web port: avoid ssh", []composePub{{51261, 22}, {51263, 9999}}, "51263"},
		{"single web port", []composePub{{55000, 80}}, "55000"},
		{"empty", nil, ""},
		{"all service ports → fall back to first (unchanged)", []composePub{{60001, 3306}, {60002, 6379}}, "60001"},
	}
	for _, c := range cases {
		if got := pickWebTargetPort(c.pubs); got != c.want {
			t.Errorf("%s: pickWebTargetPort(%v) = %q, want %q", c.name, c.pubs, got, c.want)
		}
	}
}
