package bench

import (
	"strings"
	"testing"
)

func TestStatusFor(t *testing.T) {
	cases := []struct {
		measured, bar float64
		want          string
	}{
		{-1, 0.56, "not_run"},
		{0.40, 0.35, "met"},
		{0.30, 0.56, "below"},
		{1.0, 1.0, "met"},
		{0.99, 1.0, "below"},
	}
	for _, c := range cases {
		if got := statusFor(c.measured, c.bar); got != c.want {
			t.Errorf("statusFor(%.2f, %.2f) = %q, want %q", c.measured, c.bar, got, c.want)
		}
	}
}

func TestScoreboard_RendersVerdictsAndCompetitors(t *testing.T) {
	md := Scoreboard(map[string]float64{
		"repo_sast": 0.40, // ≥ Fortify 35 → met
		"web_dast":  0.30, // < ZAP 56 → below
		// the rest omitted → pending
	})

	// every category appears
	for _, want := range []string{"Web app · DAST", "Repository · SAST", "L2 agent · autonomy", "API · recall parity"} {
		if !strings.Contains(md, want) {
			t.Errorf("scoreboard missing category %q", want)
		}
	}
	// verdicts
	if !strings.Contains(md, "✅ at/above par") || !strings.Contains(md, "⚠️ below") || !strings.Contains(md, "— pending run") {
		t.Errorf("scoreboard missing a verdict badge:\n%s", md)
	}
	// competitor leaderboards are cited (the bar)
	for _, want := range []string{"Acunetix", "Veracode", "XBOW"} {
		if !strings.Contains(md, want) {
			t.Errorf("scoreboard must cite competitor %q", want)
		}
	}
	// summary line present
	if !strings.Contains(md, "**Summary:**") {
		t.Errorf("scoreboard missing summary line")
	}
}

func TestScoreboard_EmptyResultsAllPending(t *testing.T) {
	md := Scoreboard(nil)
	if !strings.Contains(md, "pending a live run") {
		t.Errorf("empty results should render all-pending summary:\n%s", md)
	}
	if strings.Contains(md, "✅ at/above par") {
		t.Errorf("empty results must not show any met verdict")
	}
}
