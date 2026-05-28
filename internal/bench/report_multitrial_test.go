package bench

import (
	"math"
	"strings"
	"testing"
)

func TestStats_MedianP10P90(t *testing.T) {
	s := stats([]float64{0.2, 0.4, 0.6, 0.8, 1.0})
	if s.N != 5 {
		t.Errorf("N: %d", s.N)
	}
	if math.Abs(s.Median-0.6) > 1e-9 {
		t.Errorf("median: got %v, want 0.6", s.Median)
	}
	if s.Min != 0.2 || s.Max != 1.0 {
		t.Errorf("min/max: %v/%v", s.Min, s.Max)
	}
	// p10 of [0.2..1.0] with linear interp ≈ 0.28
	if s.P10 < 0.2 || s.P10 > 0.4 {
		t.Errorf("p10 out of range: %v", s.P10)
	}
	if s.P90 < 0.8 || s.P90 > 1.0 {
		t.Errorf("p90 out of range: %v", s.P90)
	}
}

func TestStats_SingleSample(t *testing.T) {
	s := stats([]float64{0.7})
	if s.Median != 0.7 || s.P10 != 0.7 || s.P90 != 0.7 {
		t.Errorf("single sample stats wrong: %+v", s)
	}
}

func TestStats_Empty(t *testing.T) {
	if s := stats(nil); s.N != 0 {
		t.Errorf("empty stats N: %d", s.N)
	}
}

func TestRender_AlwaysCitesCompetitors(t *testing.T) {
	// The render_report guard (CLAUDE.md §14.2.2): every report must
	// carry a competitors section.
	f := &Fixture{
		Name: "x", Asset: "container_image", Metric: MetricMustFindRecall,
		Competitors: Competitors{
			Leaderboard: "Trivy/Snyk self-published",
			Scores:      map[string]string{"Trivy": "n/a"},
			Note:        "no neutral leaderboard",
		},
	}
	res := &RunResult{Fixture: "x", AllPass: true, RecallStats: stats([]float64{1.0})}
	out := Render(f, res)
	if !strings.Contains(out, "competitors:") {
		t.Errorf("report missing competitors section:\n%s", out)
	}
	if !strings.Contains(out, "Trivy/Snyk self-published") {
		t.Errorf("report missing leaderboard citation:\n%s", out)
	}
	if !strings.Contains(out, "PASS") {
		t.Errorf("report missing verdict:\n%s", out)
	}
}

func TestRenderAblation_ShowsBothDeltas(t *testing.T) {
	f := &Fixture{Name: "x"}
	a := &Ablation{
		Enabled:  &RunResult{RecallStats: stats([]float64{1.0}), EnrichStats: stats([]float64{1.0})},
		Disabled: &RunResult{RecallStats: stats([]float64{1.0}), EnrichStats: stats([]float64{0.0})},
	}
	out := RenderAblation(f, a)
	if !strings.Contains(out, "enrichment coverage") || !strings.Contains(out, "L1.5 lift") {
		t.Errorf("ablation report missing enrichment delta:\n%s", out)
	}
}
