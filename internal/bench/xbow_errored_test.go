package bench

import (
	"strings"
	"testing"
)

// TestAggregateXBOW_ExcludesErrored: a benchmark that could not be BUILT or STARTED (a docker-hub pull
// flake, an EOL-apt build-rot, a compose-up failure) is an INFRA failure — the agent never assessed the
// app. Counting it as an unsolved detection result understates the true solve-rate (observed live:
// XBEN-082 failed on a transient `nginx:alpine` TLS-handshake timeout and was scored command_injection
// 0/1). Errored results must be EXCLUDED from the detection denominators (overall, by-level, by-tag) and
// reported separately — honest measurement (§14), not hidden.
func TestAggregateXBOW_ExcludesErrored(t *testing.T) {
	results := []XBOWResult{
		{ID: "A", Level: 1, Tags: []string{"ssti"}, Solved: true, Findings: 1, Note: "flag captured"},
		{ID: "B", Level: 1, Tags: []string{"sqli"}, Solved: false, Findings: 1, Note: "no flag"}, // real detection miss (agent ran)
		{ID: "C", Level: 2, Tags: []string{"command_injection"}, Errored: true, Note: "compose build failed: nginx:alpine TLS timeout"},
	}
	sb := AggregateXBOW(results)

	if sb.Total != 2 {
		t.Errorf("Total should exclude the errored benchmark: got %d, want 2", sb.Total)
	}
	if sb.Solved != 1 {
		t.Errorf("Solved: got %d, want 1", sb.Solved)
	}
	if sb.Errored != 1 {
		t.Errorf("Errored count: got %d, want 1", sb.Errored)
	}
	if sb.SolveRate != 0.5 {
		t.Errorf("SolveRate should be 1/2 over the RAN benchmarks (not 1/3): got %v, want 0.5", sb.SolveRate)
	}
	// the errored benchmark's tag/level must NOT pollute the detection cuts
	if _, ok := sb.ByTag["command_injection"]; ok {
		t.Errorf("errored benchmark's tag leaked into ByTag: %+v", sb.ByTag)
	}
	if l2, ok := sb.ByLevel[2]; ok && l2.Total != 0 {
		t.Errorf("errored benchmark's level leaked into ByLevel: %+v", sb.ByLevel)
	}

	// the render must surface the exclusion honestly (not silently drop it)
	out := RenderXBOWScoreboard(sb)
	if !strings.Contains(strings.ToLower(out), "excluded") && !strings.Contains(strings.ToLower(out), "errored") {
		t.Errorf("scoreboard must report the excluded/errored count honestly:\n%s", out)
	}
	if !strings.Contains(out, "1/2") {
		t.Errorf("overall should be 1/2 (ran benchmarks), not 1/3:\n%s", out)
	}
}
