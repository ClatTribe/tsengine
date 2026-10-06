package tenanteval

import "testing"

func run(arm, model, hash string, passed, cases int, at string) Run {
	return Run{Arm: arm, Model: model, SuiteHash: hash, Passed: passed, Cases: cases, RanAt: at}
}

// Three outcomes, and unmeasured is never a pass.
func TestRouteVerdict(t *testing.T) {
	const h, cand = "suite-1", "ollama/qwen"
	inc := run(ArmModel, "openai/frontier", h, 9, 12, "2026-10-01T00:00:00Z")
	cases := []struct {
		name string
		runs []Run
		want string
	}{
		{"no trial", []Run{inc}, RouteUnmeasured},
		{"too few cases", []Run{inc, run(ArmCandidate, cand, h, 4, 4, "2026-10-02T00:00:00Z")}, RouteUnmeasured},
		{"no incumbent", []Run{run(ArmCandidate, cand, h, 12, 12, "2026-10-02T00:00:00Z")}, RouteUnmeasured},
		{"trial on an older suite", []Run{inc, run(ArmCandidate, cand, "suite-0", 12, 12, "2026-10-02T00:00:00Z")}, RouteUnmeasured},
		{"equal", []Run{inc, run(ArmCandidate, cand, h, 9, 12, "2026-10-02T00:00:00Z")}, RouteMatches},
		{"better", []Run{inc, run(ArmCandidate, cand, h, 11, 12, "2026-10-02T00:00:00Z")}, RouteMatches},
		{"worse", []Run{inc, run(ArmCandidate, cand, h, 8, 12, "2026-10-02T00:00:00Z")}, RouteWorse},
		{"latest trial wins", []Run{inc,
			run(ArmCandidate, cand, h, 12, 12, "2026-10-02T00:00:00Z"),
			run(ArmCandidate, cand, h, 3, 12, "2026-10-03T00:00:00Z")}, RouteWorse},
		{"another model's trial is not evidence", []Run{inc, run(ArmCandidate, "ollama/other", h, 12, 12, "2026-10-02T00:00:00Z")}, RouteUnmeasured},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			ev := RouteVerdict(c.runs, cand, h)
			if ev.Status != c.want || ev.Reason == "" {
				t.Fatalf("got %s (%q), want %s", ev.Status, ev.Reason, c.want)
			}
		})
	}
}

// A trial is recorded under its own arm, so it can never move the assigned model's trend.
func TestCandidateRunsStayOutOfTheModelHistory(t *testing.T) {
	runs := []Run{run(ArmModel, "a", "h", 1, 12, "1"), run(ArmCandidate, "b", "h", 12, 12, "2")}
	if got := RunsForArm(runs, ArmModel); len(got) != 1 || got[0].Model != "a" {
		t.Fatalf("a candidate trial leaked into the model arm: %+v", got)
	}
}
