package bench

import (
	"strings"
	"testing"
)

func TestAgentLift(t *testing.T) {
	// the real measured run: bounded substrate 1/2, agent 2/2, invented 0 → +1 grounded lift (the win).
	l := ComputeAgentLift(2, 1, 2, 0)
	if !l.Lifted() || l.LiftPaths != 1 {
		t.Errorf("agent recovering a missed path with no hallucination is a LIFT, got %+v", l)
	}
	if l.LiftPct != 0.5 {
		t.Errorf("lift pct should be 0.5, got %v", l.LiftPct)
	}
	if !strings.Contains(l.Verdict(), "AGENT LIFT +1") {
		t.Errorf("verdict should announce the +1 lift, got %q", l.Verdict())
	}

	// a higher recall bought with an invented path is NOT a lift (grounding, §10).
	ung := ComputeAgentLift(2, 1, 2, 1)
	if ung.Lifted() {
		t.Error("a lift bought with a hallucinated issue must NOT count as a lift")
	}
	if !strings.Contains(ung.Verdict(), "UNGROUNDED") {
		t.Errorf("an ungrounded run must be flagged, got %q", ung.Verdict())
	}

	// a fully-covered account: agent==engine==all → no lift, and it's the non-discriminating case.
	flat := ComputeAgentLift(2, 2, 2, 0)
	if flat.Lifted() || flat.LiftPaths != 0 {
		t.Errorf("a fully-covered account has no lift, got %+v", flat)
	}
	if !strings.Contains(flat.Verdict(), "non-discriminating") {
		t.Errorf("a fully-covered account should be called out as non-discriminating, got %q", flat.Verdict())
	}

	// a regression: the agent found fewer than the substrate.
	reg := ComputeAgentLift(3, 3, 2, 0)
	if reg.Lifted() || reg.LiftPaths != -1 {
		t.Errorf("agent finding fewer is a regression, got %+v", reg)
	}
	if !strings.Contains(reg.Verdict(), "REGRESSION") {
		t.Errorf("a regression must be flagged, got %q", reg.Verdict())
	}
}
