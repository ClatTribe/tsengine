package bench

import (
	"strings"
	"testing"
)

// TestCloudDiscrimination_Headroom: the headroom math + the discriminates verdict.
func TestCloudDiscrimination_Headroom(t *testing.T) {
	// a large account: substrate finds all 200 at production budget but only 150 at a tight scale budget
	// → 50 real, recoverable paths of headroom (25%). This scenario measures agent quality.
	r := ComputeCloudDiscrimination("large", 200, 1600, 5, 200, 150)
	if !r.Discriminates() {
		t.Error("a scenario the bounded substrate under-covers must DISCRIMINATE")
	}
	if r.Headroom != 50 {
		t.Errorf("headroom should be 50, got %d", r.Headroom)
	}
	if r.HeadroomPct != 0.25 {
		t.Errorf("headroom pct should be 0.25, got %v", r.HeadroomPct)
	}

	// a CLEAN scenario: the substrate finds everything at both budgets → 0 headroom, must NOT discriminate
	// (this is the seeded synthetic account where both substrate and a frontier agent scored 100%).
	clean := ComputeCloudDiscrimination("clean", 2, 20, 5, 2, 2)
	if clean.Discriminates() {
		t.Error("a scenario the substrate fully covers must NOT be flagged as discriminating")
	}
	if clean.Headroom != 0 {
		t.Errorf("a fully-covered scenario has 0 headroom, got %d", clean.Headroom)
	}

	// guard: a noisy input where the bounded run claims MORE than the ceiling is clamped (never negative headroom).
	g := ComputeCloudDiscrimination("x", 10, 20, 5, 8, 9)
	if g.Headroom != 0 || g.FoundScale != 8 {
		t.Errorf("scale can't exceed the ceiling; want headroom 0 & foundScale 8, got headroom=%d foundScale=%d", g.Headroom, g.FoundScale)
	}

	// the render must state the verdict + the headroom for the operator.
	out := RenderCloudDiscrimination(r)
	for _, want := range []string{"AGENT HEADROOM", "DISCRIMINATES", "50 path"} {
		if !strings.Contains(out, want) {
			t.Errorf("render missing %q:\n%s", want, out)
		}
	}
}
