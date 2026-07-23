package bench

import (
	"fmt"
	"strings"
	"testing"
)

// TestContainment_GatePasses is the release gate itself: every containment invariant must hold against
// the real shipped guards. If this fails, an agent can exceed scope / reach metadata / cross tenants —
// do NOT ship.
func TestContainment_GatePasses(t *testing.T) {
	r := RunContainment()
	if !r.Passed() {
		t.Fatalf("CONTAINMENT GATE FAILED (%d/%d held). Violations:\n  %s",
			r.Held, r.Total, strings.Join(r.Violations, "\n  "))
	}
	if r.Total < 6 {
		t.Errorf("expected a meaningful suite, got only %d cases", r.Total)
	}
	// every case must be backed and non-empty
	for _, d := range r.Details {
		if d.Category == "" || d.Name == "" || d.Invariant == "" {
			t.Errorf("under-specified case: %+v", d)
		}
	}
}

// TestContainment_GateIsNotVacuous proves the gate actually CATCHES a violation (and a panicking
// guard) — a gate that always passes is worthless.
func TestContainment_GateIsNotVacuous(t *testing.T) {
	violating := []ContainmentCase{
		{"x", "always-holds", "ok", func() error { return nil }},
		{"x", "always-violates", "bad", func() error { return fmt.Errorf("scope exceeded") }},
		{"x", "panics", "bad", func() error { panic("guard crashed") }},
	}
	r := runContainment(violating)
	if r.Passed() {
		t.Fatal("a suite containing a violation MUST fail the gate")
	}
	if r.Held != 1 || len(r.Violations) != 2 {
		t.Errorf("want 1 held, 2 violations (incl. the panic), got held=%d violations=%d", r.Held, len(r.Violations))
	}
	// a panicking guard must be reported as a violation, not crash the runner
	joined := strings.Join(r.Violations, " ")
	if !strings.Contains(joined, "PANICKED") {
		t.Errorf("a guard that panics under adversarial input must be a violation, got: %s", joined)
	}
}
