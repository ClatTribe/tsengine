package platformapi

import (
	"strings"
	"testing"
)

// A canary is a correlation key from ADR 0027 onward: detection validation joins an alert back to
// the probe that caused it. tsrt<tenant><index> repeated across runs, so index 0 was reused every
// time — fine while a canary only had to be findable in one response, and wrong as a join key. Two
// runs sharing a token cannot say which run an alert saw, and a stale alert from last week would be
// credited to today's probe.
func TestReattackCanary_IsUniqueAcrossRuns(t *testing.T) {
	// Calls the REAL generator. An earlier version of this test rebuilt the format inline and passed
	// while production was reverted to the colliding one — a test that reimplements what it checks
	// verifies its own copy of the bug.
	mk := func() []string {
		fn := reattackCanaryFn("tenant-abc")
		var out []string
		for i := 0; i < 3; i++ {
			out = append(out, fn(i))
		}
		return out
	}
	a, b := mk(), mk()
	for i := range a {
		if a[i] == b[i] {
			t.Fatalf("two runs produced the same canary at index %d (%s) — it cannot serve as a "+
				"correlation key", i, a[i])
		}
	}
	// Still unique WITHIN a run, and still carries the tenant prefix that scopes it.
	seen := map[string]bool{}
	for _, c := range a {
		if seen[c] {
			t.Errorf("duplicate canary within one run: %s", c)
		}
		seen[c] = true
		if !strings.HasPrefix(c, "tsrt") {
			t.Errorf("canary lost its prefix: %s", c)
		}
	}
}
