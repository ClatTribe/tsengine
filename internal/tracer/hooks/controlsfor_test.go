package hooks

import "testing"

// TestControlsFor proves the crosswalk yields a framework's assessable control set — used to seed an
// audit engagement for a fresh tenant (no posture) so it isn't an empty/useless audit.
func TestControlsFor(t *testing.T) {
	c := NewCompliance()
	soc2 := c.ControlsFor("soc2")
	if len(soc2) == 0 {
		t.Fatal("soc2 must yield a non-empty control set from the crosswalk")
	}
	// must be sorted + distinct
	for i := 1; i < len(soc2); i++ {
		if soc2[i] <= soc2[i-1] {
			t.Errorf("controls not sorted+distinct: %v", soc2)
			break
		}
	}
	// a couple of well-known SOC2 controls the crosswalk maps to
	want := map[string]bool{"CC6.1": false, "CC7.1": false}
	for _, id := range soc2 {
		if _, ok := want[id]; ok {
			want[id] = true
		}
	}
	for id, found := range want {
		if !found {
			t.Errorf("expected SOC2 control %q in the seeded set, got %v", id, soc2)
		}
	}
	if c.ControlsFor("not-a-framework") != nil {
		t.Error("unknown framework must return nil (no guessed controls)")
	}
}
