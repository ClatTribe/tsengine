package l2

import "testing"

// The ≤12 cap (§2.6) is a capability constraint, not bureaucracy: past ~12 visible tools, model
// tool-use accuracy degrades steeply. Adding five acting tools to an eleven-tool catalog would blow
// it in every phase — the agent would gain hands and lose the accuracy to use them.
//
// Phase-scoping is what makes the belt fit. These tests fail if someone unscopes a tool, which is the
// easy mistake: it looks harmless and quietly makes the Lead worse.
func TestEngineerCatalog_StaysUnderTheToolCap(t *testing.T) {
	d := Deps{Engineer: EngineerTools(nil, nil, nil, nil, nil, nil)}
	c := BuildCatalog(d)

	if err := c.Validate(); err != nil {
		t.Fatalf("catalog with the engineer belt must still satisfy the ≤12 cap: %v", err)
	}
	for _, p := range []Phase{PhaseTriage, PhaseInvestigate, PhaseChain, PhaseReport} {
		if n := len(c.exposedIn(p)); n > 12 {
			t.Errorf("phase %s exposes %d tools, over the cap", p, n)
		}
	}
}

// The belt has to actually be REACHABLE — a cap satisfied by hiding every acting tool would be a
// regression dressed as compliance.
func TestEngineerCatalog_ActingToolsAreReachableInTheRightPhase(t *testing.T) {
	c := BuildCatalog(Deps{Engineer: EngineerTools(nil, nil, nil, nil, nil, nil)})

	want := map[string]Phase{
		"search_estate":    PhaseTriage,
		"check_fix_status": PhaseTriage,
		"request_proof":    PhaseInvestigate,
		"propose_fix":      PhaseReport,
		"open_ticket":      PhaseReport,
	}
	for tool, phase := range want {
		found := false
		for _, s := range c.exposedIn(phase) {
			if s.Name == tool {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("%s is not exposed in %s — the agent can never call it", tool, phase)
		}
	}
}

// Unwired → the catalog is unchanged. A deployment without the platform's adapters must not spend cap
// on tools that can only answer "not available".
func TestEngineerCatalog_UnwiredLeavesTheCatalogUntouched(t *testing.T) {
	base := len(BuildCatalog(Deps{}))
	withBelt := len(BuildCatalog(Deps{Engineer: EngineerTools(nil, nil, nil, nil, nil, nil)}))
	if base != withBelt-6 {
		t.Errorf("base=%d withBelt=%d — expected exactly the 6 acting tools to be added", base, withBelt)
	}
	if got := len(BuildCatalog(Deps{Engineer: nil})); got != base {
		t.Errorf("nil Engineer changed the catalog size (%d vs %d)", got, base)
	}
}
