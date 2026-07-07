package main

import "testing"

// TestParseDiscovery_EmptySentinels: a model answering a clean estate writes "HIGH_IMPACT: none" (or n/a,
// nothing, -). That must parse to ZERO picks, not an invented id — else the zero-impact precision-floor test
// would falsely fail a correct engineer. Real ids alongside a sentinel are still kept.
func TestParseDiscovery_EmptySentinels(t *testing.T) {
	for _, in := range []string{"HIGH_IMPACT: none", "HIGH_IMPACT: (none)", "HIGH_IMPACT: n/a", "HIGH_IMPACT:", "HIGH_IMPACT: nothing", "HIGH_IMPACT: -"} {
		if got := parseDiscovery(in); len(got.HighImpactIDs) != 0 {
			t.Errorf("%q must parse to zero picks, got %v", in, got.HighImpactIDs)
		}
	}
	// a real id is preserved; a stray sentinel mixed in is dropped.
	got := parseDiscovery("HIGH_IMPACT: leaked-key, none")
	if len(got.HighImpactIDs) != 1 || got.HighImpactIDs[0] != "leaked-key" {
		t.Errorf("real id must survive, sentinel dropped: %v", got.HighImpactIDs)
	}
}
