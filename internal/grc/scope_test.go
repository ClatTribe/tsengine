package grc

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

func TestSuggestedFrameworks_GatedOnApplicability(t *testing.T) {
	base := SuggestedFrameworks(platform.ComplianceProfile{})
	// trust baseline always; never HIPAA/PCI without the fact (§10)
	if !has(base, FrameworkSOC2) || has(base, FrameworkHIPAA) || has(base, FrameworkPCI) {
		t.Errorf("baseline wrong: %v", base)
	}
	phi := SuggestedFrameworks(platform.ComplianceProfile{HandlesPHI: true, ProcessesCards: true})
	if !has(phi, FrameworkHIPAA) || !has(phi, FrameworkPCI) {
		t.Errorf("PHI+cards should add HIPAA+PCI: %v", phi)
	}
}

func TestScopeReadiness_CountsConnected(t *testing.T) {
	r := ScopeReadiness([]string{"soc2"}, map[string]bool{"identity": true, "cloud": true})
	if r.Recommended != 6 || r.Connected != 2 {
		t.Errorf("want 2 of 6 connected, got %d of %d", r.Connected, r.Recommended)
	}
	// honest note while partial
	if !containsWord(r.Note, "not a certification") {
		t.Errorf("partial readiness must disclaim certification: %q", r.Note)
	}
}

func has(xs []string, w string) bool {
	for _, x := range xs {
		if x == w {
			return true
		}
	}
	return false
}

func TestScopeReadiness_NamesUnautomatedAssetAreas(t *testing.T) {
	r := ScopeReadiness([]string{"soc2"}, map[string]bool{"identity": true, "cloud": true, "code": true, "saas": true, "email": true, "web_api": true})
	// Even fully connected, the manual areas (endpoint/logging/backup/HR) must be named + the note must
	// disclaim certification — the asset-type-coverage half of no-false-compliant.
	if len(r.ManualAreas) < 4 {
		t.Errorf("manual control areas (endpoint/logging/backup/hr) must be surfaced, got %d", len(r.ManualAreas))
	}
	if !containsWord(r.Note, "not a certification") {
		t.Errorf("even fully connected, the note must disclaim certification: %q", r.Note)
	}
	cats := map[string]bool{}
	for _, m := range r.ManualAreas {
		cats[m.Category] = true
	}
	for _, want := range []string{"endpoint", "logging", "backup", "hr"} {
		if !cats[want] {
			t.Errorf("manual area %q missing", want)
		}
	}
}
