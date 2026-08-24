package bizservice

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func assets() []platform.Asset {
	return []platform.Asset{
		{ID: "a1", Target: "checkout.acme.com", Type: "web_application"},
		{ID: "a2", Target: "api.acme.com", Type: "api"},
		{ID: "a3", Target: "marketing.acme.com", Type: "web_application"},
	}
}

func TestCompute_NoServicesIsAPromptNotAReport(t *testing.T) {
	r := Compute(nil, assets(), nil, nil)
	if r.Declared {
		t.Error("no services declared but Declared is true")
	}
	if !strings.Contains(r.Note, "is checkout at risk") {
		t.Errorf("the empty state should say what the question actually is: %q", r.Note)
	}
}

func TestCompute_GroupsFindingsByService(t *testing.T) {
	svcs := []platform.BusinessService{
		{ID: "s1", Name: "Checkout", Criticality: "critical", Owner: "payments-team", AssetIDs: []string{"a1", "a2"}},
		{ID: "s2", Name: "Marketing site", Criticality: "low", AssetIDs: []string{"a3"}},
	}
	fs := []types.Finding{
		{ID: "f1", Endpoint: "https://checkout.acme.com/pay", Severity: types.SeverityCritical,
			Tool: "web-investigate", VerificationStatus: types.VerificationVerified},
		{ID: "f2", Endpoint: "https://api.acme.com/v1/orders", Severity: types.SeverityMedium},
		{ID: "f3", Endpoint: "https://marketing.acme.com/", Severity: types.SeverityLow},
	}
	r := Compute(svcs, assets(), fs, map[string]bool{"a1": true, "a2": true, "a3": true})

	if len(r.Services) != 2 {
		t.Fatalf("want 2 services, got %d", len(r.Services))
	}
	// Critical first — an owner scanning the page should meet the service that matters first.
	if r.Services[0].Name != "Checkout" {
		t.Errorf("services are not ordered by criticality: first is %q", r.Services[0].Name)
	}
	co := r.Services[0]
	if co.Findings != 2 {
		t.Errorf("Checkout should carry 2 findings (its two assets), got %d", co.Findings)
	}
	if co.WorstSeverity != "critical" {
		t.Errorf("worst severity = %q, want critical", co.WorstSeverity)
	}
	if co.Exploited != 1 {
		t.Errorf("Exploited = %d, want 1 — the exploited finding is the one an owner acts on first", co.Exploited)
	}
	if r.Unmapped != 0 {
		t.Errorf("nothing should be unmapped here, got %d", r.Unmapped)
	}
}

func TestCompute_UnscannedAssetIsNotACleanService(t *testing.T) {
	// The refusal that matters most: a service with an unassessed asset has not been cleared.
	svcs := []platform.BusinessService{{ID: "s1", Name: "Checkout", AssetIDs: []string{"a1", "a2"}}}
	r := Compute(svcs, assets(), nil, map[string]bool{"a1": true}) // a2 never scanned

	s := r.Services[0]
	if s.Scanned != 1 || s.Assets != 2 {
		t.Fatalf("assets=%d scanned=%d, want 2/1", s.Assets, s.Scanned)
	}
	if len(s.UnscannedTargets) != 1 || s.UnscannedTargets[0] != "api.acme.com" {
		t.Errorf("the unscanned asset must be NAMED, not just counted: %v", s.UnscannedTargets)
	}
	if !strings.Contains(s.Note, "not a complete picture") {
		t.Errorf("a partly-assessed service must say so: %q", s.Note)
	}
}

func TestCompute_WhollyUnassessedServiceSaysNobodyLooked(t *testing.T) {
	svcs := []platform.BusinessService{{ID: "s1", Name: "Checkout", AssetIDs: []string{"a1"}}}
	r := Compute(svcs, assets(), nil, nil) // nothing scanned

	s := r.Services[0]
	if s.Assessed {
		t.Error("a service with no scanned asset is marked assessed")
	}
	if !strings.Contains(s.Note, "nobody has looked") {
		t.Errorf("zero findings on an unassessed service must not read as clean: %q", s.Note)
	}
}

func TestCompute_UnmappedFindingsAreSurfacedNotDropped(t *testing.T) {
	// Declaring one service must not make the rest of the estate vanish.
	svcs := []platform.BusinessService{{ID: "s1", Name: "Checkout", AssetIDs: []string{"a1"}}}
	fs := []types.Finding{
		{ID: "f1", Endpoint: "https://checkout.acme.com/pay", Severity: types.SeverityHigh},
		{ID: "f2", Endpoint: "app/db.py:42", Severity: types.SeverityHigh}, // matches no asset target
		{ID: "f3", Endpoint: "https://marketing.acme.com/", Severity: types.SeverityLow},
	}
	r := Compute(svcs, assets(), fs, map[string]bool{"a1": true})

	if r.Unmapped != 2 {
		t.Errorf("Unmapped = %d, want 2 (the source-file finding and the marketing one)", r.Unmapped)
	}
	if !strings.Contains(r.UnmappedNote, "They are real and they are not represented above") {
		t.Errorf("a bare unmapped count reads as an error; it needs the sentence: %q", r.UnmappedNote)
	}
}

func TestCompute_AttributionIsLiteralAndLongestWins(t *testing.T) {
	// Two assets where one target is a substring of the other. A finding on the more specific host
	// must attribute to it, or a service map sends the wrong team.
	as := []platform.Asset{
		{ID: "broad", Target: "acme.com"},
		{ID: "specific", Target: "checkout.acme.com"},
	}
	svcs := []platform.BusinessService{
		{ID: "s1", Name: "Checkout", AssetIDs: []string{"specific"}},
		{ID: "s2", Name: "Everything else", AssetIDs: []string{"broad"}},
	}
	fs := []types.Finding{{ID: "f1", Endpoint: "https://checkout.acme.com/pay", Severity: types.SeverityHigh}}
	r := Compute(svcs, as, fs, map[string]bool{"specific": true, "broad": true})

	var checkout, other int
	for _, s := range r.Services {
		if s.Name == "Checkout" {
			checkout = s.Findings
		} else {
			other = s.Findings
		}
	}
	if checkout != 1 || other != 0 {
		t.Errorf("longest-match attribution failed: checkout=%d other=%d, want 1/0", checkout, other)
	}
}

func TestCompute_DanglingAssetIDIsSkippedNotCounted(t *testing.T) {
	svcs := []platform.BusinessService{{ID: "s1", Name: "Checkout", AssetIDs: []string{"a1", "gone"}}}
	r := Compute(svcs, assets(), nil, map[string]bool{"a1": true})
	if r.Services[0].Assets != 1 {
		t.Errorf("a dangling asset id was counted: assets=%d, want 1", r.Services[0].Assets)
	}
}
