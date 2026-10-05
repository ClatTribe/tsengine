package aibudget

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func asset(id, typ, target string) platform.Asset {
	return platform.Asset{ID: id, Type: typ, Target: target}
}

func bucket(p Plan, surface string) Bucket {
	for _, b := range p.Buckets {
		if b.Surface == surface {
			return b
		}
	}
	return Bucket{}
}

// A clean estate allocates nothing — never an even split to look busy.
func TestBuild_NoExposureAllocatesNothing(t *testing.T) {
	p := Build(Inputs{Budget: 1000, ModelConfigured: true})
	for _, b := range p.Buckets {
		if b.SharePct != 0 || b.RecommendedUSD != 0 {
			t.Errorf("%s got share %d / $%.0f on an empty estate", b.Surface, b.SharePct, b.RecommendedUSD)
		}
	}
	if !hasNote(p, "nothing to allocate") {
		t.Errorf("expected a 'nothing to allocate' note, got %v", p.Notes)
	}
}

// Exposure routes to the right surface, shares sum to 100, and a cloud critical outweighs a web low.
func TestBuild_ExposureRoutesAndSumsTo100(t *testing.T) {
	assets := []platform.Asset{
		asset("a1", "cloud_account", "123456789012"),
		asset("a2", "repository", "github.com/acme/api"),
		asset("a3", "web_application", "https://app.acme.test"),
	}
	issues := []crossdetect.Issue{
		{Key: "k1", Severity: "critical", Endpoint: "arn:aws:iam::123456789012:role/admin"},
		{Key: "k2", Severity: "low", Endpoint: "github.com/acme/api/src/x.go:10"},
		{Key: "k3", Severity: "low", Endpoint: "https://app.acme.test/login"},
	}
	p := Build(Inputs{Budget: 1000, ModelConfigured: true, OpenIssues: issues, Assets: assets})

	if p.AttributedIssues != 3 || p.UnattributedIssues != 0 {
		t.Fatalf("attribution: got %d attributed / %d not", p.AttributedIssues, p.UnattributedIssues)
	}
	sum := 0
	for _, b := range p.Buckets {
		sum += b.SharePct
	}
	if sum != 100 {
		t.Errorf("shares sum to %d, want 100", sum)
	}
	if bucket(p, SurfaceCloud).SharePct <= bucket(p, SurfaceWeb).SharePct {
		t.Errorf("cloud critical (%d) should outrank web low (%d)", bucket(p, SurfaceCloud).SharePct, bucket(p, SurfaceWeb).SharePct)
	}
	if got := bucket(p, SurfaceCloud).RecommendedUSD + bucket(p, SurfaceCode).RecommendedUSD + bucket(p, SurfaceWeb).RecommendedUSD; got < 999 || got > 1001 {
		t.Errorf("recommended USD should sum to the budget, got %.2f", got)
	}
}

// An unattributed issue is excluded and named, never guessed into a bucket.
func TestBuild_UnattributedExcludedAndNoted(t *testing.T) {
	issues := []crossdetect.Issue{{Key: "k", Severity: "high", Endpoint: "mystery://nowhere"}}
	p := Build(Inputs{ModelConfigured: true, OpenIssues: issues})
	if p.AttributedIssues != 0 || p.UnattributedIssues != 1 {
		t.Fatalf("got %d attributed / %d unattributed", p.AttributedIssues, p.UnattributedIssues)
	}
	if !hasNote(p, "could not be attributed") {
		t.Errorf("expected an unattributed note, got %v", p.Notes)
	}
}

// Yield history nudges allocation toward the surface that proves findings cheaply — and the basis says so.
func TestBuild_MeasuredYieldFavorsTheCheaperSurface(t *testing.T) {
	assets := []platform.Asset{
		asset("a2", "repository", "github.com/acme/api"),
		asset("a3", "web_application", "https://app.acme.test"),
	}
	// Equal exposure on code and web.
	issues := []crossdetect.Issue{
		{Key: "k2", Severity: "high", Endpoint: "github.com/acme/api/x.go:1"},
		{Key: "k3", Severity: "high", Endpoint: "https://app.acme.test/a"},
	}
	spend := []platform.AISpend{
		// code proved 4 findings for $4 → $1 each (cheap).
		{Surface: "code", USD: 4, CostKnown: true, Verified: 4},
		// web proved 1 finding for $8 → $8 each (expensive).
		{Surface: "web", USD: 8, CostKnown: true, Verified: 1},
	}
	p := Build(Inputs{Budget: 100, ModelConfigured: true, OpenIssues: issues, Assets: assets, Spend: spend})
	code, web := bucket(p, SurfaceCode), bucket(p, SurfaceWeb)
	if code.Exposure != web.Exposure {
		t.Fatalf("test setup: exposures differ (%d vs %d)", code.Exposure, web.Exposure)
	}
	if code.SharePct <= web.SharePct {
		t.Errorf("cheaper-yield code (%d) should outrank web (%d) at equal exposure", code.SharePct, web.SharePct)
	}
	if code.CostPerVerified == nil || *code.CostPerVerified != 1 {
		t.Errorf("code cost-per-verified: got %v want 1", code.CostPerVerified)
	}
	if code.Basis != "exposure × measured yield (cost per proven finding)" {
		t.Errorf("code basis: %q", code.Basis)
	}
}

// A surface with an unknown-cost run gets NO cost-per-verified ratio (same rule as ai-value), and is
// ranked on exposure alone with the honest basis.
func TestBuild_UnknownCostYieldsNoRatio(t *testing.T) {
	assets := []platform.Asset{asset("a2", "repository", "github.com/acme/api")}
	issues := []crossdetect.Issue{{Key: "k2", Severity: "high", Endpoint: "github.com/acme/api/x.go:1"}}
	spend := []platform.AISpend{
		{Surface: "code", USD: 5, CostKnown: true, Verified: 2},
		{Surface: "code", CostKnown: false, Verified: 1}, // one unknown-cost run poisons the ratio
	}
	p := Build(Inputs{Budget: 100, ModelConfigured: true, OpenIssues: issues, Assets: assets, Spend: spend})
	code := bucket(p, SurfaceCode)
	if code.CostPerVerified != nil {
		t.Errorf("cost-per-verified should be withheld when a run's cost is unknown, got %v", code.CostPerVerified)
	}
	if code.UnknownCostRuns != 1 {
		t.Errorf("unknown-cost runs: got %d want 1", code.UnknownCostRuns)
	}
	if code.Basis != "exposure only (no yield history on this surface yet)" {
		t.Errorf("basis should fall back to exposure-only, got %q", code.Basis)
	}
}

// KEV / observed-in-the-wild raise exposure above the same severity without the signal.
func TestBuild_ExploitationSignalRaisesExposure(t *testing.T) {
	assets := []platform.Asset{asset("a", "web_application", "https://app.acme.test")}
	plain := Build(Inputs{ModelConfigured: true, Assets: assets, OpenIssues: []crossdetect.Issue{
		{Key: "k", Severity: "high", Endpoint: "https://app.acme.test/a"},
	}})
	attacked := Build(Inputs{ModelConfigured: true, Assets: assets, OpenIssues: []crossdetect.Issue{
		{Key: "k", Severity: "high", Endpoint: "https://app.acme.test/a", Attacked: true},
	}})
	if bucket(attacked, SurfaceWeb).Exposure <= bucket(plain, SurfaceWeb).Exposure {
		t.Errorf("attacked-in-the-wild should raise exposure (%d vs %d)",
			bucket(attacked, SurfaceWeb).Exposure, bucket(plain, SurfaceWeb).Exposure)
	}
}

// No model configured and no budget are both named, so the plan is never read as actionable when it isn't.
func TestBuild_MissingModelAndBudgetNoted(t *testing.T) {
	assets := []platform.Asset{asset("a", "web_application", "https://app.acme.test")}
	issues := []crossdetect.Issue{{Key: "k", Severity: "high", Endpoint: "https://app.acme.test/a"}}
	p := Build(Inputs{ModelConfigured: false, OpenIssues: issues, Assets: assets})
	if !hasNote(p, "No agent model") {
		t.Errorf("expected a no-model note, got %v", p.Notes)
	}
	if !hasNote(p, "No monthly AI budget") {
		t.Errorf("expected a no-budget note, got %v", p.Notes)
	}
	if p.BudgetSet {
		t.Errorf("BudgetSet should be false")
	}
}

func hasNote(p Plan, sub string) bool {
	for _, n := range p.Notes {
		if containsFold(n, sub) {
			return true
		}
	}
	return false
}

func containsFold(s, sub string) bool {
	return len(sub) == 0 || indexFold(s, sub) >= 0
}

func indexFold(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
