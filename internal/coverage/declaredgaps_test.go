package coverage

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func webAsset() []platform.Asset {
	return []platform.Asset{{ID: "a1", Target: "https://t.test", Type: "web_application"}}
}

func scanned() []platform.Engagement {
	return []platform.Engagement{{AssetID: "a1", CompletedAt: time.Unix(1000, 0).UTC()}}
}

// THE BUG THIS PREVENTS: counting a coverage disclosure as a finding makes admitting a gap
// IMPROVE the numbers that describe how well the asset was covered. The count rises and a
// "coverage" tool joins tools-with-findings, so an asset reads as more tested for having
// been honest about what it skipped.
func TestCompute_DeclaredGapDoesNotInflateCoverage(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "nuclei::xss", Tool: "nuclei", Endpoint: "https://t.test/a", Severity: types.SeverityHigh},
		{RuleID: asset.CoverageRulePrefix + "threat-informed-untested-cve", Tool: "coverage",
			Endpoint: "https://t.test", Severity: types.SeverityInfo,
			Title:       "2 exploited CVE(s) against observed Apache httpd could not be tested",
			Description: "This is a coverage gap, not a vulnerability."},
	}
	got := Compute(webAsset(), findings, scanned())
	if len(got.Assets) != 1 {
		t.Fatalf("assets = %d", len(got.Assets))
	}
	c := got.Assets[0]
	if c.FindingsCount != 1 {
		t.Errorf("FindingsCount = %d, want 1 — the coverage disclosure must not count as a finding", c.FindingsCount)
	}
	for _, tl := range c.ToolsWithFindings {
		if tl == "coverage" {
			t.Errorf("ToolsWithFindings = %v — a disclosure must not read as a tool that found something", c.ToolsWithFindings)
		}
	}
	if len(c.DeclaredGaps) != 1 {
		t.Fatalf("DeclaredGaps = %+v, want the disclosure surfaced", c.DeclaredGaps)
	}
}

// The caveat lives in the wording, so the wording rides verbatim. Summarising a
// disclosure is exactly where "this is a coverage gap, not a vulnerability" gets lost.
func TestCompute_DeclaredGapKeepsItsWording(t *testing.T) {
	const detail = "Ranked but NOT TESTED. This is a coverage gap, not a vulnerability. " +
		"The match is on PRODUCT, not version."
	findings := []types.Finding{{
		RuleID: asset.CoverageRulePrefix + "threat-informed-untested-cve", Tool: "coverage",
		Endpoint: "https://t.test", Title: "could not test", Description: detail,
	}}
	got := Compute(webAsset(), findings, scanned())
	g := got.Assets[0].DeclaredGaps
	if len(g) != 1 {
		t.Fatalf("DeclaredGaps = %+v", g)
	}
	if g[0].Detail != detail {
		t.Errorf("Detail = %q; the disclosure must ride verbatim", g[0].Detail)
	}
	if g[0].Rule != asset.CoverageRulePrefix+"threat-informed-untested-cve" {
		t.Errorf("Rule = %q; a reader must be able to tell two kinds of gap apart", g[0].Rule)
	}
}

// DeclaredGaps and UntestedClasses are different claims and must not merge. One is what
// this asset TYPE cannot reach without config — knowable before any scan, true of every
// asset of the type. The other is what THIS run against THIS target actually hit and could
// not test. Collapsed, a standing caveat absorbs a live one.
func TestCompute_DeclaredGapsAreNotUntestedClasses(t *testing.T) {
	findings := []types.Finding{{
		RuleID: asset.CoverageRulePrefix + "x", Tool: "coverage", Endpoint: "https://t.test", Title: "g",
	}}
	got := Compute(webAsset(), findings, scanned())
	c := got.Assets[0]
	if len(c.DeclaredGaps) != 1 {
		t.Fatalf("want the declared gap")
	}
	for _, u := range c.UntestedClasses {
		if u.Class == "g" {
			t.Error("a declared gap leaked into UntestedClasses — they are different claims")
		}
	}
}

// The common case: no disclosures, nothing added, nothing changed.
func TestCompute_NoGapsIsUnchanged(t *testing.T) {
	findings := []types.Finding{{RuleID: "nuclei::xss", Tool: "nuclei", Endpoint: "https://t.test/a"}}
	got := Compute(webAsset(), findings, scanned())
	c := got.Assets[0]
	if len(c.DeclaredGaps) != 0 {
		t.Errorf("DeclaredGaps = %+v, want none", c.DeclaredGaps)
	}
	if c.FindingsCount != 1 {
		t.Errorf("FindingsCount = %d, want 1", c.FindingsCount)
	}
}
