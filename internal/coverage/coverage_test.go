package coverage

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

var scanT = time.Date(2026, 6, 27, 9, 0, 0, 0, time.UTC)

// A scanned asset reports its declared toolset, the scan time, and which tools surfaced findings.
func TestCompute_ScannedAssetCoverage(t *testing.T) {
	assets := []platform.Asset{{ID: "a1", TenantID: "t", Type: "repository", Target: "acme/api"}}
	findings := []types.Finding{
		{ID: "f1", Tool: "gitleaks", Endpoint: "acme/api/config.yaml:3"},
		{ID: "f2", Tool: "trivy", Endpoint: "acme/api/go.mod"},
	}
	engs := []platform.Engagement{{ID: "e1", AssetID: "a1", CompletedAt: scanT}}

	s := Compute(assets, findings, engs)
	if s.TotalAssets != 1 || s.ScannedAssets != 1 {
		t.Fatalf("summary: %+v", s)
	}
	c := s.Assets[0]
	if !c.Scanned || !c.LastScannedAt.Equal(scanT) {
		t.Errorf("scanned/at: %+v", c)
	}
	if len(c.RunsTools) != 5 { // repository anchor set
		t.Errorf("RunsTools: %+v", c.RunsTools)
	}
	if c.FindingsCount != 2 {
		t.Errorf("findings count: %d", c.FindingsCount)
	}
	// gitleaks + trivy surfaced findings; semgrep/grype/trufflehog ran clean (not listed).
	if len(c.ToolsWithFindings) != 2 || c.ToolsWithFindings[0] != "gitleaks" || c.ToolsWithFindings[1] != "trivy" {
		t.Errorf("tools with findings: %+v", c.ToolsWithFindings)
	}
}

// Grounded §10: a never-scanned asset is scanned:false with no findings — never "covered".
func TestCompute_NeverScannedIsHonest(t *testing.T) {
	assets := []platform.Asset{{ID: "a1", TenantID: "t", Type: "web_application", Target: "https://app.acme.com"}}
	s := Compute(assets, nil, nil)
	c := s.Assets[0]
	if c.Scanned || c.FindingsCount != 0 || len(c.ToolsWithFindings) != 0 {
		t.Fatalf("never-scanned must be honest: %+v", c)
	}
	if len(c.RunsTools) == 0 {
		t.Error("should still declare what a web scan WOULD run")
	}
	if s.ScannedAssets != 0 {
		t.Errorf("scanned count: %d", s.ScannedAssets)
	}
}

// Attribution is by literal target match (longest wins) — a finding on another asset doesn't count here.
func TestCompute_AttributionIsScoped(t *testing.T) {
	assets := []platform.Asset{
		{ID: "a1", TenantID: "t", Type: "web_application", Target: "https://a.com"},
		{ID: "a2", TenantID: "t", Type: "web_application", Target: "https://b.com"},
	}
	findings := []types.Finding{{ID: "f1", Tool: "nuclei", Endpoint: "https://b.com/x"}}
	engs := []platform.Engagement{
		{ID: "e1", AssetID: "a1", CompletedAt: scanT},
		{ID: "e2", AssetID: "a2", CompletedAt: scanT},
	}
	s := Compute(assets, findings, engs)
	byID := map[string]AssetCoverage{}
	for _, c := range s.Assets {
		byID[c.AssetID] = c
	}
	if byID["a1"].FindingsCount != 0 {
		t.Errorf("a1 should have no findings, got %d", byID["a1"].FindingsCount)
	}
	if byID["a2"].FindingsCount != 1 {
		t.Errorf("a2 should have the finding, got %d", byID["a2"].FindingsCount)
	}
}

// The latest completed engagement is the last-scanned time.
func TestCompute_LatestScanWins(t *testing.T) {
	assets := []platform.Asset{{ID: "a1", TenantID: "t", Type: "container_image", Target: "alpine:3.18"}}
	later := scanT.Add(48 * time.Hour)
	engs := []platform.Engagement{
		{ID: "e1", AssetID: "a1", CompletedAt: scanT},
		{ID: "e2", AssetID: "a1", CompletedAt: later},
	}
	s := Compute(assets, nil, engs)
	if !s.Assets[0].LastScannedAt.Equal(later) {
		t.Fatalf("want latest scan %v, got %v", later, s.Assets[0].LastScannedAt)
	}
}
