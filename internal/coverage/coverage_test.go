package coverage

import (
	"strings"
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

// TestCompute_DoesNotClaimToolsExecuted pins what coverage is allowed to assert.
//
// RunsTools is a static declared map, not observed dispatch. The struct documented the remainder as
// "rest ran clean" and the UI rendered "All tools ran and found nothing — a clean result, not a
// skipped scan" — a confident claim in exactly the case most likely to be false.
//
// Two live mechanisms produce it: a per-tool timeout drops a tool silently (measured — four identical
// api scans returned 1, 1, 11, 11 findings), and a TOOLSET-limited image answers "prowler: not found"
// for tools it did not install. Either way the customer was told every tool ran.
func TestCompute_DoesNotClaimToolsExecuted(t *testing.T) {
	for _, c := range Compute(
		[]platform.Asset{{ID: "a1", Target: "acct-1", Type: "cloud_account"}},
		nil,
		[]platform.Engagement{{ID: "e1", AssetID: "a1", CompletedAt: time.Now().UTC()}},
	).Assets {
		if c.ExecutionConfirmed {
			t.Error("coverage has no per-tool dispatch data — it must not report execution as confirmed")
		}
		if len(c.RunsTools) > 0 && len(c.ToolsWithFindings) != 0 {
			t.Errorf("no findings supplied, so nothing may be listed as having surfaced one: %v",
				c.ToolsWithFindings)
		}
	}
}

// TestCompute_UsesRealExecutionWhenReported is the other half of ExecutionConfirmed: once the
// engagement records what actually dispatched, coverage reports THAT rather than the declared list,
// and names the tools that failed instead of implying they ran clean.
func TestCompute_UsesRealExecutionWhenReported(t *testing.T) {
	eng := platform.Engagement{
		ID: "e1", AssetID: "a1", CompletedAt: time.Now().UTC(),
		ToolsRan:    []string{"nuclei", "openapi_spec_ingest"},
		ToolsFailed: []types.ToolFailure{{Tool: "schemathesis", Reason: "context deadline exceeded"}},
	}
	got := Compute(
		[]platform.Asset{{ID: "a1", TenantID: "t", Target: "https://api.example.com", Type: "api"}},
		nil, []platform.Engagement{eng},
	).Assets[0]

	if !got.ExecutionConfirmed {
		t.Error("engagement reported its toolset, so execution IS confirmed")
	}
	if len(got.ToolsFailed) != 1 || got.ToolsFailed[0].Tool != "schemathesis" {
		t.Errorf("a failed tool must be named, not folded into 'ran clean': %+v", got.ToolsFailed)
	}
	for _, tool := range got.RunsTools {
		if tool == "schemathesis" {
			t.Error("a tool that failed must not be listed as having run")
		}
	}
}

// A runner that reports no execution (operate dispatches no sandbox tools) must stay "unknown" — the
// declared toolset, unconfirmed — never "nothing ran".
func TestCompute_NoReportStaysUnknownNotEmpty(t *testing.T) {
	got := Compute(
		[]platform.Asset{{ID: "a1", TenantID: "t", Target: "acme/app", Type: "repository"}},
		nil,
		[]platform.Engagement{{ID: "e1", AssetID: "a1", CompletedAt: time.Now().UTC()}},
	).Assets[0]

	if got.ExecutionConfirmed {
		t.Error("no reported toolset means execution is unknown, not confirmed")
	}
	if len(got.RunsTools) == 0 {
		t.Error("with no report, coverage must still show the DECLARED toolset rather than nothing")
	}
}

// A scanned API that surfaced zero findings must NOT read as "clean": BOLA/BFLA/cross-user auth are
// business-logic classes the anchor pass cannot test without two declared identities. This is the
// asset-level form of the "Clear on unscanned scope" overclaim — the fixtures already record these as
// NOT COVERED, so the customer-facing coverage must say so too.
func TestUntestedClasses_ZeroFindingApiDoesNotReadAsClean(t *testing.T) {
	now := time.Now()
	assets := []platform.Asset{{ID: "a1", Type: "api", Target: "https://api.example.com"}}
	engs := []platform.Engagement{{AssetID: "a1", CompletedAt: now, ToolsRan: []string{"nuclei"}}}

	got := Compute(assets, nil, engs) // zero findings — the "you're clean" case
	if len(got.Assets) != 1 {
		t.Fatalf("want 1 asset, got %d", len(got.Assets))
	}
	cov := got.Assets[0]
	if !cov.Scanned || cov.FindingsCount != 0 {
		t.Fatalf("precondition: want a scanned asset with 0 findings, got scanned=%v n=%d", cov.Scanned, cov.FindingsCount)
	}
	if len(cov.UntestedClasses) == 0 {
		t.Fatal("a zero-finding API with no authz_test config reported NO untested classes — it reads as 'clean' while BOLA/BFLA were never tested")
	}
	var haveBOLA bool
	for _, c := range cov.UntestedClasses {
		if c.NeedsConfig == "" {
			t.Errorf("untested class %q names no config key, so the customer cannot act on it", c.Class)
		}
		if strings.Contains(c.Class, "BOLA") {
			haveBOLA = true
		}
	}
	if !haveBOLA {
		t.Errorf("BOLA (OWASP API1, the top API risk) missing from untested classes: %+v", cov.UntestedClasses)
	}
}

// The list must shrink as the customer configures — it is grounded in stored state, not a constant
// disclaimer. A configured asset claims no gap.
func TestUntestedClasses_ConfiguredAssetReportsNoGap(t *testing.T) {
	assets := []platform.Asset{{
		ID: "a1", Type: "api", Target: "https://api.example.com",
		Meta: map[string]string{"authz_test": "sealed:ref-123"},
	}}
	got := Compute(assets, nil, nil)
	if n := len(got.Assets[0].UntestedClasses); n != 0 {
		t.Fatalf("configured asset still reports %d untested classes: %+v", n, got.Assets[0].UntestedClasses)
	}
}

// A web app with no login flow is only tested unauthenticated — the FN guard webauth exists for.
func TestUntestedClasses_WebWithoutLoginFlow(t *testing.T) {
	assets := []platform.Asset{{ID: "w1", Type: "web_application", Target: "https://app.example.com"}}
	got := Compute(assets, nil, nil)
	if len(got.Assets[0].UntestedClasses) == 0 {
		t.Fatal("web asset with no login_flow reported no untested classes — the authenticated surface was never scanned")
	}
}
