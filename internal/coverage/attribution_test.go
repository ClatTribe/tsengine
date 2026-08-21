package coverage

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func repoAsset() []platform.Asset {
	return []platform.Asset{{ID: "r1", Target: "/workspace", Type: "repository"}}
}
func scannedRepo() []platform.Engagement {
	return []platform.Engagement{{AssetID: "r1", CompletedAt: time.Unix(1000, 0).UTC()}}
}

// THE BUG. Attribution matches the asset's Target inside the finding's Endpoint. That works
// for a URL or a host and cannot work for a repository, whose findings are file-relative
// ("src/app.py:12") while the target is a workspace path that never appears in them. So a
// scanned repository holding a SQLi and a leaked AWS key reported zero findings and an empty
// tool list, and the page rendered "No findings recorded" — on the one screen whose entire
// job is telling the customer honestly what was and was not covered.
func TestCompute_RepoFindingsAreNotSilentlyZero(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "semgrep::sqli", Tool: "semgrep", Endpoint: "src/app.py:12", Severity: types.SeverityHigh},
		{RuleID: "gitleaks::aws-key", Tool: "gitleaks", Endpoint: "config/prod.env:3", Severity: types.SeverityCritical},
	}
	c := Compute(repoAsset(), findings, scannedRepo()).Assets[0]
	if c.Attributed {
		t.Fatal("premise changed: a repo target should not match a file-relative endpoint")
	}
	if c.UnattributableFromOurTools != 2 {
		t.Errorf("UnattributableFromOurTools = %d, want 2 — without this the zero above is "+
			"indistinguishable from a clean scan, which is exactly how the page came to say "+
			"'No findings recorded' over a critical leaked key", c.UnattributableFromOurTools)
	}
}

// A genuinely clean asset must stay clean: nothing attributed AND nothing unattributable.
// Otherwise the new signal becomes noise on every healthy asset and stops being read.
func TestCompute_CleanAssetShowsNoAttributionProblem(t *testing.T) {
	c := Compute(repoAsset(), nil, scannedRepo()).Assets[0]
	if c.Attributed || c.UnattributableFromOurTools != 0 {
		t.Errorf("a clean asset must report no attribution problem, got attributed=%v unattributable=%d",
			c.Attributed, c.UnattributableFromOurTools)
	}
}

// A web asset attributes normally — the fix must not disturb the case that already worked.
func TestCompute_WebAssetStillAttributes(t *testing.T) {
	assets := []platform.Asset{{ID: "w1", Target: "https://t.test", Type: "web_application"}}
	eng := []platform.Engagement{{AssetID: "w1", CompletedAt: time.Unix(1000, 0).UTC()}}
	findings := []types.Finding{{RuleID: "nuclei::xss", Tool: "nuclei", Endpoint: "https://t.test/a", Severity: types.SeverityHigh}}
	c := Compute(assets, findings, eng).Assets[0]
	if !c.Attributed || c.FindingsCount != 1 {
		t.Errorf("web attribution regressed: attributed=%v count=%d", c.Attributed, c.FindingsCount)
	}
	if c.UnattributableFromOurTools != 0 {
		t.Errorf("an attributed finding must not also count as unattributable: %d", c.UnattributableFromOurTools)
	}
}

// A finding from a tool this asset type does NOT run is somebody else's problem and must not
// be counted here — otherwise every asset reports every other asset's orphans.
func TestCompute_OnlyOurOwnToolsCount(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "prowler::iam", Tool: "prowler", Endpoint: "aws://acct/role", Severity: types.SeverityHigh},
	}
	c := Compute(repoAsset(), findings, scannedRepo()).Assets[0]
	if c.UnattributableFromOurTools != 0 {
		t.Errorf("a cloud finding must not count against a repository: %d", c.UnattributableFromOurTools)
	}
}

// A coverage disclosure is not a finding and must not be counted as an orphan either.
func TestCompute_CoverageGapIsNotAnOrphan(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "coverage::identity-oauth-grants", Tool: "coverage", Endpoint: "somewhere", Severity: types.SeverityInfo},
	}
	c := Compute(repoAsset(), findings, scannedRepo()).Assets[0]
	if c.UnattributableFromOurTools != 0 {
		t.Errorf("a coverage disclosure must not read as an unattributed finding: %d", c.UnattributableFromOurTools)
	}
}

// The recorded link is what makes a repository attributable at all. With it, the same two
// findings that previously vanished are counted, from the tools that produced them.
func TestCompute_RecordedAssetIDAttributesARepo(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "semgrep::sqli", Tool: "semgrep", Endpoint: "src/app.py:12", Severity: types.SeverityHigh, AssetID: "r1"},
		{RuleID: "gitleaks::aws-key", Tool: "gitleaks", Endpoint: "config/prod.env:3", Severity: types.SeverityCritical, AssetID: "r1"},
	}
	c := Compute(repoAsset(), findings, scannedRepo()).Assets[0]
	if !c.Attributed || c.FindingsCount != 2 {
		t.Errorf("attributed=%v count=%d; the recorded link must tie file-relative findings to their repo",
			c.Attributed, c.FindingsCount)
	}
	if len(c.ToolsWithFindings) != 2 {
		t.Errorf("ToolsWithFindings = %v, want both tools", c.ToolsWithFindings)
	}
	if c.UnattributableFromOurTools != 0 {
		t.Errorf("nothing should remain unattributable: %d", c.UnattributableFromOurTools)
	}
}

// An AssetID naming an asset this tenant does not have is NOT attribution. Honouring it
// would cross a boundary the store spends real effort enforcing, so the id is validated
// rather than trusted — and the endpoint fallback still gets its chance.
func TestCompute_ForeignAssetIDIsNotHonoured(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "semgrep::sqli", Tool: "semgrep", Endpoint: "src/app.py:12", Severity: types.SeverityHigh,
			AssetID: "someone-elses-asset"},
	}
	c := Compute(repoAsset(), findings, scannedRepo()).Assets[0]
	if c.Attributed || c.FindingsCount != 0 {
		t.Errorf("a foreign asset id must not attribute: attributed=%v count=%d", c.Attributed, c.FindingsCount)
	}
	if c.UnattributableFromOurTools != 1 {
		t.Errorf("it should still be reported as an unattributable orphan, got %d", c.UnattributableFromOurTools)
	}
}

// Findings stored before the field existed carry no id and must keep working through the
// endpoint fallback — an empty AssetID means "not recorded", never "no asset".
func TestCompute_EmptyAssetIDFallsBackToTheEndpoint(t *testing.T) {
	assets := []platform.Asset{{ID: "w1", Target: "https://t.test", Type: "web_application"}}
	eng := []platform.Engagement{{AssetID: "w1", CompletedAt: time.Unix(1000, 0).UTC()}}
	findings := []types.Finding{{RuleID: "nuclei::xss", Tool: "nuclei", Endpoint: "https://t.test/a", Severity: types.SeverityHigh}}
	if c := Compute(assets, findings, eng).Assets[0]; !c.Attributed || c.FindingsCount != 1 {
		t.Errorf("legacy findings must still attribute by endpoint: attributed=%v count=%d", c.Attributed, c.FindingsCount)
	}
}
