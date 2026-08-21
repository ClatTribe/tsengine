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
