package crossdetect

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A web finding that bridges (via a shared AWS key) to a cloud-admin crown jewel must get a blast radius
// reaching the crown jewel — so the alert can say "this medium reaches your cloud root", not just its
// severity. A finding NOT on a crown-jewel chain gets no radius (impact = its own severity, never inflated).
func TestBlastRadiusByFinding_ReachesCrownJewel(t *testing.T) {
	assets := []platform.Asset{
		{ID: "a-web", Type: "web_application", Target: "https://app.acme.com"},
		{ID: "a-cloud", Type: "cloud_account", Target: "aws:123456789012"},
	}
	findings := []types.Finding{
		{ID: "f-web", RuleID: "nuclei::exposed-env", Tool: "nuclei", Severity: types.SeverityHigh,
			Title: "Exposed .env leaks credentials", Endpoint: "https://app.acme.com/.env",
			Description: "Response body contained AKIAIOSFODNN7EXAMPLE"},
		{ID: "f-cloud", RuleID: "prowler::iam_role_administratoraccess_policy", Tool: "prowler", Severity: types.SeverityHigh,
			Title: "IAM access key has AdministratorAccess", Endpoint: "AwsIamAccessKey ci @global",
			Description: "Access key AKIAIOSFODNN7EXAMPLE is attached to a role with AdministratorAccess"},
		// an isolated finding on no chain → no blast radius
		{ID: "f-lonely", RuleID: "semgrep::xss", Tool: "semgrep", Severity: types.SeverityMedium,
			Title: "Reflected XSS", Endpoint: "src/render.js:10"},
	}

	br := BlastRadiusByFinding(assets, findings)

	web, ok := br["f-web"]
	if !ok || !web.ReachesCrownJewel || web.CrownJewelType != "cloud_account" {
		t.Fatalf("f-web should reach a cloud_account crown jewel, got %+v (ok=%v)", web, ok)
	}
	if web.Hops < 1 {
		t.Errorf("f-web is upstream of the crown jewel, want hops>=1, got %d", web.Hops)
	}
	// the crown-jewel finding itself is on the chain at hops 0
	if cloud, ok := br["f-cloud"]; !ok || cloud.Hops != 0 {
		t.Errorf("f-cloud is the crown jewel, want hops 0, got %+v (ok=%v)", cloud, ok)
	}
	// the isolated finding has no blast radius — impact is just its own severity
	if _, ok := br["f-lonely"]; ok {
		t.Errorf("f-lonely is on no crown-jewel chain and must have no blast radius")
	}
}
