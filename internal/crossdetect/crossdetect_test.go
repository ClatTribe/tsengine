package crossdetect

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// A web entry point that leaks an AWS key, and a cloud admin finding that names
// the same key, must correlate into one cross-surface attack path.
func TestCorrelate_CrossSurfaceChainViaLeakedKey(t *testing.T) {
	assets := []platform.Asset{
		{ID: "a-web", Type: "web_application", Target: "https://app.acme.com"},
		{ID: "a-cloud", Type: "cloud_account", Target: "aws:123456789012"},
	}
	findings := []types.Finding{
		{
			ID: "f-web", RuleID: "nuclei::exposed-env", Tool: "nuclei", Severity: types.SeverityHigh,
			Title: "Exposed .env leaks credentials", Endpoint: "https://app.acme.com/.env",
			Description: "Response body contained AKIAIOSFODNN7EXAMPLE",
		},
		{
			ID: "f-cloud", RuleID: "prowler::iam_role_administratoraccess_policy", Tool: "prowler", Severity: types.SeverityHigh,
			Title: "IAM access key has AdministratorAccess", Endpoint: "AwsIamAccessKey ci @global",
			Description: "Access key AKIAIOSFODNN7EXAMPLE is attached to a role with AdministratorAccess",
		},
	}

	chains := Correlate(assets, findings)
	if len(chains) == 0 {
		t.Fatal("expected a cross-surface chain, got none")
	}
	ch := chains[0]
	if len(ch.Steps) < 2 {
		t.Fatalf("chain too short: %+v", ch)
	}
	// Entry must be the web finding; terminal must be the cloud crown jewel.
	if ch.Steps[0].AssetType != "web_application" {
		t.Errorf("entry step asset = %q, want web_application", ch.Steps[0].AssetType)
	}
	last := ch.Steps[len(ch.Steps)-1]
	if last.AssetType != "cloud_account" || !last.CrownJewel {
		t.Errorf("terminal step = %+v, want cloud_account crown jewel", last)
	}
	// The bridge must cite the shared AWS key (grounded, not guessed).
	if ch.Steps[0].ViaEntity == "" {
		t.Error("entry step should name the bridging entity")
	}
}

// Findings that share no entity must not produce a chain (no guessed links).
func TestCorrelate_NoChainWithoutSharedEntity(t *testing.T) {
	assets := []platform.Asset{
		{ID: "a-web", Type: "web_application", Target: "https://app.acme.com"},
		{ID: "a-cloud", Type: "cloud_account", Target: "aws:123456789012"},
	}
	findings := []types.Finding{
		{ID: "f-web", Tool: "nuclei", Severity: types.SeverityHigh, Title: "Reflected XSS", Endpoint: "https://app.acme.com/search"},
		{ID: "f-cloud", Tool: "prowler", Severity: types.SeverityHigh, Title: "S3 bucket public", Endpoint: "AwsS3Bucket logs @us-east-1"},
	}
	if chains := Correlate(assets, findings); len(chains) != 0 {
		t.Errorf("unrelated findings should not chain, got %d", len(chains))
	}
}

func TestAssets_BucketsByInferredType(t *testing.T) {
	findings := []types.Finding{
		{ID: "1", Tool: "gitleaks", Severity: types.SeverityHigh, Title: "AWS key"},
		{ID: "2", Tool: "prowler", Severity: types.SeverityHigh, Title: "admin role"},
		{ID: "3", Tool: "nuclei", Severity: types.SeverityHigh, Title: "ssrf"},
		{ID: "4", RuleID: "sspm::github-2fa", Tool: "sspm", Severity: types.SeverityMedium, Title: "2fa off"},
	}
	got := Assets(nil, findings)
	byType := map[string]int{}
	for _, a := range got {
		byType[a.Type] += len(a.Findings)
	}
	for _, want := range []string{"repository", "cloud_account", "web_application", "saas"} {
		if byType[want] != 1 {
			t.Errorf("type %q got %d findings, want 1 (buckets=%v)", want, byType[want], byType)
		}
	}
}

func TestInferType_RuleIDFallback(t *testing.T) {
	if got := inferType(types.Finding{RuleID: "prowler::s3_public"}); got != "cloud_account" {
		t.Errorf("rule-id fallback = %q, want cloud_account", got)
	}
	if got := inferType(types.Finding{Tool: "unknown-tool"}); got != "repository" {
		t.Errorf("unknown tool default = %q, want repository", got)
	}
}
