package bench

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestEstateFromFindings_GroundTruthFromEngine: the end-to-end bridge derives the estate + ground truth from
// the REAL substrate — a finding is high-impact iff crossdetect chains it to a crown jewel, not because a
// human labelled it. Here a leaked key (repo) + an admin-role finding on that same key (cloud) chain to a
// crown; the 3 noise findings (a build-only CVE, a public-CDN bucket, missing headers) do not. So the estate
// marks exactly the 2 chain findings high-impact, and the oracle answer passes.
func TestEstateFromFindings_GroundTruthFromEngine(t *testing.T) {
	in := ScanInput{
		Assets: []platform.Asset{
			{ID: "a-repo", Type: "repository", Target: "github.com/acme/deploy"},
			{ID: "a-cloud", Type: "cloud_account", Target: "aws:123456789012"},
			{ID: "a-web", Type: "web_application", Target: "https://app.acme.com"},
		},
		Findings: []types.Finding{
			{ID: "leak", Tool: "gitleaks", Severity: types.SeverityHigh, Title: "AWS key committed",
				Description: "Hardcoded AKIAIOSFODNN7EXAMPLE in deploy/config.yaml"},
			{ID: "role", Tool: "prowler", Severity: types.SeverityHigh, Title: "Role has AdministratorAccess over customer-PII backups",
				Endpoint: "AwsIamRole ci @global", Description: "AKIAIOSFODNN7EXAMPLE assumes a role with AdministratorAccess over the customer-pii backup bucket"},
			{ID: "cve", Tool: "trivy", Severity: types.SeverityMedium, Title: "build-only CVE", Description: "not shipped at runtime"},
			{ID: "cdn", Tool: "prowler", Severity: types.SeverityMedium, Title: "public CDN bucket", Endpoint: "AwsS3Bucket acme-cdn @us-east-1", Description: "public static assets only"},
			{ID: "hdr", Tool: "nuclei", Severity: types.SeverityLow, Title: "missing headers", Endpoint: "https://app.acme.com/"},
		},
	}
	sc, chains := EstateFromFindings("e2e", in)
	if len(chains) == 0 {
		t.Fatal("substrate must surface the code→cloud chain from the real findings")
	}
	high := map[string]bool{}
	for _, f := range sc.Findings {
		if f.HighImpact {
			high[f.ID] = true
		}
	}
	if !high["leak"] || !high["role"] {
		t.Errorf("both chain findings must be ground-truth high-impact, got %v", high)
	}
	for _, noise := range []string{"cve", "cdn", "hdr"} {
		if high[noise] {
			t.Errorf("non-chaining noise %q must NOT be high-impact (engine derived, not hand-labelled)", noise)
		}
	}
	// the oracle answer (the engine-derived impacts) must score a clean PASS — the pipeline is self-consistent.
	if s := ScoreDiscovery(sc, OracleDiscovery(sc)); !s.Pass() || s.TP != 2 {
		t.Errorf("oracle over the engine-derived estate must PASS with 2 impacts: %s", RenderDiscoveryScore(s))
	}
}
