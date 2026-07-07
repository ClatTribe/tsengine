package bench

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// discoverysubstrate_test.go answers the honesty question the impact-discovery benchmark raises: "does
// `tsbench discover` measure the PRODUCT, or just an LLM given hand-authored facts?" The discovery scenarios
// present an estate + Context facts (a leaked key → role → PII bucket) and score the engineer's JUDGMENT.
// Those facts are not hypothetical — they are exactly the cross-surface linkage the DETERMINISTIC substrate
// (`crossdetect.Correlate`) surfaces from real scanner findings. This test proves that: it feeds realistic
// repo + cloud findings that mirror the `estate-correlate` / `estate-combo` chains and asserts the engine
// produces the entry→crown chain. So the benchmark's judgment layer sits on real engine output (§10) — the
// substrate finds the FACTS, the discovery benchmark measures the JUDGMENT on top of them.

// TestSubstrateSurfacesDiscoveryChain: the code→cloud chain the estate-correlate scenario asks the engineer
// to DISCOVER is the same one the substrate SURFACES deterministically — a leaked AWS key in the repo that
// bridges (via the shared key entity) to a cloud role with administrator/PII access.
func TestSubstrateSurfacesDiscoveryChain(t *testing.T) {
	assets := []platform.Asset{
		{ID: "a-repo", Type: "repository", Target: "github.com/acme/deploy"},
		{ID: "a-cloud", Type: "cloud_account", Target: "aws:123456789012"},
	}
	// mirror estate-correlate: a leaked deploy key in code (entry) + a cloud finding on that same key that
	// reaches customer data with admin-level access (crown). The shared entity is the AWS key.
	findings := []types.Finding{
		{
			ID: "f-leak", RuleID: "gitleaks::aws-access-key", Tool: "gitleaks", Severity: types.SeverityHigh,
			Title: "AWS access key committed in ci/deploy.sh",
			Description: "Hardcoded long-lived key AKIAIOSFODNN7EXAMPLE in the CI deploy script",
		},
		{
			ID: "f-role", RuleID: "prowler::iam_role_administratoraccess_policy", Tool: "prowler", Severity: types.SeverityHigh,
			Title: "Role reachable by key has AdministratorAccess to customer data",
			Endpoint: "AwsIamRole ci-deployer @global",
			Description: "Key AKIAIOSFODNN7EXAMPLE assumes prod-backup with AdministratorAccess over the customer-pii export bucket",
		},
	}
	chains := crossdetect.Correlate(assets, findings)
	if len(chains) == 0 {
		t.Fatal("substrate must surface the code→cloud chain the discovery scenario asks the engineer to find")
	}
	// the chain must start at the repo entry and reach the cloud crown jewel via the shared key.
	ch := chains[0]
	if len(ch.Steps) < 2 {
		t.Fatalf("chain must bridge two surfaces, got %d steps", len(ch.Steps))
	}
	first, last := ch.Steps[0], ch.Steps[len(ch.Steps)-1]
	if first.AssetType != "repository" {
		t.Errorf("entry must be the repo leak, got %q", first.AssetType)
	}
	if last.AssetType != "cloud_account" || !last.CrownJewel {
		t.Errorf("chain must terminate at the cloud crown jewel, got type=%q crown=%v", last.AssetType, last.CrownJewel)
	}
}

// TestSubstrateNoChainWithoutRealLink: the grounding guard (§10) — if the two findings do NOT share a real
// entity, the substrate surfaces NO chain (so the discovery decoys, which look impactful but don't actually
// link, are honest: the engine wouldn't manufacture the bridge either).
func TestSubstrateNoChainWithoutRealLink(t *testing.T) {
	assets := []platform.Asset{
		{ID: "a-repo", Type: "repository", Target: "github.com/acme/app"},
		{ID: "a-cloud", Type: "cloud_account", Target: "aws:123456789012"},
	}
	findings := []types.Finding{
		{ID: "f-leak", Tool: "gitleaks", Severity: types.SeverityHigh, Title: "Key committed", Description: "Hardcoded AKIAIOSFODNN7EXAMPLE"},
		{ID: "f-cloud", Tool: "prowler", Severity: types.SeverityHigh, Title: "Role has AdministratorAccess", Endpoint: "AwsIamRole other @global", Description: "unrelated role AKIAUNRELATEDKEY0000 with admin"},
	}
	if chains := crossdetect.Correlate(assets, findings); len(chains) != 0 {
		t.Errorf("no shared entity → no chain; substrate must not invent a bridge, got %d", len(chains))
	}
}
