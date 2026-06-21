package remediate

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestProposeCloud_S3PublicGetsLiveWritePath(t *testing.T) {
	asset := platform.Asset{
		ID: "a-cloud", TenantID: "t1", ConnectionID: "c-aws", Type: "cloud_account",
		Target: "aws:111122223333", Meta: map[string]string{"provider": "aws"},
	}
	// A DSPM/CSPM public-bucket finding.
	f := types.Finding{
		ID: "f1", Severity: types.SeverityHigh, Tool: "cloudengine",
		Title:  "cust-pii is internet-exposed: sensitive data publicly reachable",
		RuleID: "cloudengine::dspm", Endpoint: "arn:aws:s3:::cust-pii",
	}
	act, ok := Propose(f, asset, nil)
	if !ok {
		t.Fatal("a cloud finding should produce an action")
	}
	if act.Kind != platform.ActApplyConfig || act.Tier != tierApplyConfig {
		t.Errorf("cloud remediation should be a tier-2 gated ApplyConfig, got kind=%s tier=%d", act.Kind, act.Tier)
	}
	if act.Payload["remediation_type"] != "s3_block_public_access" {
		t.Errorf("an S3-public finding should carry the live remediation_type, got %v", act.Payload["remediation_type"])
	}
	// The target must be the specific bucket (resource), not the account.
	if act.Payload["target"] != "arn:aws:s3:::cust-pii" {
		t.Errorf("target should be the bucket resource, got %v", act.Payload["target"])
	}
}

func TestProposeCloud_NonS3StaysAccountRunbook(t *testing.T) {
	asset := platform.Asset{ID: "a", TenantID: "t1", Type: "cloud_account", Target: "aws:111122223333", Meta: map[string]string{"provider": "aws"}}
	// A non-S3-public cloud finding (e.g. root MFA) → no live write path yet.
	f := types.Finding{ID: "f2", Severity: types.SeverityHigh, Title: "Root account MFA not enabled", RuleID: "prowler::iam_root_mfa"}
	act, ok := Propose(f, asset, nil)
	if !ok {
		t.Fatal("should still produce an action")
	}
	if _, has := act.Payload["remediation_type"]; has {
		t.Error("a finding with no live write path must NOT carry a remediation_type (stays an account-scoped runbook)")
	}
	if act.Payload["target"] != "aws:111122223333" {
		t.Errorf("the account runbook target should be the account, got %v", act.Payload["target"])
	}
}

func TestLiveCloudMutation_ProviderGating(t *testing.T) {
	f := types.Finding{Title: "public S3 bucket exposed", Endpoint: "arn:aws:s3:::b"}
	if rt, _ := liveCloudMutation(f, "gcp"); rt != "" {
		t.Error("a non-AWS provider has no live cloud write path yet")
	}
	if rt, _ := liveCloudMutation(f, "aws"); rt != "s3_block_public_access" {
		t.Errorf("AWS S3-public should map to the live block, got %q", rt)
	}
	if rt, _ := liveCloudMutation(f, ""); rt != "s3_block_public_access" {
		t.Error("empty provider is treated as AWS (the only wired cloud connector)")
	}
}
