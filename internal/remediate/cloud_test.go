package remediate

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The deliver gate must re-bind a live cloud-storage mutation to the finding it cites: a target that no
// longer matches the finding's resource (retargeted/misattributed) is refused, but a matching target —
// or an aged-out finding — proceeds (no false-refusal of a legit, previously-grounded action).
func TestVerifyCloudTargetGrounded(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f1", Endpoint: "arn:aws:s3:::bucket-A"})
	d := &Deliverer{Store: st}

	cloudAct := func(target, findingID string) platform.Action {
		return platform.Action{ID: "a1", TenantID: "t1", FindingID: findingID,
			Payload: map[string]any{"remediation_type": rtypeS3Block, "target": target}}
	}

	if err := d.verifyCloudTargetGrounded(ctx, cloudAct("arn:aws:s3:::bucket-A", "f1")); err != nil {
		t.Errorf("a target matching its finding must pass, got %v", err)
	}
	if err := d.verifyCloudTargetGrounded(ctx, cloudAct("arn:aws:s3:::bucket-B", "f1")); err == nil {
		t.Error("SECURITY: a cloud mutation retargeted away from its cited finding must be refused")
	}
	if err := d.verifyCloudTargetGrounded(ctx, cloudAct("arn:aws:s3:::bucket-A", "gone")); err != nil {
		t.Errorf("an aged-out finding must NOT false-refuse, got %v", err)
	}
	if err := d.verifyCloudTargetGrounded(ctx, cloudAct("arn:aws:s3:::bucket-A", "")); err == nil {
		t.Error("a cloud mutation with no finding binding must be refused")
	}
	pr := platform.Action{ID: "a2", TenantID: "t1", Payload: map[string]any{"target": "github.com/x/y"}}
	if err := d.verifyCloudTargetGrounded(ctx, pr); err != nil {
		t.Errorf("a non-cloud-storage action must be untouched, got %v", err)
	}
}

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
	f := types.Finding{Title: "public storage bucket exposed", Endpoint: "arn:aws:s3:::b"}
	if rt, _ := liveCloudMutation(f, "aws"); rt != "s3_block_public_access" {
		t.Errorf("AWS public-bucket should map to the live block, got %q", rt)
	}
	if rt, _ := liveCloudMutation(f, ""); rt != "s3_block_public_access" {
		t.Error("empty provider is treated as AWS")
	}
	// GCP now has a live write path too (GCS Public Access Prevention).
	if rt, tgt := liveCloudMutation(f, "gcp"); rt != "gcs_public_access_prevention" || tgt != "arn:aws:s3:::b" {
		t.Errorf("GCP public-bucket should map to PAP enforce, got rt=%q tgt=%q", rt, tgt)
	}
	// Azure now has a live write path too (disable storage public access).
	if rt, _ := liveCloudMutation(f, "azure"); rt != "azure_storage_disable_public_access" {
		t.Errorf("azure public-storage should map to disable-public-access, got %q", rt)
	}
	// an unsupported provider still has none.
	if rt, _ := liveCloudMutation(f, "oracle"); rt != "" {
		t.Errorf("an unsupported provider must have no live write path, got %q", rt)
	}
}
