package remediate

import (
	"context"
	"strings"
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

func TestProposeCloud_UnclassifiableStaysAccountRunbook(t *testing.T) {
	asset := platform.Asset{ID: "a", TenantID: "t1", Type: "cloud_account", Target: "aws:111122223333", Meta: map[string]string{"provider": "aws"}}
	// A cloud finding that matches NO remediation class (not storage, not IAM, not SG/encryption/MFA/…)
	// → falls back to the generic account-scoped runbook with no remediation_type.
	f := types.Finding{ID: "f2", Severity: types.SeverityMedium, Title: "Tag policy is not applied to the account", RuleID: "prowler::org_tag_policy"}
	act, ok := Propose(f, asset, nil)
	if !ok {
		t.Fatal("should still produce an action")
	}
	if _, has := act.Payload["remediation_type"]; has {
		t.Errorf("an unclassifiable finding must NOT carry a remediation_type (stays an account-scoped runbook), got %v", act.Payload["remediation_type"])
	}
	if act.Payload["target"] != "aws:111122223333" {
		t.Errorf("the account runbook target should be the account, got %v", act.Payload["target"])
	}
}

// TestProposeCloud_BreadthCatalog: the Respond breadth catalog gives the common non-storage cloud-
// misconfig classes a class-correct remediation_type + a SPECIFIC runbook (grounded on the finding's own
// resource), instead of the old generic "review this" ticket. Each is named + promotable to a live write.
func TestProposeCloud_BreadthCatalog(t *testing.T) {
	asset := platform.Asset{ID: "a", TenantID: "t1", Type: "cloud_account", Target: "aws:111122223333", Meta: map[string]string{"provider": "aws"}}
	cases := []struct {
		name      string
		f         types.Finding
		wantType  string
		wantInRun string // a substring the specific runbook must contain (proves it's class-correct, not generic)
	}{
		{
			name:      "open security group",
			f:         types.Finding{ID: "sg", Title: "Security group allows 0.0.0.0/0 ingress on port 22", RuleID: "prowler::ec2_sg_open_ssh", Endpoint: "sg-0abc123"},
			wantType:  "sg_restrict_ingress",
			wantInRun: "revoke-security-group-ingress",
		},
		{
			name:      "unencrypted volume",
			f:         types.Finding{ID: "ebs", Title: "EBS volume is unencrypted at rest", RuleID: "prowler::ec2_ebs_encryption", Endpoint: "vol-0abc"},
			wantType:  "enable_encryption",
			wantInRun: "encryption at rest",
		},
		{
			name:      "public RDS",
			f:         types.Finding{ID: "rds", Title: "RDS database instance is publicly accessible", RuleID: "prowler::rds_public", Endpoint: "db-prod-1"},
			wantType:  "disable_public_access",
			wantInRun: "PubliclyAccessible=false",
		},
		{
			name:      "root MFA",
			f:         types.Finding{ID: "mfa", Title: "Root account MFA not enabled", RuleID: "prowler::iam_root_mfa", Endpoint: "root"},
			wantType:  "enforce_mfa",
			wantInRun: "MFA",
		},
		{
			name:      "cloudtrail disabled",
			f:         types.Finding{ID: "ct", Title: "CloudTrail logging is disabled in region", RuleID: "prowler::cloudtrail_disabled", Endpoint: "us-east-1"},
			wantType:  "enable_logging",
			wantInRun: "CloudTrail",
		},
		{
			name:      "root access key",
			f:         types.Finding{ID: "rk", Title: "Root account has an active access key", RuleID: "prowler::iam_root_key", Endpoint: "root"},
			wantType:  "remove_root_access_key",
			wantInRun: "root-account access key",
		},
		{
			name:      "weak password policy",
			f:         types.Finding{ID: "pp", Title: "Account password policy minimum length is too short", RuleID: "prowler::iam_password_policy", Endpoint: "aws:111122223333"},
			wantType:  "strengthen_password_policy",
			wantInRun: "update-account-password-policy",
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			act, ok := Propose(c.f, asset, nil)
			if !ok {
				t.Fatal("should produce an action")
			}
			if act.Payload["remediation_type"] != c.wantType {
				t.Errorf("want remediation_type %q, got %v", c.wantType, act.Payload["remediation_type"])
			}
			// target must be the finding's own resource (grounded), not the account.
			if c.f.Endpoint != "" && act.Payload["target"] != c.f.Endpoint {
				t.Errorf("target should be the finding's resource %q, got %v", c.f.Endpoint, act.Payload["target"])
			}
			run, _ := act.Payload["remediation"].(string)
			if !strings.Contains(run, c.wantInRun) {
				t.Errorf("runbook should be class-correct (contain %q), got:\n%s", c.wantInRun, run)
			}
		})
	}
}

func TestProposeCloud_IAMPrivescGetsLayerCorrectType(t *testing.T) {
	asset := platform.Asset{ID: "a", TenantID: "t1", Type: "cloud_account", Target: "aws:111122223333", Meta: map[string]string{"provider": "aws"}}
	// An IAM over-privilege / privesc finding — the right-layer fix is tighten the principal's policy,
	// not a storage toggle. No live write yet, so it's labeled iam_restrict + the principal as target.
	f := types.Finding{
		ID: "f3", Severity: types.SeverityHigh, Tool: "cloudengine",
		Title:    "IAM role allows privilege escalation to AdministratorAccess",
		RuleID:   "cloudengine::iam-privesc",
		Endpoint: "arn:aws:iam::111122223333:role/deploy",
	}
	act, ok := Propose(f, asset, nil)
	if !ok {
		t.Fatal("an IAM finding should produce an action")
	}
	if act.Payload["remediation_type"] != "iam_restrict" {
		t.Errorf("an IAM-privesc finding should carry the layer-correct iam_restrict type, got %v", act.Payload["remediation_type"])
	}
	if act.Payload["target"] != "arn:aws:iam::111122223333:role/deploy" {
		t.Errorf("target should be the offending principal, got %v", act.Payload["target"])
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
