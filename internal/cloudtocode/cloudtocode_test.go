package cloudtocode

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// prowlerFinding builds a types.Finding shaped like the prowler wrapper emits,
// with an OCSF resource in raw_output.
func prowlerFinding(checkID, resType, name, region, arn string) types.Finding {
	raw, _ := json.Marshal(map[string]any{
		"resources": []map[string]any{
			{"uid": arn, "name": name, "type": resType, "region": region},
		},
	})
	return types.Finding{
		ID:        "f-" + checkID,
		RuleID:    "prowler::" + checkID,
		Tool:      "prowler",
		Severity:  types.SeverityHigh,
		Endpoint:  resType + " " + name + " @" + region,
		Title:     checkID,
		RawOutput: raw,
		ToolArgs:  map[string]string{"check_id": checkID},
	}
}

func mustIndex(t *testing.T) []Resource {
	t.Helper()
	idx, err := IndexDir(filepath.Join("testdata", "iac"))
	if err != nil {
		t.Fatalf("IndexDir: %v", err)
	}
	return idx
}

func TestAnnotate_HighConfidencePhysicalName(t *testing.T) {
	idx := mustIndex(t)
	f := prowlerFinding("s3_bucket_level_public_access_block", "AwsS3Bucket", "acme-prod-assets", "us-east-1", "arn:aws:s3:::acme-prod-assets")
	findings := []types.Finding{f}

	if n := Annotate(findings, idx); n != 1 {
		t.Fatalf("linked = %d, want 1", n)
	}
	p := findings[0].CodeProvenance
	if p == nil {
		t.Fatal("expected CodeProvenance, got nil")
	}
	if p.File != "s3.tf" || p.Line != 1 {
		t.Errorf("provenance = %s:%d, want s3.tf:1", p.File, p.Line)
	}
	if p.IaCResource != "aws_s3_bucket.assets" {
		t.Errorf("iac_resource = %q", p.IaCResource)
	}
	if p.Confidence != "high" {
		t.Errorf("confidence = %q, want high", p.Confidence)
	}
	if p.MatchedOn != "acme-prod-assets" {
		t.Errorf("matched_on = %q", p.MatchedOn)
	}
}

func TestAnnotate_MediumConfidenceLogicalName(t *testing.T) {
	idx := mustIndex(t)
	// The instance has no physical-name attribute; its block is named
	// "acme_app_server" and the live instance is "acme-app-server" → normalized
	// logical-name match → medium.
	f := prowlerFinding("ec2_instance_imdsv2_enabled", "AwsEc2Instance", "acme-app-server", "us-east-1", "")
	findings := []types.Finding{f}
	Annotate(findings, idx)

	p := findings[0].CodeProvenance
	if p == nil {
		t.Fatal("expected a medium-confidence link, got nil")
	}
	if p.Confidence != "medium" {
		t.Errorf("confidence = %q, want medium", p.Confidence)
	}
	if p.IaCResource != "aws_instance.acme_app_server" {
		t.Errorf("iac_resource = %q", p.IaCResource)
	}
}

func TestAnnotate_ARNTailMatch(t *testing.T) {
	idx := mustIndex(t)
	// Name absent, but the ARN tail carries the physical name.
	f := prowlerFinding("s3_bucket_default_encryption", "AwsS3Bucket", "", "us-east-1", "arn:aws:s3:::acme-prod-assets")
	findings := []types.Finding{f}
	Annotate(findings, idx)
	p := findings[0].CodeProvenance
	if p == nil || p.Confidence != "high" || p.IaCResource != "aws_s3_bucket.assets" {
		t.Fatalf("ARN-tail match failed: %+v", p)
	}
}

func TestAnnotate_TypeNexusGuardsAgainstNameCollision(t *testing.T) {
	idx := mustIndex(t)
	// An S3 finding whose name coincidentally equals the security group's name
	// must NOT link — the type nexus (s3 → aws_s3_bucket only) blocks it.
	f := prowlerFinding("s3_bucket_level_public_access_block", "AwsS3Bucket", "acme-web-sg", "us-east-1", "")
	findings := []types.Finding{f}
	Annotate(findings, idx)
	if findings[0].CodeProvenance != nil {
		t.Errorf("cross-service name collision should not link: %+v", findings[0].CodeProvenance)
	}
}

func TestAnnotate_NoLinkWhenResourceAbsentOrInterpolated(t *testing.T) {
	idx := mustIndex(t)
	// The logs bucket's physical name is an interpolation, so the live bucket's
	// real name appears nowhere in source → no guessed link.
	f := prowlerFinding("s3_bucket_level_public_access_block", "AwsS3Bucket", "acme-prod-logs-9f2a", "us-east-1", "")
	findings := []types.Finding{f}
	Annotate(findings, idx)
	if findings[0].CodeProvenance != nil {
		t.Errorf("absent/interpolated resource should not link: %+v", findings[0].CodeProvenance)
	}
}

func TestAnnotate_LeavesNonCloudFindingsUntouched(t *testing.T) {
	idx := mustIndex(t)
	web := types.Finding{ID: "w-1", RuleID: "nuclei::xss", Tool: "nuclei", Endpoint: "https://acme-prod-assets.example.com"}
	findings := []types.Finding{web}
	if n := Annotate(findings, idx); n != 0 {
		t.Errorf("non-cloud finding linked (n=%d)", n)
	}
	if findings[0].CodeProvenance != nil {
		t.Error("nuclei finding should never get CodeProvenance")
	}
}

func TestAnnotate_EmptyIndexIsNoop(t *testing.T) {
	f := prowlerFinding("s3_bucket_level_public_access_block", "AwsS3Bucket", "acme-prod-assets", "us-east-1", "")
	findings := []types.Finding{f}
	if n := Annotate(findings, nil); n != 0 {
		t.Errorf("empty index should link nothing, got %d", n)
	}
}

func TestServiceOf(t *testing.T) {
	cases := map[string]string{
		"s3_bucket_public":        "s3",
		"ec2_instance_imdsv2":     "ec2",
		"iam_user_mfa":            "iam",
		"rds_instance_encryption": "rds",
		"cloudtrail_enabled":      "cloudtrail",
		"":                        "",
	}
	for in, want := range cases {
		if got := serviceOf(in, ""); got != want {
			t.Errorf("serviceOf(%q) = %q, want %q", in, got, want)
		}
	}
	// OCSF-type fallback when no check id.
	if got := serviceOf("", "AwsS3Bucket"); got != "s3" {
		t.Errorf("serviceOf fallback = %q, want s3", got)
	}
}
