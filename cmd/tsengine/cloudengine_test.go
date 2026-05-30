package main

import (
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestAttachCloudEngine_DualView(t *testing.T) {
	inv := filepath.Join("..", "..", "fixtures", "cloud", "sample-inventory.json")

	// a cloud_account scan whose prowler findings_raw flags the data-role on the
	// real path (should corroborate) and a public-but-inert bucket (downgrade).
	scan := &types.Scan{
		Asset: types.Asset{Type: types.AssetCloudAccount},
		FindingsRaw: []types.Finding{
			{ID: "p-onpath", Tool: "prowler", Endpoint: "AWS::IAM::Role role-data @us-east-1"},
			{ID: "p-inert", Tool: "prowler", Endpoint: "AWS::S3::Bucket bucket-public-assets @us-east-1"},
		},
	}
	attachCloudEngine(scan, inv, "test")

	if scan.AIAssessment == nil {
		t.Fatal("a cloud_account scan with a snapshot must get an ai_assessment")
	}
	if len(scan.AIAssessment.Paths) != 1 {
		t.Fatalf("want 1 attack path (internet→…→PII), got %d", len(scan.AIAssessment.Paths))
	}
	if c := scan.AIAssessment.Paths[0].Corroborates; len(c) != 1 || c[0] != "p-onpath" {
		t.Errorf("the prowler finding on the path should be corroborated: %v", c)
	}
	if d := scan.AIAssessment.Downgraded; len(d) != 1 || d[0] != "p-inert" {
		t.Errorf("the off-path prowler finding should be downgraded: %v", d)
	}
}

func TestAttachCloudEngine_NoopForOtherAssets(t *testing.T) {
	scan := &types.Scan{Asset: types.Asset{Type: types.AssetWebApplication}}
	attachCloudEngine(scan, "anything.json", "test")
	if scan.AIAssessment != nil {
		t.Error("non-cloud assets must not get an ai_assessment")
	}
}
