package bench

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestLoadCloudCases(t *testing.T) {
	csv := "# cis_control,section,check_id,violated\n" +
		"1.4,iam,iam_no_root_access_key,true\n" +
		"4.16,monitoring,securityhub_enabled,false\n"
	p := filepath.Join(t.TempDir(), "expected-controls.csv")
	if err := os.WriteFile(p, []byte(csv), 0o600); err != nil {
		t.Fatal(err)
	}
	cases, err := LoadCloudCases(p)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(cases) != 2 {
		t.Fatalf("want 2 cases (header skipped), got %d", len(cases))
	}
	if cases[0].Control != "1.4" || cases[0].Section != "iam" ||
		cases[0].CheckID != "iam_no_root_access_key" || !cases[0].Violated {
		t.Errorf("row0 mis-parsed: %+v", cases[0])
	}
	if cases[1].Violated {
		t.Errorf("row1 should be non-violated: %+v", cases[1])
	}
}

func TestScoreCloud_ConfusionMatrix(t *testing.T) {
	cases := []CloudCase{
		{Control: "1.4", Section: "iam", CheckID: "iam_no_root_access_key", Violated: true},   // flagged → TP
		{Control: "1.5", Section: "iam", CheckID: "iam_root_mfa_enabled", Violated: true},     // not flagged → FN
		{Control: "4.16", Section: "iam", CheckID: "securityhub_enabled", Violated: false},    // not flagged → TN
		{Control: "1.8", Section: "iam", CheckID: "iam_password_policy_min", Violated: false}, // flagged → FP
	}
	scan := &types.Scan{FindingsRaw: []types.Finding{
		{Tool: "prowler", RuleID: "prowler::iam_no_root_access_key"},
		{Tool: "prowler", RuleID: "prowler::iam_password_policy_min"},
		// a finding whose check_id matches no ground-truth control must not matter:
		{Tool: "prowler", RuleID: "prowler::guardduty_is_enabled"},
	}}
	rep := ScoreCloud(cases, scan)
	iam := rep.PerSection["iam"]
	if iam == nil {
		t.Fatal("no iam section")
	}
	if iam.TP != 1 || iam.FP != 1 || iam.TN != 1 || iam.FN != 1 {
		t.Errorf("confusion = TP%d FP%d TN%d FN%d, want 1/1/1/1", iam.TP, iam.FP, iam.TN, iam.FN)
	}
	if r := iam.Recall(); r > 0.51 || r < 0.49 { // 1/(1+1)
		t.Errorf("recall = %v, want ~0.5", r)
	}
	if rep.Overall.TP != 1 || rep.Overall.FN != 1 {
		t.Errorf("overall rollup wrong: %+v", rep.Overall)
	}
	if rep.Competitors.Leaderboard == "" && rep.Competitors.Note == "" {
		t.Error("report must carry the competitor citation")
	}
}

func TestMatchCheckID_NoPrefixCollision(t *testing.T) {
	// A short check_id must not collide with a longer one sharing its prefix.
	if matchCheckID("prowler::s3_bucket_public_access_block", "s3_bucket_public_access") {
		t.Error("s3_bucket_public_access must not match …_access_block (token boundary)")
	}
	if !matchCheckID("prowler::s3_bucket_public_access", "s3_bucket_public_access") {
		t.Error("exact check_id at end-of-rule_id should match")
	}
	if !matchCheckID("scoutsuite::s3_bucket_public_access@us-east-1", "s3_bucket_public_access") {
		t.Error("check_id followed by a non-identifier char ('@') should match")
	}
}
