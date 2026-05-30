package bench

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestScoreParity_AtParity(t *testing.T) {
	standalone := []types.Finding{
		{Tool: "prowler", RuleID: "prowler::iam_no_root_access_key", Endpoint: "iam @global"},
		{Tool: "prowler", RuleID: "prowler::s3_bucket_default_encryption", Endpoint: "s3 b1 @us-east-1"},
	}
	through := []types.Finding{
		// same two prowler findings survive into findings_raw, plus an extra
		// from a corroborating tool (must not count against prowler parity):
		{Tool: "prowler", RuleID: "prowler::iam_no_root_access_key", Endpoint: "iam @global"},
		{Tool: "prowler", RuleID: "prowler::s3_bucket_default_encryption", Endpoint: "s3 b1 @us-east-1"},
		{Tool: "scoutsuite", RuleID: "scoutsuite::s3-encryption", Endpoint: "s3 b1 @us-east-1"},
	}
	r := ScoreParity("prowler", standalone, through)
	if !r.Pass {
		t.Fatalf("expected parity PASS, got missed=%v", r.Missed)
	}
	if r.Recall != 1.0 {
		t.Errorf("recall = %v, want 1.0", r.Recall)
	}
	if r.StandaloneCount != 2 || r.Matched != 2 {
		t.Errorf("counts wrong: %+v", r)
	}
}

func TestScoreParity_OrchestrationDroppedFinding(t *testing.T) {
	standalone := []types.Finding{
		{Tool: "nuclei", RuleID: "nuclei::cve-2021-1", Endpoint: "https://x/a"},
		{Tool: "nuclei", RuleID: "nuclei::cve-2021-2", Endpoint: "https://x/b"},
	}
	// the orchestrated run is missing the /b finding — a recall regression.
	through := []types.Finding{
		{Tool: "nuclei", RuleID: "nuclei::cve-2021-1", Endpoint: "https://x/a"},
	}
	r := ScoreParity("nuclei", standalone, through)
	if r.Pass {
		t.Fatal("expected parity FAIL when orchestration drops a finding")
	}
	if len(r.Missed) != 1 || r.Missed[0] != "nuclei::cve-2021-2|https://x/b" {
		t.Errorf("missed set wrong: %v", r.Missed)
	}
	if r.Recall != 0.5 {
		t.Errorf("recall = %v, want 0.5", r.Recall)
	}
}

func TestScoreParity_OrchestrationAddsAreFine(t *testing.T) {
	// The orchestrated run finding MORE than the standalone tool (e.g. via
	// fan-out across a crawled surface) is fine — parity only gates drops.
	standalone := []types.Finding{
		{Tool: "dalfox", RuleID: "dalfox::xss", Endpoint: "https://x/1?q="},
	}
	through := []types.Finding{
		{Tool: "dalfox", RuleID: "dalfox::xss", Endpoint: "https://x/1?q="},
		{Tool: "dalfox", RuleID: "dalfox::xss", Endpoint: "https://x/2?q="},
		{Tool: "dalfox", RuleID: "dalfox::xss", Endpoint: "https://x/3?q="},
	}
	r := ScoreParity("dalfox", standalone, through)
	if !r.Pass || r.Recall != 1.0 {
		t.Fatalf("orchestration adds should still be parity PASS: %+v", r)
	}
	if r.OrchestratorAdds != 2 {
		t.Errorf("OrchestratorAdds = %d, want 2", r.OrchestratorAdds)
	}
}
