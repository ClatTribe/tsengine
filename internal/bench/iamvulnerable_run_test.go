package bench

import (
	"os"
	"testing"
)

// TestScoreIAMVulnerable_Live runs the neutral corpus when it is present. Skipped
// otherwise, because a benchmark that fails for want of a checkout teaches people to
// ignore failures.
//
// Point it at the corpus with:
//
//	IAM_VULNERABLE_DIR=/path/to/iam-vulnerable/modules/free-resources/privesc-paths \
//	  go test ./internal/bench/ -run IAMVulnerable_Live -v
func TestScoreIAMVulnerable_Live(t *testing.T) {
	dir := os.Getenv("IAM_VULNERABLE_DIR")
	if dir == "" {
		t.Skip("set IAM_VULNERABLE_DIR to the corpus's privesc-paths directory")
	}
	res, err := ScoreIAMVulnerable(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + RenderIAMVulnerable(res))
	if res.Total == 0 {
		t.Fatal("no paths scored — the corpus shape changed and the extractor stopped matching, " +
			"which is exactly the failure this is meant to make visible")
	}
}

// TestScorePolicyCases_Live runs BishopFox's FP/FN control set — the half that says
// whether we are wrong in the expensive direction. Opt-in like the recall run.
//
//	IAM_VULNERABLE_TOOLTEST_DIR=/path/to/iam-vulnerable/modules/free-resources/tool-testing \
//	  go test ./internal/bench/ -run PolicyCases_Live -v
func TestScorePolicyCases_Live(t *testing.T) {
	dir := os.Getenv("IAM_VULNERABLE_TOOLTEST_DIR")
	if dir == "" {
		t.Skip("set IAM_VULNERABLE_TOOLTEST_DIR to the corpus's tool-testing directory")
	}
	res, err := ScorePolicyCases(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Log("\n" + RenderPolicyCases(res))
	if res.FPTotal+res.FNTotal == 0 {
		t.Fatal("no cases scored — the corpus shape changed and the extractor stopped matching")
	}
}
