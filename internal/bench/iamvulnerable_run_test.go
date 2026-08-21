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
