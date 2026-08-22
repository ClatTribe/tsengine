package cloudbench

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

var oneExpected = []CISExpectation{{ControlID: "2.1.1", Resource: "arn:aws:s3:::acme-data"}}

// "A signal to investigate" is not something anyone can act on as an integer, and WHICH resource it
// is decides what the number means: a real false positive is a specificity problem in the engine,
// while a violation the ground truth never enumerated is a gap in the FIXTURE — in which case the
// recall figure is understated rather than the engine being noisy. Same integer, opposite
// conclusions.
func TestScoreCIS_NamesTheUnexpectedResources(t *testing.T) {
	s := ScoreCIS([]string{"arn:aws:s3:::acme-data", "arn:aws:s3:::mystery-bucket"}, oneExpected)
	if s.Unexpected != 1 {
		t.Fatalf("unexpected count = %d, want 1", s.Unexpected)
	}
	if len(s.UnexpectedResources) != 1 || s.UnexpectedResources[0] != "arn:aws:s3:::mystery-bucket" {
		t.Errorf("the unexpected resource must be named, got %v", s.UnexpectedResources)
	}
}

// The pseudo-node is not a cloud resource and cannot breach a CIS control. Counting it put a
// permanent floor of 1 under the only specificity signal this lane has — which both overstates our
// noise and hides the first REAL unexpected finding, since it would look like no change at all.
func TestScoreCIS_TheInternetPseudoNodeIsNotAnUnexpectedFinding(t *testing.T) {
	s := ScoreCIS([]string{"arn:aws:s3:::acme-data", cloudgraph.InternetID}, oneExpected)
	if s.Unexpected != 0 {
		t.Errorf("the synthetic attacker node was counted as a flagged resource: %v", s.UnexpectedResources)
	}
	if s.Found != 1 {
		t.Errorf("excluding the pseudo-node must not affect recall, got found=%d", s.Found)
	}
}

// The counterweight must print when the engine has NO lift — that is exactly when a reader needs to
// know whether we are merely noisier than prowler at the same recall. It used to be nested inside
// the lift branch and was therefore withheld precisely then.
func TestRenderCIS_ReportsUnexpectedEvenWithNoLift(t *testing.T) {
	same := ScoreCIS([]string{"arn:aws:s3:::acme-data"}, oneExpected)
	noisy := ScoreCIS([]string{"arn:aws:s3:::acme-data", "arn:aws:s3:::mystery-bucket"}, oneExpected)

	out := RenderCIS(same, noisy) // identical recall → no lift
	if strings.Contains(out, "engine lift") {
		t.Fatal("fixture error: this case must have no lift, or it does not test what it claims")
	}
	if !strings.Contains(out, "unexpected findings") {
		t.Error("the specificity counterweight was withheld on a no-lift run — the one number that " +
			"stops recall being gameable, missing exactly when recall shows nothing")
	}
	if !strings.Contains(out, "mystery-bucket") {
		t.Error("and it must name them")
	}
}
