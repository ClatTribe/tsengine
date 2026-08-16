package cloudbench

import (
	"os"
	"strings"
	"testing"
)

func expectations() []CISExpectation {
	return []CISExpectation{
		{ControlID: "1.4", Resource: "acct:root"},
		{ControlID: "2.1.1", Resource: "arn:aws:s3:::data"},
		{ControlID: "5.2", Resource: "sg-ssh"},
		{ControlID: "3.3", Resource: "arn:aws:s3:::pii"}, // the data-protection control DSPM uniquely covers
	}
}

func TestScoreCIS_RecallAndLift(t *testing.T) {
	exp := expectations()
	// Prowler-only covers 3 of 4 (misses the sensitive-data resource).
	prowler := []string{"acct:root", "arn:aws:s3:::data", "sg-ssh"}
	ps := ScoreCIS(prowler, exp)
	if ps.Found != 3 || ps.Total != 4 {
		t.Fatalf("prowler-only should cover 3/4, got %d/%d", ps.Found, ps.Total)
	}
	if ps.Recall < 0.74 || ps.Recall > 0.76 {
		t.Errorf("recall = %.2f, want 0.75", ps.Recall)
	}
	if len(ps.Missed) != 1 || ps.Missed[0].ControlID != "3.3" {
		t.Errorf("the data-protection control should be the miss, got %+v", ps.Missed)
	}

	// tsengine adds the DSPM exposure on the PII bucket → full coverage (the engine lift).
	engine := append(append([]string{}, prowler...), "internet", "arn:aws:s3:::pii")
	es := ScoreCIS(engine, exp)
	if es.Found != 4 || es.Recall != 1.0 {
		t.Errorf("tsengine should cover 4/4 (recall 1.0), got %d/%d (%.2f)", es.Found, es.Total, es.Recall)
	}
	if es.Recall <= ps.Recall {
		t.Error("the engine must lift recall above prowler-only on this baseline")
	}
}

func TestScoreCIS_GroundedMatch(t *testing.T) {
	exp := []CISExpectation{{ControlID: "2.1.1", Resource: "arn:aws:s3:::data"}}
	// No matching resource → not found (grounded; never assumed).
	if s := ScoreCIS([]string{"arn:aws:s3:::other"}, exp); s.Found != 0 {
		t.Errorf("a non-matching resource must not count as covered, got %d", s.Found)
	}
	// A qualified-vs-bare ARN still matches (substring both ways).
	if s := ScoreCIS([]string{"arn:aws:s3:::data/key.csv"}, exp); s.Found != 1 {
		t.Errorf("a more-qualified resource id should still match the violation, got %d", s.Found)
	}
}

// Anti-overfit guard (§14.2): the scorer must not hard-code any system-under-test or
// fixture-specific identifier — it scores by structure, not by memorized answers.
func TestNoSUTIdentifiersInScorer(t *testing.T) {
	src, err := os.ReadFile("cis.go")
	if err != nil {
		t.Fatal(err)
	}
	banned := []string{"cust-pii", "cust-data", "sg-public-ssh", "iam-user-ci", "111122223333", "cloudtrail"}
	low := strings.ToLower(string(src))
	for _, b := range banned {
		if strings.Contains(low, strings.ToLower(b)) {
			t.Errorf("scorer must not hard-code the fixture identifier %q", b)
		}
	}
}

func TestRenderCIS_HasCompetitorCitation(t *testing.T) {
	out := RenderCIS(ScoreCIS(nil, expectations()), ScoreCIS([]string{"acct:root"}, expectations()))
	// §14.2: every bench report must cite the neutral competitor baseline.
	if !strings.Contains(out, "Prowler") || !strings.Contains(out, "Scout") {
		t.Error("the scorecard must cite Prowler / Scout Suite (mandatory competitor citation)")
	}
}

// TestScoreCIS_CountsUnexpectedFindings pins the specificity counterpart.
//
// The cloud lane reported recall only — "of the violations the baseline says exist, how many did we
// find". That is gameable: flag every resource and it reads 1.00. SAST and WAVSEP report Youden for
// exactly this reason, and §14.1.1 mandates an FP half per asset; cloud was the one measured asset
// without one, which made its 1.00 incomparable to SAST's 46.5%.
func TestScoreCIS_CountsUnexpectedFindings(t *testing.T) {
	expected := []CISExpectation{
		{ControlID: "2.1.1", Resource: "arn:aws:s3:::cust-data"},
		{ControlID: "5.2", Resource: "sg-public-ssh"},
	}
	// Both real violations found, plus two resources nothing expected.
	s := ScoreCIS([]string{
		"arn:aws:s3:::cust-data", "sg-public-ssh",
		"arn:aws:s3:::unrelated-bucket", "sg-internal-only",
	}, expected)

	if s.Recall != 1 {
		t.Errorf("recall = %.2f, want 1.00 (both expected violations matched)", s.Recall)
	}
	if s.Unexpected != 2 {
		t.Errorf("Unexpected = %d, want 2.\nWithout this a scanner that flags everything scores a "+
			"perfect recall and looks flawless.", s.Unexpected)
	}
}

// A precise scan surfaces nothing beyond the baseline — the counter must not manufacture noise.
func TestScoreCIS_NoUnexpectedWhenExact(t *testing.T) {
	expected := []CISExpectation{{ControlID: "3.1", Resource: "111122223333:cloudtrail"}}
	if s := ScoreCIS([]string{"111122223333:cloudtrail"}, expected); s.Unexpected != 0 {
		t.Errorf("Unexpected = %d, want 0 for an exactly-matching scan", s.Unexpected)
	}
}
