package grc

import "testing"

func TestComputeCoverage_NeverCertifiableNeverCompliant(t *testing.T) {
	// 1 of 4 assessed, no gaps → honest "no automated gaps", NOT "compliant".
	c := computeCoverage("soc2", 4, 1, 0)
	if c.Certifiable {
		t.Error("automated coverage must never be certifiable")
	}
	if c.AssessedControls != 1 || c.NotAssessed != 3 || c.AutomatedCoveragePct != 25 {
		t.Errorf("coverage math wrong: %+v", c)
	}
	if containsWord(c.Readiness, "Compliant") || containsWord(c.Readiness, "compliant") && !containsWord(c.Readiness, "NOT a compliance") {
		t.Errorf("readiness must not assert compliance: %q", c.Readiness)
	}
	if !containsWord(c.Readiness, "NOT a compliance certification") {
		t.Errorf("a no-gap-but-partial readiness must disclaim certification: %q", c.Readiness)
	}
	// nothing assessed → explicit "not yet assessed", never "compliant".
	z := computeCoverage("soc2", 4, 0, 0)
	if !containsWord(z.Readiness, "Not yet assessed") {
		t.Errorf("zero-assessed readiness wrong: %q", z.Readiness)
	}
	// a gap present → gap-count readiness.
	gp := computeCoverage("soc2", 4, 1, 2)
	if gp.Gaps != 2 || !containsWord(gp.Readiness, "gap(s) to remediate") {
		t.Errorf("gap readiness wrong: %+v", gp)
	}
}

func containsWord(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && (indexOf(s, sub) >= 0)
}
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
