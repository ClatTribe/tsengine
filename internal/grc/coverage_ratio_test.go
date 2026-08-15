package grc

import "testing"

// TestCoverageNeverExceeds100 guards an arithmetic bug that reached the auditor-facing compliance
// report: "12 of 9 technical controls assessed (133%)". A tenant can genuinely touch more controls
// than the static universe lists (the CWE crosswalk maps a finding to every control it affects), so
// the fix is to widen the denominator rather than to drop the extra controls — but the ratio must
// stay coherent either way, because an impossible percentage puts every other number in the document
// in doubt.
func TestCoverageNeverExceeds100(t *testing.T) {
	cases := []struct {
		name                  string
		assessable, met, gaps int
	}{
		{"assessed exceeds static universe", 9, 5, 7}, // the reported bug: 12 of 9
		{"exactly equal", 10, 4, 6},
		{"normal partial coverage", 20, 3, 2},
		{"nothing assessed", 12, 0, 0},
		{"zero universe", 0, 2, 1},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := computeCoverage("soc2", c.assessable, c.met, c.gaps)
			assessed := c.met + c.gaps
			if got.AssessedControls > got.AssessableControls {
				t.Errorf("assessed %d > assessable %d — the report would read %q",
					got.AssessedControls, got.AssessableControls, "N of M where N>M")
			}
			if got.AutomatedCoveragePct > 100 {
				t.Errorf("coverage %.0f%% exceeds 100", got.AutomatedCoveragePct)
			}
			if got.NotAssessed < 0 {
				t.Errorf("NotAssessed negative: %d", got.NotAssessed)
			}
			// The extra controls must not be discarded — assessed still reflects real work done.
			if got.AssessedControls != assessed {
				t.Errorf("assessed = %d, want %d (extra controls must not be dropped)", got.AssessedControls, assessed)
			}
			// And it must never claim certification.
			if got.Certifiable {
				t.Error("Certifiable must always be false")
			}
		})
	}
}
