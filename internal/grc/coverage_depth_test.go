package grc

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/tracer/hooks"
)

// coverage_depth_test.go covers the Q6 finding: every framework IS wired, and the DEPTH of the
// wiring is wildly uneven — measured on the real crosswalk, nist_800_53 maps 20 distinct controls
// and dpdp, sox, pipeda and iso22301 map exactly one.
//
// That matters because AssessableControls is OUR crosswalk's count and also the denominator of
// AutomatedCoveragePct, so the shallower the mapping the better the number looks. "1 of 1 technical
// controls assessed · 100%" is true of our mapping and nearly meaningless about the framework —
// the vacuous-pass shape §14.2 names, where a rate rises as the evidence behind it shrinks.

func TestCoverage_ShallowCrosswalkIsDisclosed(t *testing.T) {
	c := computeCoverage("dpdp", 1, 0, 1)
	if !c.ShallowCrosswalk {
		t.Fatal("a one-control framework is not marked shallow, so 100% coverage over a single mapped " +
			"control renders exactly like 100% over twenty")
	}
	if c.DepthNote == "" {
		t.Error("no depth note — the flag alone reaches an API consumer and never reaches a reader")
	}
	if !strings.Contains(c.Readiness, "machine-checkable here") {
		t.Errorf("the readiness line carries no depth qualifier. It is what the dashboard card shows, "+
			"and a caveat that travels separately from the number does not travel: %q", c.Readiness)
	}
}

func TestCoverage_DeepCrosswalkIsNotQualified(t *testing.T) {
	// The negative that makes the positive mean something: a framework we map broadly must not be
	// hedged, or the qualifier becomes noise everyone learns to skip.
	c := computeCoverage("nist_800_53", 20, 9, 3)
	if c.ShallowCrosswalk {
		t.Error("a twenty-control framework was marked shallow")
	}
	if c.DepthNote != "" || strings.Contains(c.Readiness, "machine-checkable here") {
		t.Error("a broadly-mapped framework carries the shallow caveat")
	}
}

// TestRealCrosswalkDepth_PerFrameworkFloors is the corpus-must-not-shrink guard (§14.2). It records
// the measured depth of every framework and fails if one LOSES controls — a framework quietly
// dropping from 20 mapped controls to 2 would otherwise keep reporting coverage, at a better
// percentage, on strictly weaker evidence.
func TestRealCrosswalkDepth_PerFrameworkFloors(t *testing.T) {
	// Measured 24 Aug 2026 against internal/tracer/hooks/data/compliance.json (50 CWEs). Floors are
	// the measured values: raise them when the crosswalk deepens, never lower one silently.
	floors := map[string]int{
		"nist_800_53": 20, "fedramp": 18, "nist_800_171": 18, "pci": 14, "cis_v8": 13,
		"nist_csf": 13, "iso27001": 9, "soc2": 9, "cmmc": 7, "rbi": 6, "sebi": 6,
		"hipaa": 5, "glba": 4, "iso27018": 4, "iso27701": 3, "iso42001": 3, "nist_ai_rmf": 3,
		"ccpa": 2, "certin": 2, "eu_ai_act": 2, "gdpr": 2,
		"dpdp": 1, "iso22301": 1, "pipeda": 1, "sox": 1,
	}
	universe := hooks.NewCompliance().ControlsFor
	for _, fw := range Frameworks {
		got := len(universe(fw))
		floor, known := floors[fw]
		if !known {
			t.Errorf("framework %q has no recorded depth floor. A new framework must record one, or the "+
				"guard silently stops covering it.", fw)
			continue
		}
		if got < floor {
			t.Errorf("%s maps %d controls, floor is %d — the crosswalk LOST controls. Coverage would keep "+
				"reporting, at a better percentage, on weaker evidence.", fw, got, floor)
		}
		if got > floor {
			t.Logf("%s deepened: %d controls (floor %d) — raise the floor", fw, got, floor)
		}
	}
	for fw := range floors {
		var declared bool
		for _, f := range Frameworks {
			if f == fw {
				declared = true
			}
		}
		if !declared {
			t.Errorf("floor recorded for %q, which is not in Frameworks — stale entry", fw)
		}
	}
}
