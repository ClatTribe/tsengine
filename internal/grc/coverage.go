package grc

import (
	"context"
	"fmt"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Coverage is the HONESTY layer over a framework's posture: how much of the framework our automated
// scanning actually assessed — so a clean result is never mis-read as "compliant". Absence of a gap means
// "no scanner flagged it", NOT "verified compliant": a control with no scan evidence is UNASSESSED, and
// procedural controls (policies, training, vendor management, BCP) can't be scanner-assessed at all. Every
// compliance report MUST carry this so we never present a false-compliant posture.
type Coverage struct {
	Framework            string  `json:"framework"`
	AssessableControls   int     `json:"assessable_controls"` // controls our crosswalk CAN evaluate (the tooling-addressable subset)
	AssessedControls     int     `json:"assessed_controls"`   // controls a finding has actually touched (met + gap)
	NotAssessed          int     `json:"not_assessed"`        // assessable but no scan evidence yet
	Gaps                 int     `json:"gaps"`
	Met                  int     `json:"met"`
	AutomatedCoveragePct float64 `json:"automated_coverage_pct"` // assessed / assessable, 0..100
	Certifiable          bool    `json:"certifiable"`            // ALWAYS false: an automated scan is never a certification
	Readiness            string  `json:"readiness"`              // honest one-liner, never the word "Compliant"
	// ShallowCrosswalk marks a framework our crosswalk maps only a handful of controls for.
	//
	// WHY THIS EXISTS. AssessableControls is OUR crosswalk's count, and it is also the denominator of
	// AutomatedCoveragePct — so the shallower our mapping, the better the number looks. Measured on
	// the real crosswalk: nist_800_53 maps 20 distinct controls, fedramp 18, pci 14 … and dpdp, sox,
	// pipeda and iso22301 map exactly ONE. A tenant selecting DPDP whose single mapped control is
	// touched reads "1 of 1 technical controls assessed" at 100% coverage, which is true of our
	// mapping and says almost nothing about the framework.
	//
	// Every framework IS wired end to end — all 25 produce a posture and a report from real findings.
	// This is about depth, not wiring, and the fix is disclosure rather than inventing control
	// mappings we have no nexus for (§8: a finding maps only where a real nexus exists).
	ShallowCrosswalk bool `json:"shallow_crosswalk,omitempty"`
	// DepthNote states the limit in words when the crosswalk is shallow, "" otherwise.
	DepthNote string `json:"depth_note,omitempty"`
}

// ShallowCrosswalkBelow is the control count under which a percentage stops describing a framework
// and starts describing our mapping of it. Four is deliberate: three of the shallow frameworks map
// one control and two map two, so the line sits above the cluster it exists to flag rather than
// being tuned to it.
const ShallowCrosswalkBelow = 4

// assessable returns how many controls the crosswalk can evaluate for a framework (0 if the universe
// provider isn't wired — coverage then degrades to "unavailable" rather than over-claiming).
func (g *GRC) assessable(framework string) int {
	if g.ControlUniverse == nil {
		return 0
	}
	return len(g.ControlUniverse(framework))
}

// Coverage computes the honest coverage for a framework directly from its posture (without building the
// full report) — the cheap path for the dashboard/summary.
func (g *GRC) Coverage(ctx context.Context, tenantID, framework string) (Coverage, error) {
	cs, err := g.Posture(ctx, tenantID, framework)
	if err != nil {
		return Coverage{}, err
	}
	met, gaps := 0, 0
	for _, c := range cs {
		switch c.State {
		case platform.ControlGap:
			gaps++
		case platform.ControlMet:
			met++
		}
	}
	return computeCoverage(framework, g.assessable(framework), met, gaps), nil
}

func computeCoverage(framework string, assessable, met, gaps int) Coverage {
	assessed := met + gaps
	// A tenant can legitimately touch MORE controls than the static universe lists: the CWE crosswalk
	// maps a finding to every control it genuinely affects, which can include controls outside the set
	// our scanners are catalogued as covering. That is real signal, not an error — but it used to be
	// reported as "12 of 9 technical controls assessed (133%)", twice, in the report handed to an
	// auditor. An impossible ratio does not read as nuance; it reads as arithmetic nobody checked, and
	// it puts every other number in the document in doubt.
	//
	// If we assessed 12 controls then at least 12 were assessable, so the static count was an
	// UNDERESTIMATE and the denominator widens to match. Coverage then stays a coherent fraction
	// (assessed <= assessable, pct <= 100) without discarding the extra controls or pretending the
	// static universe was right.
	if assessed > assessable {
		assessable = assessed
	}
	notAssessed := assessable - assessed
	pct := 0.0
	if assessable > 0 {
		pct = float64(assessed) / float64(assessable) * 100
	}
	c := Coverage{
		Framework: framework, AssessableControls: assessable, AssessedControls: assessed,
		NotAssessed: notAssessed, Gaps: gaps, Met: met, AutomatedCoveragePct: pct, Certifiable: false,
	}
	c.ShallowCrosswalk = c.AssessableControls > 0 && c.AssessableControls < ShallowCrosswalkBelow
	if c.ShallowCrosswalk {
		c.DepthNote = fmt.Sprintf("Our crosswalk maps %d technical control(s) for this framework, so the "+
			"coverage figure describes that narrow slice and not the framework, which has many more "+
			"controls than automated scanning can reach here. Read it as \"the controls we can check are "+
			"checked\", never as broad coverage.", c.AssessableControls)
	}
	c.Readiness = readiness(c)
	return c
}

// readiness is the honest status line — it NEVER says "Compliant" (only a human auditor attests that).
func readiness(c Coverage) string {
	switch {
	case c.AssessableControls == 0:
		return "Automated coverage unavailable for this framework"
	case c.AssessedControls == 0:
		return "Not yet assessed — connect assets and run a scan"
	case c.Gaps > 0:
		return fmt.Sprintf("%d gap(s) to remediate · %d of %d technical controls assessed by automated scanning%s",
			c.Gaps, c.AssessedControls, c.AssessableControls, shallowSuffix(c))
	default:
		return fmt.Sprintf("No automated gaps across the %d of %d technical controls assessed — this is NOT a compliance certification; the remaining %d control(s) and all procedural controls require auditor attestation%s",
			c.AssessedControls, c.AssessableControls, c.NotAssessed, shallowSuffix(c))
	}
}

// shallowSuffix appends the depth qualifier to the readiness line. It goes IN the line rather than
// beside it because the readiness string is what surfaces on the dashboard card, and a caveat that
// travels separately from the number it qualifies does not travel.
func shallowSuffix(c Coverage) string {
	if !c.ShallowCrosswalk {
		return ""
	}
	return fmt.Sprintf(" — note: only %d control(s) of this framework are machine-checkable here, so this is a narrow slice of it", c.AssessableControls)
}
