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
}

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
	notAssessed := assessable - assessed
	if notAssessed < 0 {
		notAssessed = 0 // a tenant may legitimately have more touched controls than the static universe
	}
	pct := 0.0
	if assessable > 0 {
		pct = float64(assessed) / float64(assessable) * 100
	}
	c := Coverage{
		Framework: framework, AssessableControls: assessable, AssessedControls: assessed,
		NotAssessed: notAssessed, Gaps: gaps, Met: met, AutomatedCoveragePct: pct, Certifiable: false,
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
		return fmt.Sprintf("%d gap(s) to remediate · %d of %d technical controls assessed by automated scanning",
			c.Gaps, c.AssessedControls, c.AssessableControls)
	default:
		return fmt.Sprintf("No automated gaps across the %d of %d technical controls assessed — this is NOT a compliance certification; the remaining %d control(s) and all procedural controls require auditor attestation",
			c.AssessedControls, c.AssessableControls, c.NotAssessed)
	}
}
