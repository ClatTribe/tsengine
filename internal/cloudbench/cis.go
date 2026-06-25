// Package cloudbench scores our cloud lane's CIS-control coverage against a ground-truth
// baseline — the proof number (ADR 0009 Phase 3). It is the OFFLINE complement to
// `tsbench cloud` (which runs the real binary against a live account through the sandbox):
// here a fixture account + its expected CIS violations are scored without any sandbox or AWS,
// so a defensible CIS-recall number runs on a laptop / in CI.
//
// The metric is per-CIS-control recall: of the violations the baseline says exist, how many
// does our pipeline surface? Because we WRAP prowler/scoutsuite for detection (§13), our
// prowler-only recall is prowler-parity by construction — the interesting number is the LIFT
// our engine adds (DSPM, workload/CWPP exposures cover data-protection / workload controls a
// raw CSPM finding doesn't attribute).
package cloudbench

import (
	"fmt"
	"sort"
	"strings"
)

// CISExpectation is one ground-truth CIS violation: the control it breaches + the resource it
// lives on. Authored per fixture account, never derived from the system under test.
type CISExpectation struct {
	ControlID string `json:"control_id"`
	Resource  string `json:"resource"`
	Title     string `json:"title,omitempty"`
	Severity  string `json:"severity,omitempty"`
}

// CISScore is the scorecard for one finding set against the baseline.
type CISScore struct {
	Total      int                  `json:"total"`
	Found      int                  `json:"found"`
	Recall     float64              `json:"recall"`
	PerControl map[string]bool      `json:"per_control"` // control_id → covered
	Missed     []CISExpectation     `json:"missed"`
	covered    map[string]CISResult // internal, by control
}

// CISResult records whether a control's violation was covered.
type CISResult struct {
	ControlID string
	Resource  string
	Covered   bool
}

// ScoreCIS measures CIS recall: a baseline violation is covered when any surfaced resource
// matches its resource (exact, or one contains the other — ARNs/ids vary in qualification).
// Grounded: a violation is "found" only on a real resource match, never assumed.
func ScoreCIS(coveredResources []string, expected []CISExpectation) CISScore {
	s := CISScore{Total: len(expected), PerControl: map[string]bool{}, covered: map[string]CISResult{}}
	for _, e := range expected {
		hit := false
		for _, r := range coveredResources {
			if resourceMatch(r, e.Resource) {
				hit = true
				break
			}
		}
		// A control is covered if ANY of its violations is covered.
		if hit {
			s.PerControl[e.ControlID] = true
		} else if _, seen := s.PerControl[e.ControlID]; !seen {
			s.PerControl[e.ControlID] = false
		}
		s.covered[e.ControlID+"|"+e.Resource] = CISResult{e.ControlID, e.Resource, hit}
		if !hit {
			s.Missed = append(s.Missed, e)
		}
	}
	for _, e := range expected {
		// count per-violation found (a control with multiple violations counts each)
		if s.covered[e.ControlID+"|"+e.Resource].Covered {
			s.Found++
		}
	}
	if s.Total > 0 {
		s.Recall = float64(s.Found) / float64(s.Total)
	}
	sort.Slice(s.Missed, func(i, j int) bool { return s.Missed[i].ControlID < s.Missed[j].ControlID })
	return s
}

func resourceMatch(a, b string) bool {
	a, b = strings.TrimSpace(a), strings.TrimSpace(b)
	if a == "" || b == "" {
		return false
	}
	return a == b || strings.Contains(a, b) || strings.Contains(b, a)
}

// RenderCIS formats the scorecard with the mandatory competitor citation (§14.2).
func RenderCIS(prowlerOnly, withEngine CISScore) string {
	var b strings.Builder
	b.WriteString("=== CIS baseline scorecard (offline) ===\n")
	fmt.Fprintf(&b, "baseline violations: %d\n\n", withEngine.Total)
	fmt.Fprintf(&b, "  prowler/scout only:   %d/%d  recall %.2f\n", prowlerOnly.Found, prowlerOnly.Total, prowlerOnly.Recall)
	fmt.Fprintf(&b, "  tsengine (engine+DSPM/CWPP): %d/%d  recall %.2f", withEngine.Found, withEngine.Total, withEngine.Recall)
	if lift := withEngine.Recall - prowlerOnly.Recall; lift > 0 {
		fmt.Fprintf(&b, "   (engine lift +%.2f)", lift)
	}
	b.WriteString("\n\n")
	if len(withEngine.Missed) > 0 {
		b.WriteString("  still missed:\n")
		for _, m := range withEngine.Missed {
			fmt.Fprintf(&b, "    - CIS %s on %s\n", m.ControlID, m.Resource)
		}
		b.WriteString("\n")
	}
	// §14.2: mandatory neutral competitor citation in every bench report.
	b.WriteString("comparison: Prowler / Scout Suite publish their own CIS coverage; no neutral cloud\n")
	b.WriteString("benchmark exists (Wiz/Orca don't publish one either). This offline scorecard measures\n")
	b.WriteString("our pipeline's recall over a fixture account; the live number runs via `tsbench cloud`.\n")
	return b.String()
}
