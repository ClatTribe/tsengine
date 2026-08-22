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

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
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

	// Unexpected counts surfaced resources matching no expected violation.
	//
	// Recall alone is gameable: a scanner that flagged every resource scores 1.00. That is why the
	// SAST and WAVSEP lanes report Youden (TPR − FPR) and §14.1.1 mandates an FP half per asset.
	// Cloud was the one measured asset reporting sensitivity with no specificity counterpart, so its
	// "recall 1.00" was not comparable to SAST's 46.5% Youden.
	//
	// Deliberately NOT called false positives. On a curated fixture an unexpected finding is either
	// a real FP OR a genuine violation the ground truth never enumerated, and this scorer cannot
	// tell which (§10). Naming it honestly keeps it a signal to investigate, not a verdict.
	Unexpected int `json:"unexpected"`
	// UnexpectedResources NAMES them. The count alone was unactionable: this field's own comment
	// calls it "a signal to investigate", and nobody can investigate an integer — the resource was
	// known at the moment it was counted and thrown away one line later.
	//
	// It matters more here than a count usually would, because which one it is decides what the
	// number MEANS. A real false positive is a specificity problem in the engine; a genuine
	// violation the ground truth never enumerated is a gap in the FIXTURE, and the recall figure
	// above is then understated rather than the engine being noisy. Same integer, opposite
	// conclusions, and only the resource tells them apart.
	UnexpectedResources []string `json:"unexpected_resources,omitempty"`
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
	for _, r := range coveredResources {
		// cloudgraph.InternetID is a PSEUDO-NODE — "the well-known pseudo-node representing any
		// external attacker" — not a cloud resource. It cannot breach a CIS control, so counting it
		// as an unflagged-by-ground-truth resource permanently inflated the unexpected count by one,
		// on every run, for every fixture.
		//
		// That is worse than a cosmetic off-by-one: unexpected is the only specificity signal this
		// lane has, so a constant floor of 1 both overstates our noise and masks the first REAL
		// unexpected finding, which would look like no change at all.
		//
		// Found by naming the unexpected resources rather than counting them. The count said "1 —
		// either an FP or a fixture gap"; the name said "neither, it is our own attacker node".
		if r == cloudgraph.InternetID {
			continue
		}
		matched := false
		for _, e := range expected {
			if resourceMatch(r, e.Resource) {
				matched = true
				break
			}
		}
		if !matched {
			s.Unexpected++
			s.UnexpectedResources = append(s.UnexpectedResources, r)
		}
	}
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
	b.WriteString("\n")

	// OUTSIDE the lift branch, deliberately. This block used to be nested inside it, so the one
	// number that stops recall being gameable was printed only when the engine had a lift to show —
	// and withheld exactly when it did not, which is when a reader most needs to know whether we are
	// merely noisier than prowler at the same recall.
	fmt.Fprintf(&b, "  unexpected findings:  prowler/scout %d, tsengine %d\n"+
		"                        (NOT scored as false positives: on a curated fixture these are\n"+
		"                        either FPs or violations the ground truth never listed. Recall\n"+
		"                        alone is gameable — flag everything and it reads 1.00.)\n",
		prowlerOnly.Unexpected, withEngine.Unexpected)
	// Named, because "a signal to investigate" is not something anyone can act on as an integer —
	// and which resource it is decides what the number means. A real false positive is a specificity
	// problem in the engine; a violation the ground truth never enumerated is a gap in the FIXTURE,
	// and then the recall above is understated rather than the engine being noisy.
	if len(withEngine.UnexpectedResources) > 0 {
		b.WriteString("    tsengine flagged, not in ground truth:\n")
		for _, r := range withEngine.UnexpectedResources {
			fmt.Fprintf(&b, "      - %s\n", r)
		}
	}
	b.WriteString("\n")
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
