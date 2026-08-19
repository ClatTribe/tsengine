package tenanteval

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
)

// trend.go answers the question the point-in-time score cannot: is the setup getting BETTER or WORSE
// on this estate?
//
// That is the differentiator — "your agent got worse at X on your estate" is a claim no public
// benchmark can make — but it is also the easiest place in this whole product to lie by accident,
// because two percentages will happily subtract whether or not they measure the same thing.
//
// Two rules keep it honest, and both refuse to draw a line rather than draw a misleading one:
//
//  1. One sample is not a trend. A single run has nothing to compare against, and rendering it as a
//     flat line implies stability that was never observed.
//  2. A trend across a CHANGING case set is not comparable. The suite grows every time someone
//     reinstates a finding or marks one a false positive — which is exactly what we want them to do
//     — but 80% of ten cases and 80% of twelve are not the same measurement. Comparing them would
//     punish or reward a customer for grading more of their own estate.
//
// SuiteHash is what makes rule 2 enforceable rather than aspirational: it fingerprints the graded
// set, so "did the suite change?" is a fact rather than a guess.

// SuiteHash fingerprints a case set — its findings AND what each is expected to do. Two runs with
// the same hash graded exactly the same examples the same way, so their scores are comparable.
//
// The EXPECTATION is part of the hash on purpose: if a human reverses their judgement on a case
// (they suppressed something, then reinstated it), the suite has materially changed even though its
// membership has not, and the two runs should not be compared.
func SuiteHash(cases []Case) string {
	keys := make([]string, 0, len(cases))
	for _, c := range cases {
		keys = append(keys, c.FindingID+"="+string(c.Expect))
	}
	sort.Strings(keys)
	sum := sha256.Sum256([]byte(strings.Join(keys, ";")))
	return hex.EncodeToString(sum[:])[:16]
}

// Run is one recorded evaluation — the shape persisted per tenant.
type Run struct {
	RanAt     string         `json:"ran_at"`
	Cases     int            `json:"cases"`
	Passed    int            `json:"passed"`
	SuiteHash string         `json:"suite_hash"`
	BySource  map[Source]int `json:"by_source,omitempty"`
}

// Trend is the comparison between the two most recent runs, or an explicit refusal to compare.
type Trend struct {
	// Comparable is false whenever the delta below would mislead. A reader should show Note instead.
	Comparable bool `json:"comparable"`
	// DeltaPoints is the change in agreement in PERCENTAGE POINTS (not a ratio of a ratio, which is
	// the classic way to make a small move look dramatic). Valid only when Comparable.
	DeltaPoints float64 `json:"delta_points,omitempty"`
	Direction   string  `json:"direction,omitempty"` // "improved" | "regressed" | "unchanged"
	Note        string  `json:"note"`
	Runs        int     `json:"runs"`
}

// TrendOf compares the last two runs, refusing when the comparison cannot be read honestly.
func TrendOf(runs []Run) Trend {
	t := Trend{Runs: len(runs)}
	switch {
	case len(runs) == 0:
		t.Note = "No evaluations have been recorded yet."
		return t
	case len(runs) == 1:
		t.Note = "Only one evaluation so far. A single run is a reading, not a trend — there is nothing " +
			"to compare it against yet."
		return t
	}

	prev, cur := runs[len(runs)-2], runs[len(runs)-1]
	if prev.SuiteHash != cur.SuiteHash {
		// The honest refusal. This is the COMMON case for a healthy customer, because the suite grows
		// every time they grade something — so the wording says that plainly rather than reading as a
		// malfunction.
		t.Note = fmt.Sprintf("The graded set changed between these runs (%d cases then, %d now), so the "+
			"two scores measure different things and are not compared. This is normal — the suite grows "+
			"each time you reinstate a finding, mark one a false positive, or confirm a fix.",
			prev.Cases, cur.Cases)
		return t
	}
	if prev.Cases == 0 {
		t.Note = "The previous run had no graded cases, so there is no score to compare against."
		return t
	}

	noun := "cases"
	if cur.Cases == 1 {
		noun = "case"
	}
	before := float64(prev.Passed) / float64(prev.Cases) * 100
	after := float64(cur.Passed) / float64(cur.Cases) * 100
	t.Comparable = true
	// Rounded to one decimal: this is a percentage-POINT delta, and emitting raw float noise
	// (-20.000000000000004) through the API would show up verbatim in somebody's UI.
	t.DeltaPoints = math.Round((after-before)*10) / 10
	switch {
	case t.DeltaPoints > 0:
		t.Direction = "improved"
		t.Note = fmt.Sprintf("Agreement rose %.0f points on the same %d graded %s.", t.DeltaPoints, cur.Cases, noun)
	case t.DeltaPoints < 0:
		t.Direction = "regressed"
		t.Note = fmt.Sprintf("Agreement FELL %.0f points on the same %d graded %s — the setup now "+
			"disagrees with your experts more often than it did.", -t.DeltaPoints, cur.Cases, noun)
	default:
		t.Direction = "unchanged"
		t.Note = fmt.Sprintf("Agreement is unchanged on the same %d graded %s.", cur.Cases, noun)
	}
	return t
}
