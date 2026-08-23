// Package exposuretrend answers the question CTEM exists to make answerable: is exposure going down?
//
// WHAT WAS ALREADY THERE, and why it was not enough. platform.SummarizeEpisodes already sums Opened
// and Closed across the corpus, correctly caveated, and the eval page renders it. But a LIFETIME
// TOTAL cannot show direction — "opened 40, closed 38" says nothing about whether this quarter is
// better than last. Direction needs a series.
//
// TWO HONESTY RULES, both inherited from the data rather than invented here:
//
//  1. CLOSED IS NOT FIXED. ledger.SecurityStateDelta says it outright: Closed means the issue STOPPED
//     APPEARING. A degraded scan, a descoped asset and a real fix all produce it. A burndown built on
//     "no longer detected" is the industry's standard chart and it is the flattering one — so the
//     strong signal is reported BESIDE it, never merged into it: ConfirmedFixed comes from re-test
//     having proven closure, which is a different and much smaller number.
//
//  2. AN UNSCORED RUN IS NOT A QUIET ONE. An episode whose delta could not be computed is a run whose
//     effect nobody measured. Counted as zero it would read as "nothing changed", so it is counted as
//     itself and reported alongside — the same discipline EpisodeStats.Scored already keeps.
//
// SCOPE: EpisodeRecord.Scope is what makes two episodes comparable, and ledger.Diff refuses a
// mismatch. A series that mixes scopes compares different censuses, so Trend says which scopes it
// included and flags a mixed one rather than quietly averaging them.
package exposuretrend

import (
	"sort"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// Point is one period's movement.
type Point struct {
	// Day is the UTC date this period covers (RFC3339 date).
	Day string `json:"day"`
	// Opened / Closed / Persisted are summed over the scored episodes that ran that day.
	Opened    int `json:"opened"`
	Closed    int `json:"closed"`
	Persisted int `json:"persisted"`
	// Episodes ran that day; Unscored is how many of them produced no measurable delta.
	Episodes int `json:"episodes"`
	Unscored int `json:"unscored"`
	// NetChange is Closed minus Opened, serialised so the reader is not doing arithmetic across
	// eight rows to see direction. Net() computed this and nothing called it — a method with a
	// carefully argued name and no caller.
	NetChange int `json:"net_change"`
}

// Net is closed minus opened for the period. Negative means exposure grew.
//
// Deliberately NOT called "reduction": Closed counts issues that stopped appearing, which is not the
// same as fixed, and a name that implied otherwise would smuggle the claim past the caveat.
func (p Point) Net() int { return p.Closed - p.Opened }

// Trend is the series plus what qualifies it.
type Trend struct {
	Points []Point `json:"points"`
	// ConfirmedFixed counts remediations a RE-TEST proved closed — the strong signal, reported beside
	// the series and never folded into Closed.
	ConfirmedFixed int `json:"confirmed_fixed"`
	// Unscored is the corpus-wide count of runs whose effect nobody could measure.
	Unscored int `json:"unscored"`
	// ScopesIncluded names the censuses this series spans; Mixed is true when there is more than one,
	// because those runs are not comparable to each other.
	ScopesIncluded []string `json:"scopes_included,omitempty"`
	Mixed          bool     `json:"mixed,omitempty"`
	// Caveat is rendered verbatim. A trend line without it is the chart everyone shows and nobody
	// qualifies.
	Caveat string `json:"caveat"`
}

const caveat = "Closed counts issues that STOPPED APPEARING in a later scan — a real fix, a descoped " +
	"asset and a degraded scan all produce it. Only \"confirmed fixed\" rests on a re-test having " +
	"proven closure. Runs whose effect could not be measured are counted as unscored, not as no change."

// Compute builds the series. scope filters to one census; "" includes all and flags the mix.
func Compute(eps []platform.EpisodeRecord, actions []platform.Action, scope string) Trend {
	t := Trend{Caveat: caveat}
	byDay := map[string]*Point{}
	scopes := map[string]bool{}

	for _, e := range eps {
		if scope != "" && e.Scope != scope {
			continue
		}
		scopes[e.Scope] = true
		day := e.RanAt.UTC().Format(time.DateOnly)
		p := byDay[day]
		if p == nil {
			p = &Point{Day: day}
			byDay[day] = p
		}
		p.Episodes++
		if e.Delta == nil {
			// Not a quiet run — an unmeasured one. Counted as itself so the series cannot read as
			// calm when it is simply blind.
			p.Unscored++
			t.Unscored++
			continue
		}
		p.Opened += len(e.Delta.Opened)
		p.Closed += len(e.Delta.Closed)
		p.Persisted += e.Delta.Persisted
	}

	// The strong signal, kept separate on purpose (see the package comment).
	for _, a := range actions {
		if a.Verification == nil {
			continue
		}
		switch a.Verification.Status {
		case platform.FixStatusFixed, "closed_with_proof":
			t.ConfirmedFixed++
		}
	}

	days := make([]string, 0, len(byDay))
	for d := range byDay {
		days = append(days, d)
	}
	sort.Strings(days)
	for _, d := range days {
		p := *byDay[d]
		p.NetChange = p.Net()
		t.Points = append(t.Points, p)
	}
	for s := range scopes {
		t.ScopesIncluded = append(t.ScopesIncluded, s)
	}
	sort.Strings(t.ScopesIncluded)
	t.Mixed = len(t.ScopesIncluded) > 1
	return t
}
