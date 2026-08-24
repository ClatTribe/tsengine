package exposuretrend

import (
	"fmt"
	"strings"
)

// objective.go is ADR 0028 G3: the stated target a trend is read against.
//
// The series already existed and was carefully qualified. What it could not do is answer the only
// question a program owner actually asks — IS THIS GOOD? A chart of opened-versus-closed tells you
// what happened; without a declared objective it cannot tell you whether what happened was the plan.
// CTEM's scoping phase asks how success is measured, and "we have a line going down" is not an answer
// to it.
//
// # What an objective may be expressed in
//
// Only signals the series really carries. Two:
//
//	NetPerWindow      closed − opened over the window. The headline direction.
//	MinConfirmedFixed remediations a RE-TEST proved closed. The strong signal.
//
// Deliberately NOT a percentage or a "risk score". Both would need a denominator we do not have (how
// many exposures exist that we never saw) and would let a target be met by scanning less.
//
// # When it refuses to grade
//
// This is the load-bearing half. A verdict is only issued when the series can support one:
//
//   - MIXED SCOPES → refuse. The trend's own doc says runs from different censuses "are not
//     comparable to each other"; summing them into a graded number would launder that.
//   - TOO FEW DAYS → refuse. Two data points and a target is a coin toss with a target on it.
//   - MOSTLY UNSCORED → refuse. If most runs produced no measurable delta, the measured ones are not
//     a sample of the programme, and grading them reports the runs we could see as the runs there were.
//
// A refusal says WHY and is not a failure: "we cannot tell you yet" and "you are missing the target"
// are different statements, and a page that renders them the same way is the thing this avoids.
type Objective struct {
	// Declared is whether a human actually set this objective.
	//
	// AN EXPLICIT FLAG, NOT AN INFERENCE FROM THE VALUES. The first version derived "is one set" from
	// whether any field was non-zero, which made the most natural objective in the product —
	// NetPerWindow: 0, "close at least as much as opens" — indistinguishable from having no objective
	// at all. My own doc comment two lines down said zero was a real target, and the code then treated
	// it as absence. Same mistake as inferring a claim from a field somebody else also sets: intent
	// has to be stated, never deduced.
	Declared bool `json:"declared"`
	// WindowDays is the period the target applies over. 0 means the whole series.
	WindowDays int `json:"window_days,omitempty"`
	// NetPerWindow is the required closed-minus-opened over the window. Zero is a real objective —
	// "hold the line", i.e. close at least as much as opens.
	NetPerWindow int `json:"net_per_window"`
	// MinConfirmedFixed is the required count of re-test-proven closures over the window. Optional;
	// 0 disables that clause rather than asserting a target of none.
	MinConfirmedFixed int `json:"min_confirmed_fixed,omitempty"`
}

// Set reports whether a program objective has actually been declared. An unset objective must not be
// silently treated as "net ≥ 0" — a default nobody chose is not a stated target, and CTEM's scoping
// question is whether the customer stated one.
func (o Objective) Set() bool { return o.Declared }

// Verdict is the graded answer, or an explained refusal to grade.
type Verdict struct {
	// Gradeable is false when the series cannot support a verdict. Then Met is meaningless and Reason
	// says what is missing.
	Gradeable bool `json:"gradeable"`
	Met       bool `json:"met,omitempty"`
	// Net and ConfirmedFixed are the measured actuals over the window.
	Net            int `json:"net"`
	ConfirmedFixed int `json:"confirmed_fixed"`
	// DaysMeasured is how many days of the window carried a scored episode.
	DaysMeasured int `json:"days_measured"`
	// Reason is why it was refused, or which clause failed. Rendered verbatim.
	Reason string `json:"reason"`
	// Target restates the objective so a reader is never comparing an actual against a target they
	// have to go and look up.
	Target string `json:"target"`
}

// MinDaysToGrade is the shortest series that can carry a verdict. Three is the smallest number that
// can show a direction rather than a pair of points.
const MinDaysToGrade = 3

// MaxUnscoredShare is how much of the series may be unmeasurable before a grade stops meaning
// anything. Half: past that, the measured runs are the minority and the number describes them rather
// than the programme.
const MaxUnscoredShare = 0.5

// Evaluate grades a trend against an objective, or refuses and says why.
func Evaluate(t Trend, o Objective) Verdict {
	v := Verdict{Target: o.describe()}

	if !o.Set() {
		v.Reason = "No exposure objective is set for this programme, so this series shows what happened " +
			"and cannot say whether it was the plan. Set a target — the smallest useful one is \"close at " +
			"least as much as opens\"."
		return v
	}

	pts := t.Points
	if o.WindowDays > 0 && len(pts) > o.WindowDays {
		pts = pts[len(pts)-o.WindowDays:] // the series is oldest-first; the window is the tail
	}

	var net, episodes, unscored int
	for _, p := range pts {
		net += p.Closed - p.Opened
		episodes += p.Episodes
		unscored += p.Unscored
	}
	v.Net = net
	v.ConfirmedFixed = t.ConfirmedFixed
	v.DaysMeasured = len(pts)

	// The three refusals, most disqualifying first.
	if t.Mixed {
		v.Reason = "This series spans more than one scope (" + strings.Join(t.ScopesIncluded, ", ") +
			"). Runs from different censuses are not comparable to each other, so grading their sum " +
			"would turn an incomparable mixture into a single number. Filter to one scope to get a verdict."
		return v
	}
	if len(pts) < MinDaysToGrade {
		v.Reason = fmt.Sprintf("Only %d day(s) of measured activity — at least %d are needed before a "+
			"target means anything. This is not a missed objective; it is too early to say.",
			len(pts), MinDaysToGrade)
		return v
	}
	if episodes > 0 && float64(unscored)/float64(episodes) > MaxUnscoredShare {
		v.Reason = fmt.Sprintf("%d of %d runs in this window produced no measurable change, so the "+
			"measured ones are the minority. A verdict here would describe the runs we could score "+
			"rather than the programme.", unscored, episodes)
		return v
	}

	v.Gradeable = true
	switch {
	case net < o.NetPerWindow:
		v.Reason = fmt.Sprintf("Net %+d against a target of %+d: exposure is not coming down fast enough "+
			"over this window.", net, o.NetPerWindow)
	case o.MinConfirmedFixed > 0 && t.ConfirmedFixed < o.MinConfirmedFixed:
		// Deliberately a separate failure with its own sentence. Meeting the net target while proving
		// almost nothing closed is the case worth naming: "closed" counts issues that stopped
		// appearing, and only confirmed-fixed rests on a re-test.
		v.Reason = fmt.Sprintf("Net %+d meets the target, but only %d remediation(s) were PROVEN closed "+
			"against a target of %d. The direction rests on issues that stopped appearing rather than on "+
			"fixes anyone re-tested.", net, t.ConfirmedFixed, o.MinConfirmedFixed)
	default:
		v.Met = true
		v.Reason = fmt.Sprintf("Net %+d against a target of %+d, with %d remediation(s) proven closed "+
			"by re-test.", net, o.NetPerWindow, t.ConfirmedFixed)
	}
	return v
}

func (o Objective) describe() string {
	if !o.Set() {
		return "none set"
	}
	parts := []string{fmt.Sprintf("net %+d", o.NetPerWindow)}
	if o.MinConfirmedFixed > 0 {
		parts = append(parts, fmt.Sprintf("at least %d proven closed", o.MinConfirmedFixed))
	}
	window := "the whole series"
	if o.WindowDays > 0 {
		window = fmt.Sprintf("%d days", o.WindowDays)
	}
	return strings.Join(parts, " · ") + " over " + window
}
