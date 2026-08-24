package exposuretrend

import (
	"strings"
	"testing"
)

func series(days int, opened, closed, episodes, unscored int) Trend {
	t := Trend{Caveat: caveat}
	for i := 0; i < days; i++ {
		t.Points = append(t.Points, Point{
			Day: "2026-08-0" + string(rune('1'+i)), Opened: opened, Closed: closed,
			Episodes: episodes, Unscored: unscored, NetChange: closed - opened,
		})
	}
	return t
}

func TestEvaluate_NoObjectiveIsNotAPass(t *testing.T) {
	// The default must not be "net >= 0". A target nobody stated is not a target, and CTEM's scoping
	// question is precisely whether one was stated.
	v := Evaluate(series(5, 1, 5, 1, 0), Objective{})
	if v.Gradeable || v.Met {
		t.Error("an unset objective produced a verdict — a series with no declared target cannot pass or fail")
	}
	if !strings.Contains(v.Reason, "No exposure objective is set") {
		t.Errorf("the reason must say the objective is missing, not imply a miss: %q", v.Reason)
	}
}

func TestEvaluate_MetAndMissed(t *testing.T) {
	obj := Objective{Declared: true, NetPerWindow: 0}
	if v := Evaluate(series(5, 1, 4, 1, 0), obj); !v.Gradeable || !v.Met {
		t.Errorf("closing more than opens should meet a hold-the-line target: %+v", v)
	}
	v := Evaluate(series(5, 6, 1, 1, 0), obj)
	if !v.Gradeable {
		t.Fatalf("a clean five-day series must be gradeable: %s", v.Reason)
	}
	if v.Met {
		t.Error("exposure grew and the objective was reported met")
	}
	if !strings.Contains(v.Reason, "not coming down fast enough") {
		t.Errorf("a miss must say which way it missed: %q", v.Reason)
	}
}

func TestEvaluate_NetTargetMetButNothingProvenClosed(t *testing.T) {
	// The case worth naming: "closed" counts issues that stopped appearing. Meeting a direction
	// target while proving almost nothing is a different situation from meeting it properly, and the
	// verdict has to say so rather than passing.
	tr := series(5, 1, 5, 1, 0)
	tr.ConfirmedFixed = 1
	v := Evaluate(tr, Objective{Declared: true, NetPerWindow: 0, MinConfirmedFixed: 10})
	if v.Met {
		t.Error("the objective was reported met with 1 proven closure against a target of 10")
	}
	if !strings.Contains(v.Reason, "stopped appearing rather than on fixes anyone re-tested") {
		t.Errorf("the reason must explain that direction without proof is the weaker signal: %q", v.Reason)
	}
}

func TestEvaluate_RefusesWhatItCannotGrade(t *testing.T) {
	obj := Objective{Declared: true, NetPerWindow: 0}

	t.Run("mixed scopes", func(t *testing.T) {
		tr := series(5, 1, 4, 1, 0)
		tr.Mixed = true
		tr.ScopesIncluded = []string{"repo-a", "cloud-b"}
		v := Evaluate(tr, obj)
		if v.Gradeable {
			t.Error("graded a series spanning incomparable censuses — the trend's own doc says those runs " +
				"are not comparable, and summing them into a verdict launders that")
		}
		if !strings.Contains(v.Reason, "not comparable") {
			t.Errorf("reason must name the incomparability: %q", v.Reason)
		}
	})

	t.Run("too few days", func(t *testing.T) {
		v := Evaluate(series(2, 1, 4, 1, 0), obj)
		if v.Gradeable {
			t.Error("graded a two-day series")
		}
		if !strings.Contains(v.Reason, "too early to say") {
			t.Errorf("a short series is not a missed target and must not read like one: %q", v.Reason)
		}
	})

	t.Run("mostly unscored", func(t *testing.T) {
		// 4 of 5 runs each day produced no measurable delta.
		v := Evaluate(series(5, 1, 4, 5, 4), obj)
		if v.Gradeable {
			t.Error("graded a window where most runs produced no measurable change — the verdict would " +
				"describe the runs we could score rather than the programme")
		}
		if !strings.Contains(v.Reason, "minority") {
			t.Errorf("reason must say the measured runs are the minority: %q", v.Reason)
		}
	})
}

func TestEvaluate_WindowTakesTheTail(t *testing.T) {
	// Ten days: the first five grew exposure, the last five shrank it. A 5-day window must grade the
	// RECENT half, or an objective can be met forever on old progress.
	tr := series(5, 8, 1, 1, 0) // bad
	good := series(5, 1, 8, 1, 0)
	tr.Points = append(tr.Points, good.Points...)
	v := Evaluate(tr, Objective{Declared: true, NetPerWindow: 0, WindowDays: 5})
	if !v.Gradeable {
		t.Fatalf("should be gradeable: %s", v.Reason)
	}
	if !v.Met {
		t.Errorf("the recent five days closed more than they opened; the window graded the wrong end (net=%d)", v.Net)
	}
	if v.DaysMeasured != 5 {
		t.Errorf("DaysMeasured = %d, want 5 — the window was not applied", v.DaysMeasured)
	}
}

func TestVerdict_AlwaysRestatesTheTarget(t *testing.T) {
	v := Evaluate(series(5, 1, 4, 1, 0), Objective{Declared: true, NetPerWindow: 2, MinConfirmedFixed: 3, WindowDays: 7})
	for _, want := range []string{"net +2", "at least 3 proven closed", "7 days"} {
		if !strings.Contains(v.Target, want) {
			t.Errorf("target description is missing %q: %q", want, v.Target)
		}
	}
}

func TestObjective_HoldTheLineIsARealObjective(t *testing.T) {
	// The regression for a bug my own doc comment predicted: NetPerWindow 0 means "close at least as
	// much as opens", which is the most natural target in the product. Deriving Set() from whether any
	// field was non-zero made it indistinguishable from no objective at all.
	o := Objective{Declared: true, NetPerWindow: 0}
	if !o.Set() {
		t.Error("a declared hold-the-line objective reads as unset, so the most natural target in the " +
			"product can never be graded")
	}
	if (Objective{}).Set() {
		t.Error("an undeclared objective reads as set")
	}
	// And a value-carrying objective that nobody declared must still be unset — a stored zero value
	// with stray numbers in it is not a statement of intent.
	if (Objective{NetPerWindow: 5}).Set() {
		t.Error("an undeclared objective with values reads as set — intent is stated, not deduced")
	}
}
