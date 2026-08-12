package bench

import (
	"context"
	"errors"
	"math"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// T1's scorer had NO tests. Every triage number quoted in the scorecard — 0.83 for the composed
// engine, 0.50 and 0.33 for the baselines — comes out of this arithmetic, and nothing checked it.
//
// The rendered table also makes a claim directly to the reader: "Keeping everything and dropping
// everything both score 0, so the number is only high when the engine genuinely separates signal from
// noise." That is the entire argument for using Youden J here rather than accuracy, and it was
// asserted in prose without a test behind it.

type fixedTriager struct {
	keep bool
	err  error
}

func (f fixedTriager) Engine() string { return "fixed" }
func (f fixedTriager) Triage(context.Context, types.Finding) (bool, error) {
	return f.keep, f.err
}

// oracleTriager is a perfect engine: it answers with the truth. Used to pin J=1.
type oracleTriager struct{ truth map[string]bool }

func (oracleTriager) Engine() string { return "oracle" }
func (o oracleTriager) Triage(_ context.Context, f types.Finding) (bool, error) {
	return o.truth[f.ID], nil
}

func mixedCases() []TriageCase {
	mk := func(id string, actionable bool) TriageCase {
		return TriageCase{
			Name: id, Actionable: actionable,
			Finding: types.Finding{ID: id, Title: id, Severity: types.SeverityHigh},
		}
	}
	return []TriageCase{mk("a", true), mk("b", true), mk("c", false), mk("d", false)}
}

func near(got, want float64) bool { return math.Abs(got-want) < 1e-9 }

// THE CLAIM THE TABLE MAKES. Both degenerate strategies must score 0, or Youden is the wrong metric
// and the whole comparison is meaningless — an engine that keeps everything would look competent.
func TestTriageYouden_DegenerateStrategiesScoreZero(t *testing.T) {
	ctx := context.Background()
	for _, tc := range []struct {
		name string
		keep bool
	}{{"keep everything", true}, {"drop everything", false}} {
		s, _, err := ScoreTriage(ctx, fixedTriager{keep: tc.keep}, mixedCases())
		if err != nil {
			t.Fatal(err)
		}
		if !near(s.Youden(), 0) {
			t.Errorf("%s scored J=%.4f, want 0 — the rendered table tells the reader both degenerate "+
				"strategies score 0, which is the entire reason for using Youden over accuracy",
				tc.name, s.Youden())
		}
	}
}

// A perfect engine must score 1, or the scale has no top.
func TestTriageYouden_PerfectEngineScoresOne(t *testing.T) {
	s, _, err := ScoreTriage(context.Background(),
		oracleTriager{truth: map[string]bool{"a": true, "b": true}}, mixedCases())
	if err != nil {
		t.Fatal(err)
	}
	if !near(s.Youden(), 1) {
		t.Errorf("a perfect engine scored J=%.4f, want 1 (kept=%d missed=%d dropped=%d falseAlarm=%d)",
			s.Youden(), s.Kept, s.Missed, s.Dropped, s.FalseAlarm)
	}
}

// A worked case with the arithmetic done by hand, so a refactor that changes the formula is caught
// rather than silently re-baselining every number in the scorecard.
func TestTriageYouden_WorkedExample(t *testing.T) {
	// Keeps a and c: catches one of two real (recall 0.5), drops one of two decoys (restraint 0.5).
	// J = 0.5 + 0.5 - 1 = 0.
	keepAC := oracleTriager{truth: map[string]bool{"a": true, "c": true}}
	s, _, err := ScoreTriage(context.Background(), keepAC, mixedCases())
	if err != nil {
		t.Fatal(err)
	}
	if s.Kept != 1 || s.Missed != 1 || s.Dropped != 1 || s.FalseAlarm != 1 {
		t.Fatalf("tally wrong: kept=%d missed=%d dropped=%d falseAlarm=%d", s.Kept, s.Missed, s.Dropped, s.FalseAlarm)
	}
	if !near(s.Recall(), 0.5) || !near(s.Restraint(), 0.5) || !near(s.Youden(), 0) {
		t.Errorf("recall=%.4f restraint=%.4f J=%.4f; want 0.5 / 0.5 / 0", s.Recall(), s.Restraint(), s.Youden())
	}
}

// An engine that ERRORS must not be scored as if it answered. A model that times out on every case
// would otherwise inherit whatever the empty tally produces, and that number would be reported as a
// capability.
func TestTriageScore_ErrorsAreNotCountedAsAnswers(t *testing.T) {
	s, _, err := ScoreTriage(context.Background(),
		fixedTriager{err: errors.New("model unavailable")}, mixedCases())
	if err != nil {
		t.Fatal(err)
	}
	if s.Errors != len(mixedCases()) {
		t.Errorf("Errors=%d, want %d — every case failed", s.Errors, len(mixedCases()))
	}
	if s.Kept+s.Missed+s.Dropped+s.FalseAlarm != 0 {
		t.Errorf("a wholly-failed run recorded %d graded answers", s.Kept+s.Missed+s.Dropped+s.FalseAlarm)
	}
}

// The rendered table must actually carry the degenerate-strategy caveat it is relied on to state.
func TestRenderTriage_StatesWhyYoudenNotAccuracy(t *testing.T) {
	out := RenderTriageScores([]TriageScore{{Engine: "x"}})
	for _, want := range []string{"Youden", "Keeping everything", "dropping everything"} {
		if !strings.Contains(out, want) {
			t.Errorf("rendered table lost %q — the reader needs to know why this metric was chosen", want)
		}
	}
}
