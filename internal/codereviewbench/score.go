package codereviewbench

import (
	"fmt"
	"sort"
	"strings"
)

// Prediction is one location a reviewer reported.
type Prediction struct {
	File string `json:"file"`
	Line int    `json:"line"`
	Rule string `json:"rule,omitempty"`
}

// Predictions is one reviewer's output over a corpus. Ran records which cases the reviewer actually
// completed: a case it failed on is NOT a miss — it is a case nobody looked at, reported as such.
type Predictions struct {
	Tool  string                  `json:"tool"`
	Model string                  `json:"model,omitempty"`
	Cases map[string][]Prediction `json:"cases"`
	Ran   map[string]bool         `json:"ran"`
	// Errors names why a case did not run, so "not run" is never an unexplained gap.
	Errors map[string]string `json:"errors,omitempty"`
	// CostUSD is the total spend when the reviewer reports one; 0 with CostKnown false is "unknown".
	CostUSD   float64 `json:"cost_usd,omitempty"`
	CostKnown bool    `json:"cost_known,omitempty"`
}

// DefaultTolerance is how many lines either side of a changed line still counts as the same place.
const DefaultTolerance = 3

// CaseResult is one case's outcome.
type CaseResult struct {
	ID            string `json:"id"`
	Ran           bool   `json:"ran"`
	Error         string `json:"error,omitempty"`
	FoundStrict   bool   `json:"found_strict"`  // a prediction within tolerance of a changed line
	FoundLenient  bool   `json:"found_lenient"` // a prediction anywhere in a changed file
	Predictions   int    `json:"predictions"`
	MatchedStrict int    `json:"matched_strict"` // predictions that landed on the key
}

// Score is the corpus-level result. Every rate is over the cases that RAN.
type Score struct {
	Tool           string       `json:"tool"`
	Model          string       `json:"model,omitempty"`
	Cases          int          `json:"cases"`
	Ran            int          `json:"ran"`
	NotRun         int          `json:"not_run"`
	RecallStrict   float64      `json:"recall_strict"`
	RecallLenient  float64      `json:"recall_lenient"`
	PrecisionLB    float64      `json:"precision_lower_bound"`
	F2Strict       float64      `json:"f2_strict"` // DeepSecBench's formula, over strict recall and the precision LOWER BOUND
	Predictions    int          `json:"predictions"`
	Unjudged       int          `json:"unjudged"` // predictions off the key — unknown, not wrong
	CostUSD        float64      `json:"cost_usd,omitempty"`
	CostKnown      bool         `json:"cost_known"`
	PerCase        []CaseResult `json:"per_case"`
	AfterCutoff    int          `json:"after_cutoff,omitempty"` // cases published after the supplied cutoff
	CutoffSupplied string       `json:"cutoff,omitempty"`
}

// F2 is DeepSecBench's score: recall weighted twice as heavily as precision, because a missed
// vulnerability goes unfixed while a false positive costs a reviewer's time.
func F2(precision, recall float64) float64 {
	if precision <= 0 && recall <= 0 {
		return 0
	}
	return 5 * precision * recall / (4*precision + recall)
}

func hits(p Prediction, g Range, tol int) bool {
	return samePath(p.File, g.File) && p.Line >= g.Start-tol && p.Line <= g.End+tol
}

// ScoreAll grades predictions against the corpus. cutoff (YYYY-MM-DD, optional) counts how many cases
// were published after it — the contamination question, answered with a number.
func ScoreAll(cases []Case, preds Predictions, tol int, cutoff string) Score {
	if tol < 0 {
		tol = DefaultTolerance
	}
	s := Score{Tool: preds.Tool, Model: preds.Model, Cases: len(cases), CostUSD: preds.CostUSD,
		CostKnown: preds.CostKnown, CutoffSupplied: cutoff}
	var foundS, foundL, matched int
	for _, c := range cases {
		r := CaseResult{ID: c.ID, Ran: preds.Ran[c.ID], Error: preds.Errors[c.ID]}
		if cutoff != "" && c.PublishedAt > cutoff {
			s.AfterCutoff++
		}
		if !r.Ran {
			s.NotRun++
			s.PerCase = append(s.PerCase, r)
			continue
		}
		s.Ran++
		files := c.Files()
		ps := preds.Cases[c.ID]
		r.Predictions = len(ps)
		for _, p := range ps {
			onKey := false
			for _, g := range c.Golden {
				if hits(p, g, tol) {
					onKey = true
					break
				}
			}
			if onKey {
				r.MatchedStrict++
				r.FoundStrict = true
			}
			for _, f := range files {
				if samePath(p.File, f) {
					r.FoundLenient = true
				}
			}
		}
		if r.FoundStrict {
			foundS++
		}
		if r.FoundLenient {
			foundL++
		}
		matched += r.MatchedStrict
		s.Predictions += r.Predictions
		s.PerCase = append(s.PerCase, r)
	}
	if s.Ran > 0 {
		s.RecallStrict = float64(foundS) / float64(s.Ran)
		s.RecallLenient = float64(foundL) / float64(s.Ran)
	}
	if s.Predictions > 0 {
		s.PrecisionLB = float64(matched) / float64(s.Predictions)
	}
	s.Unjudged = s.Predictions - matched
	s.F2Strict = F2(s.PrecisionLB, s.RecallStrict)
	return s
}

// Render is the human report. Its caveats are part of the result: a number from this corpus read
// without them is a stronger claim than the corpus can support.
func Render(s Score) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Held-out code-review benchmark — %s", s.Tool)
	if s.Model != "" {
		fmt.Fprintf(&b, " (%s)", s.Model)
	}
	b.WriteString("\n\n")
	fmt.Fprintf(&b, "| metric | value |\n|---|---|\n")
	fmt.Fprintf(&b, "| cases | %d (ran %d, not run %d) |\n", s.Cases, s.Ran, s.NotRun)
	fmt.Fprintf(&b, "| recall — strict (within %d lines of a fixed line) | %.1f%% |\n", DefaultTolerance, 100*s.RecallStrict)
	fmt.Fprintf(&b, "| recall — lenient (anywhere in a fixed file) | %.1f%% |\n", 100*s.RecallLenient)
	fmt.Fprintf(&b, "| precision — LOWER BOUND | %.1f%% (%d of %d predictions on the key; %d unjudged) |\n",
		100*s.PrecisionLB, s.Predictions-s.Unjudged, s.Predictions, s.Unjudged)
	fmt.Fprintf(&b, "| F2 (strict recall, precision lower bound) | %.1f |\n", 100*s.F2Strict)
	if s.CostKnown {
		fmt.Fprintf(&b, "| cost | $%.2f |\n", s.CostUSD)
	} else {
		b.WriteString("| cost | unknown |\n")
	}
	if s.CutoffSupplied != "" {
		fmt.Fprintf(&b, "| cases published after %s | %d of %d |\n", s.CutoffSupplied, s.AfterCutoff, s.Cases)
	}
	b.WriteString("\n## How to read this\n\n")
	b.WriteString("- **The answer key is the fix, not the bug.** Each case is a published advisory pinned at the commit before its " +
		"fix; the key is the lines the fix changed. A fix in the caller marks the caller, so strict recall understates what " +
		"a reviewer found and lenient recall overstates it. The truth is between them.\n")
	b.WriteString("- **Precision is a lower bound.** A prediction off the key is UNJUDGED, not false — the code may hold real " +
		"bugs nobody has reported. No judge model re-grades them here.\n")
	b.WriteString("- **A case that did not run is not a miss.** Rates are over cases that ran; the rest are listed below with why.\n")
	b.WriteString("- **Comparison:** Vercel's DeepSecBench (private corpus, judge-model precision) reports its best entry at " +
		"~36% recall (gpt-6-sol, xhigh). Different corpus, different precision method — context, not a head-to-head. " +
		"Source: https://vercel.com/ai-gateway/leaderboards/deepsecbench\n")

	if s.NotRun > 0 {
		b.WriteString("\n## Not run\n\n")
		for _, r := range s.PerCase {
			if !r.Ran {
				why := r.Error
				if why == "" {
					why = "no result recorded"
				}
				fmt.Fprintf(&b, "- %s — %s\n", r.ID, why)
			}
		}
	}
	b.WriteString("\n## Per case\n\n| case | strict | lenient | predictions | on key |\n|---|---|---|---|---|\n")
	rows := append([]CaseResult(nil), s.PerCase...)
	sort.Slice(rows, func(i, j int) bool { return rows[i].ID < rows[j].ID })
	for _, r := range rows {
		if !r.Ran {
			continue
		}
		fmt.Fprintf(&b, "| %s | %s | %s | %d | %d |\n", r.ID, yes(r.FoundStrict), yes(r.FoundLenient), r.Predictions, r.MatchedStrict)
	}
	return b.String()
}

func yes(v bool) string {
	if v {
		return "✓"
	}
	return "—"
}
