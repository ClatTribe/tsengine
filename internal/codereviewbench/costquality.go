package codereviewbench

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// costquality.go turns several scored runs into ONE cost-vs-quality table — the number that decides
// whether a cheaper model is worth routing to, stated the way §0 and the model-economics analyses
// demand: cost per CORRECT finding, not cost per token, with the spread across repeats shown so a
// single lucky run is not read as a result.
//
// It is model-free and deterministic: it consumes predictions files already written by `codereview run`
// (one per repeat per model) and the public corpus, so anyone can regenerate the exact table. That is
// the property the "17 vs 15" example lacked — a count from one run, graded by a model, with no way to
// re-check it.
//
// TWO HONESTY RULES, both inherited from the scorer:
//   - Cost per correct finding is withheld when ANY repeat of an arm has unknown cost, or when the arm
//     found nothing. An unknown cost is not zero, and a ratio with a zero denominator is not "cheap".
//   - A self-hosted / unpriced model reports its quality with cost shown as free, never as a frontier
//     estimate — the mistake #1533 fixed in the product, kept out of the benchmark too.

// Arm is one model configuration and the repeated runs measured for it.
type Arm struct {
	Label string        // human label, e.g. "qwen3:8b (local)"
	Runs  []Predictions // one per repeat; all must be the same (tool, model) or Aggregate rejects them
}

// ArmResult is the aggregated view of one arm across its repeats.
type ArmResult struct {
	Label   string `json:"label"`
	Tool    string `json:"tool"`
	Model   string `json:"model"`
	Repeats int    `json:"repeats"`

	// Recall is reported strict and lenient, each as mean with the min–max spread across repeats.
	RecallStrictMean  float64 `json:"recall_strict_mean"`
	RecallStrictMin   float64 `json:"recall_strict_min"`
	RecallStrictMax   float64 `json:"recall_strict_max"`
	RecallLenientMean float64 `json:"recall_lenient_mean"`

	PrecisionLBMean float64 `json:"precision_lb_mean"`
	KeyExaminedMean float64 `json:"key_examined_mean"` // mean cases the reviewer was shown a fixed file for
	ExaminedKnown   bool    `json:"examined_known"`    // whether any repeat reported what it examined

	// RanMean is the mean number of cases that actually ran — a tier that errors out on half the corpus
	// is not comparable on recall alone, so the denominator is shown.
	RanMean float64 `json:"ran_mean"`
	Cases   int     `json:"cases"`

	CostKnown   bool    `json:"cost_known"`  // true only when EVERY repeat reported a cost
	SelfHosted  bool    `json:"self_hosted"` // every repeat reported zero cost with cost known (free)
	CostMeanUSD float64 `json:"cost_mean_usd"`
	// CostPerCorrect is total cost / total strict-found cases across repeats. Nil when cost is unknown,
	// the model is self-hosted (free — the ratio is zero and misleading as a comparison), or nothing
	// was found.
	CostPerCorrectUSD *float64 `json:"cost_per_correct_usd,omitempty"`

	perRepeat []Score
}

// Comparison is the whole table plus the held-out verdict.
type Comparison struct {
	Arms        []ArmResult `json:"arms"`
	Cases       int         `json:"cases"`
	Cutoff      string      `json:"cutoff,omitempty"`
	AfterCutoff int         `json:"after_cutoff,omitempty"`
}

// Aggregate scores every arm's repeats against the corpus and summarises them. tol and cutoff are
// passed straight to ScoreAll. An arm whose repeats disagree on (tool, model) is an error: that is two
// configurations under one label, and averaging them would be the "17 vs 15" conflation.
func Aggregate(cases []Case, arms []Arm, tol int, cutoff string) (Comparison, error) {
	cmp := Comparison{Cases: len(cases), Cutoff: cutoff}
	for _, a := range arms {
		if len(a.Runs) == 0 {
			return cmp, fmt.Errorf("arm %q has no runs", a.Label)
		}
		ar := ArmResult{Label: a.Label, Repeats: len(a.Runs), Cases: len(cases)}
		tool, model := a.Runs[0].Tool, a.Runs[0].Model
		var costSum, ranSum, precSum, keyExSum, keyExDenom float64
		var strictVals []float64
		var lenientSum float64
		var foundTotal int
		costKnownAll, allFree := true, true
		for _, p := range a.Runs {
			if p.Tool != tool || p.Model != model {
				return cmp, fmt.Errorf("arm %q mixes configurations (%s/%s vs %s/%s) — that is two arms, not repeats",
					a.Label, tool, model, p.Tool, p.Model)
			}
			s := ScoreAll(cases, p, tol, cutoff)
			ar.perRepeat = append(ar.perRepeat, s)
			cmp.AfterCutoff = s.AfterCutoff
			strictVals = append(strictVals, s.RecallStrict)
			lenientSum += s.RecallLenient
			precSum += s.PrecisionLB
			ranSum += float64(s.Ran)
			if s.ExaminedKnown > 0 {
				keyExSum += float64(s.KeyExamined)
				keyExDenom++
				ar.ExaminedKnown = true
			}
			// strict-found cases this repeat = recall × ran, but count directly to avoid rounding.
			for _, c := range s.PerCase {
				if c.FoundStrict {
					foundTotal++
				}
			}
			if s.CostKnown {
				costSum += s.CostUSD
				if s.CostUSD > 0 {
					allFree = false
				}
			} else {
				costKnownAll = false
				allFree = false
			}
		}
		ar.Tool, ar.Model = tool, model
		n := float64(len(a.Runs))
		ar.RecallStrictMean = mean(strictVals)
		ar.RecallStrictMin, ar.RecallStrictMax = minMax(strictVals)
		ar.RecallLenientMean = lenientSum / n
		ar.PrecisionLBMean = precSum / n
		ar.RanMean = ranSum / n
		if keyExDenom > 0 {
			ar.KeyExaminedMean = keyExSum / keyExDenom
		}
		ar.CostKnown = costKnownAll
		ar.SelfHosted = costKnownAll && allFree
		if costKnownAll {
			ar.CostMeanUSD = costSum / n
		}
		// Cost per correct finding: only when cost is real (known, non-free) and something was found.
		if costKnownAll && !ar.SelfHosted && foundTotal > 0 {
			c := costSum / float64(foundTotal)
			ar.CostPerCorrectUSD = &c
		}
		cmp.Arms = append(cmp.Arms, ar)
	}
	return cmp, nil
}

func mean(v []float64) float64 {
	if len(v) == 0 {
		return 0
	}
	var s float64
	for _, x := range v {
		s += x
	}
	return s / float64(len(v))
}

func minMax(v []float64) (float64, float64) {
	if len(v) == 0 {
		return 0, 0
	}
	lo, hi := v[0], v[0]
	for _, x := range v {
		lo, hi = math.Min(lo, x), math.Max(hi, x)
	}
	return lo, hi
}

// RenderComparison is the markdown table. Its caveats are part of the result.
func RenderComparison(cmp Comparison) string {
	var b strings.Builder
	b.WriteString("# Code-review cost vs quality\n\n")
	// Ordered by strict recall, best first — the quality axis leads, cost is the tiebreak a reader applies.
	arms := append([]ArmResult(nil), cmp.Arms...)
	sort.SliceStable(arms, func(i, j int) bool { return arms[i].RecallStrictMean > arms[j].RecallStrictMean })

	b.WriteString("| model | repeats | recall strict (min–max) | recall lenient | precision ≥ | shown a fixed file | cost/run | cost per correct |\n")
	b.WriteString("|---|---|---|---|---|---|---|---|\n")
	for _, a := range arms {
		shown := "—"
		if a.ExaminedKnown {
			shown = fmt.Sprintf("%.1f/%.0f", a.KeyExaminedMean, a.RanMean)
		}
		cost := "unknown"
		switch {
		case a.SelfHosted:
			cost = "$0 (self-hosted)"
		case a.CostKnown:
			cost = fmt.Sprintf("$%.2f", a.CostMeanUSD)
		}
		cpc := "—"
		switch {
		case a.SelfHosted:
			cpc = "$0"
		case a.CostPerCorrectUSD != nil:
			cpc = fmt.Sprintf("$%.2f", *a.CostPerCorrectUSD)
		}
		fmt.Fprintf(&b, "| %s | %d | %.1f%% (%.1f–%.1f) | %.1f%% | %.1f%% | %s | %s | %s |\n",
			a.Label, a.Repeats,
			100*a.RecallStrictMean, 100*a.RecallStrictMin, 100*a.RecallStrictMax,
			100*a.RecallLenientMean, 100*a.PrecisionLBMean, shown, cost, cpc)
	}

	fmt.Fprintf(&b, "\n%d cases", cmp.Cases)
	if cmp.Cutoff != "" {
		fmt.Fprintf(&b, "; %d published after the %s cutoff", cmp.AfterCutoff, cmp.Cutoff)
	}
	b.WriteString(".\n\n## How to read this\n\n")
	b.WriteString("- **Cost per correct** is total spend ÷ cases located (strict) across all repeats — cost per *finding*, " +
		"not per token. Blank when a model reported no usage (unknown ≠ free) or found nothing.\n")
	b.WriteString("- **Recall is strict and lenient** (the answer key is the fix, not the bug, so the truth is between " +
		"them), and **precision is a lower bound** (off-key predictions are unjudged, not false).\n")
	b.WriteString("- **Shown a fixed file** separates coverage from detection: a low recall here means the planner never " +
		"pointed the model at the vulnerable file, so the model was not the bottleneck.\n")
	b.WriteString("- **Spread matters at this scale.** A gap smaller than the min–max range is noise; prefer more repeats " +
		"over trusting one run (DeepSecBench reports the median of three).\n\n")
	b.WriteString("> **Held-out status:** once this table is used to CHOOSE a model, the corpus is no longer held out for " +
		"that decision — a model picked on these cases has been tuned to them. Record the choice, then grow the corpus " +
		"before the next comparison (§14.2 rule 5).\n")
	return b.String()
}
