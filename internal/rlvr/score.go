package rlvr

import "fmt"

// Confusion is the eval-time confusion matrix over the GRADED episodes that carry a ground-
// truth label. It is deliberately built ONLY from labeled, gradeable episodes: an Ungradeable
// episode has no observation to score and a TruthUnknown episode has no answer key, so both
// are excluded from the matrix and counted separately — a rate computed over "everything we
// ran" would rise as targets became unreachable, the vacuous-pass shape (§14.2 rule 6).
//
// The headline is NOT accuracy. The product's entire value is that it says "no" correctly to
// a hallucinated exploit, so the governing number is Specificity — of the targets the corpus
// says are PATCHED, how many did the judge correctly refuse to call Exploited. A judge at 95%
// recall and 40% specificity rubber-stamps fakes and is worse than useless. Per §14.2 rule 5,
// this is the half that still means something once the training gaps are closed, because
// recall can only rise as exploitation signal is added.
type Confusion struct {
	// Over labeled + gradeable episodes:
	TP int `json:"tp"` // Truth=Vulnerable, Verdict=Exploited      (real exploit, correctly proven)
	FN int `json:"fn"` // Truth=Vulnerable, Verdict=NotExploited   (missed a real exploit)
	FP int `json:"fp"` // Truth=Patched,    Verdict=Exploited      (HALLUCINATION — the cardinal sin)
	TN int `json:"tn"` // Truth=Patched,    Verdict=NotExploited   (correctly refused)

	// Excluded from the matrix, reported so the denominators are honest:
	Ungradeable int `json:"ungradeable"` // target unreachable — DROPPED, never a negative
	Unlabeled   int `json:"unlabeled"`   // TruthUnknown — train episodes with no answer key
}

// Score builds the confusion matrix from a graded corpus.
func Score(gs []Graded) Confusion {
	var c Confusion
	for _, g := range gs {
		if g.Verdict == Ungradeable {
			c.Ungradeable++
			continue
		}
		switch g.Episode.Truth {
		case TruthVulnerable:
			if g.Verdict == Exploited {
				c.TP++
			} else {
				c.FN++
			}
		case TruthPatched:
			if g.Verdict == Exploited {
				c.FP++
			} else {
				c.TN++
			}
		default:
			c.Unlabeled++
		}
	}
	return c
}

// Specificity is the HEADLINE: TN / (TN + FP) — the fraction of patched targets the judge
// correctly refused to call exploited. Undefined (returns 0, ok=false) with no patched
// episodes, because a specificity claimed over zero negatives is the vacuous pass — there
// were no fakes to reject, so a perfect score means nothing.
func (c Confusion) Specificity() (float64, bool) {
	n := c.TN + c.FP
	if n == 0 {
		return 0, false
	}
	return float64(c.TN) / float64(n), true
}

// Recall is TP / (TP + FN). Reported beside specificity but never as the headline — recall
// can be bought with a looser predicate, and a verifier bought that way is the product's
// failure mode.
func (c Confusion) Recall() (float64, bool) {
	n := c.TP + c.FN
	if n == 0 {
		return 0, false
	}
	return float64(c.TP) / float64(n), true
}

// DropRate is Ungradeable / all episodes — the health signal. A corpus quietly failing to
// reach its targets shows up here rather than by silently shrinking the matrix; a high drop
// rate invalidates the run regardless of how clean the specificity looks.
func (c Confusion) DropRate() float64 {
	total := c.TP + c.FN + c.FP + c.TN + c.Ungradeable + c.Unlabeled
	if total == 0 {
		return 0
	}
	return float64(c.Ungradeable) / float64(total)
}

// Report renders the scorecard, specificity FIRST because it is the number that governs
// whether the judge is shippable. Follows §14.2: it states its own denominators so a reader
// cannot mistake "no negatives were tested" for "every negative was rejected".
func (c Confusion) Report() string {
	spec, okS := c.Specificity()
	rec, okR := c.Recall()
	line := func(v float64, ok bool) string {
		if !ok {
			return "n/a (no cases)"
		}
		return fmt.Sprintf("%.3f", v)
	}
	return fmt.Sprintf(
		"specificity (reject fakes): %s over %d patched  ·  recall: %s over %d vulnerable  ·  "+
			"FP=%d FN=%d  ·  dropped(ungradeable)=%d (%.1f%%)  ·  unlabeled(train-only)=%d",
		line(spec, okS), c.TN+c.FP, line(rec, okR), c.TP+c.FN, c.FP, c.FN,
		c.Ungradeable, 100*c.DropRate(), c.Unlabeled)
}
