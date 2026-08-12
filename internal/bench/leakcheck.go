package bench

import (
	"fmt"
	"math"
	"sort"
	"strings"
)

// leakcheck.go detects when a benchmark's ANSWER is inferable from its INPUT.
//
// WHY THIS EXISTS. Four separate times in this codebase a benchmark scored near-perfectly for the
// wrong reason, and each was caught by hand, late:
//
//	localize (default corpus) the deterministic substrate scored 1.00 — the sinks were blatant and the
//	                          decoys were `const Version = "1.2.3"`. No headroom, so no engine could
//	                          ever be distinguished from any other.
//	cwemap (first baseline)   the keyword table scored 1.00 because the corpus and the matcher had the
//	                          same author, and it keyed on that author's own phrasing.
//	triage (first corpus)     the decoy DESCRIPTIONS stated the conclusion ("not referenced outside
//	                          _test.go files"), so the model was graded on reading, not judgement.
//	WAVSEP (external!)        all 34 false-positive cases carry "FalsePositive" in the URL and no true
//	                          case does — a one-line grep scores 1.00. External provenance is no
//	                          protection: the corpus was built to test SCANNERS, not triagers.
//
// The common shape is a benchmark where a trivial classifier — one substring — separates the labels.
// That is worth detecting mechanically, because the author is exactly the person who cannot see it:
// they know the answer while writing the input, and a high score feels like success.
//
// WHAT IT DOES. For every token appearing in the corpus, it asks: if I classified purely on "does the
// input contain this token", how accurate would I be? A token that alone predicts the label is a leak.
//
// WHAT IT IS NOT. It cannot prove a corpus is good — only that this particular failure is absent. A
// corpus can be leak-free and still be too small, unrepresentative, or saturated. Read it as a
// necessary condition, never a certificate.

// LeakCase is one labelled example: the text an engine actually sees, and the truth.
type LeakCase struct {
	// Input is everything the engine is shown. Include every field it reads — a leak hiding in a
	// path or a rule id is exactly the kind this is meant to catch.
	Input string
	// Positive is the ground-truth label.
	Positive bool
}

// LeakReport is what the check found.
type LeakReport struct {
	// Token is the single strongest predictor found, "" when nothing predicts well.
	Token string
	// Separation is the token's Youden J as a standalone classifier: how well it tells the two classes
	// APART, not how often it is right.
	//
	// Raw accuracy cannot be used here, and the reason is the whole point of this file. WAVSEP is 97%
	// positive, so "always say true" already scores 0.97 and a token that perfectly marks every one of
	// the 34 negatives can only reach 1.00 — a 3-point gain that looks like noise. Measured by
	// separation that same token scores 1.00 against a 0.00 floor. Accuracy hides a total giveaway
	// under class imbalance; J cannot.
	Separation float64
	// Leaked reports whether the token separates the classes well enough to call it a giveaway.
	Leaked bool
	// Detail is a human-readable explanation for a bench report.
	Detail string
}

// leakThreshold is the separation (Youden J) at which a single token counts as a giveaway. 0.80 is
// deliberately high: a genuine signal word ("injection") legitimately correlates with the label, and
// flagging every one would make the check a nuisance that gets switched off. What we are hunting is
// the token that essentially IS the answer — J≈1.0 means it alone splits the corpus.
const leakThreshold = 0.80

// DetectLabelLeak reports whether any single token predicts the label.
func DetectLabelLeak(cases []LeakCase) LeakReport {
	if len(cases) < 4 {
		return LeakReport{Detail: "too few cases to check for leakage"}
	}
	pos := 0
	for _, c := range cases {
		if c.Positive {
			pos++
		}
	}
	neg := len(cases) - pos
	if pos == 0 || neg == 0 {
		return LeakReport{Detail: "corpus has only one label — nothing to separate"}
	}

	freq := map[string]bool{}
	for _, c := range cases {
		for _, tok := range tokenize(c.Input) {
			freq[tok] = true
		}
	}
	toks := make([]string, 0, len(freq))
	for t := range freq {
		toks = append(toks, t)
	}
	sort.Strings(toks) // deterministic winner when several tokens tie

	best, bestSep := "", 0.0
	for _, tok := range toks {
		var tp, fp int
		for _, c := range cases {
			if strings.Contains(strings.ToLower(c.Input), tok) {
				if c.Positive {
					tp++
				} else {
					fp++
				}
			}
		}
		// Youden J for "token present => positive", and for the inverted rule. A giveaway leaks in
		// whichever direction, so take the stronger.
		sens := float64(tp) / float64(pos)   // share of positives the token catches
		spec := 1 - float64(fp)/float64(neg) // share of negatives it correctly leaves alone
		sep := math.Abs(sens + spec - 1)     // |J| — direction-agnostic
		if sep > bestSep {
			best, bestSep = tok, sep
		}
	}

	r := LeakReport{Token: best, Separation: bestSep}
	r.Leaked = bestSep >= leakThreshold
	if r.Leaked {
		r.Detail = fmt.Sprintf(
			"the single token %q separates the classes at J=%.2f — the answer is inferable from the "+
				"input, so a score on this corpus measures string matching rather than judgement",
			best, bestSep)
	} else {
		r.Detail = fmt.Sprintf(
			"no single token separates the classes above J=%.2f (best: %q at J=%.2f) — no obvious label leak",
			leakThreshold, best, bestSep)
	}
	return r
}

// tokenize splits input into lowercase word-ish tokens worth testing. Short tokens are skipped: they
// match everywhere and would produce noise, not findings.
func tokenize(s string) []string {
	s = strings.ToLower(s)
	fields := strings.FieldsFunc(s, func(r rune) bool {
		return !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9')
	})
	seen := map[string]bool{}
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		if len(f) < 5 || seen[f] {
			continue
		}
		seen[f] = true
		out = append(out, f)
	}
	return out
}
