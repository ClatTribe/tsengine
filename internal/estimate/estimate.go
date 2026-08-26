// Package estimate prices a scan BEFORE it runs — ADR 0032 D2. The quote is a
// grounded heuristic over size signals, never a guess dressed as precision: when
// the signals cannot support one, Quote returns ok=false and names what was
// missing. The caller surfaces that honestly rather than inventing a number
// (§10 — an invented price is the pricing twin of a fabricated finding).
package estimate

import (
	"fmt"
	"math"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
)

// Depth selects how much model-backed work a scan includes.
type Depth string

const (
	DepthFast     Depth = "fast"     // anchors only; zero model spend
	DepthStandard Depth = "standard" // default: bounded hypothesis sweep
	DepthDeep     Depth = "deep"     // enlarged sweep + verification passes
)

// Normalize maps "" and unknowns to standard.
func NormalizeDepth(d string) Depth {
	switch Depth(strings.ToLower(strings.TrimSpace(d))) {
	case DepthFast:
		return DepthFast
	case DepthDeep:
		return DepthDeep
	default:
		return DepthStandard
	}
}

// SweepQuestionCap is the hypothesis-question budget per depth (D1's cap).
func SweepQuestionCap(d Depth) int {
	switch d {
	case DepthFast:
		return 0
	case DepthDeep:
		return 25
	default:
		return 12
	}
}

// Signals are the pre-run size facts the quote is derived from. Zero values mean
// "not measured", and a quote built on zero signals is refused, not invented.
type Signals struct {
	Files int // source files in scope (repository asset)
	LOC   int // lines of code in scope (optional refinement)
	URLs  int // discovered/seeded request surface (web/api assets)
}

// QuoteResult is a pre-run price with its derivation attached — Basis strings are
// rendered to the user so the number is auditable rather than oracular.
type QuoteResult struct {
	CostUSD   float64
	TokensIn  int64
	TokensOut int64
	Basis     []string
}

// Quote prices one scan at the given depth for the named brain. It returns
// ok=false (with the missing-signal names) when the signals cannot ground any
// line of the estimate. An unknown MODEL still quotes — priced at the default
// rate and labeled as such by the caller.
func Quote(depth Depth, model string, sig Signals) (QuoteResult, []string, bool) {
	d := NormalizeDepth(string(depth))
	var missing []string
	if sig.Files <= 0 && sig.LOC <= 0 && sig.URLs <= 0 {
		missing = append(missing, "files|loc|urls (at least one size signal is required)")
	}
	if len(missing) > 0 {
		return QuoteResult{}, missing, false
	}

	q := QuoteResult{Basis: []string{fmt.Sprintf("depth=%s", d)}}
	if d == DepthFast {
		q.Basis = append(q.Basis, "fast depth runs deterministic anchors only — no model spend")
		return q, nil, true
	}

	capQ := SweepQuestionCap(d)
	var questions float64
	switch {
	case sig.Files > 0:
		questions = math.Ceil(float64(sig.Files) / 50) // ~1 hypothesis question per 50 source files
		q.Basis = append(q.Basis, fmt.Sprintf("%d source file(s) → %.0f sweep question(s) (cap %d)", sig.Files, questions, capQ))
	case sig.URLs > 0:
		questions = math.Ceil(float64(sig.URLs) / 25)
		q.Basis = append(q.Basis, fmt.Sprintf("%d URL(s) → %.0f sweep question(s) (cap %d)", sig.URLs, questions, capQ))
	case sig.LOC > 0:
		questions = math.Ceil(float64(sig.LOC) / 2000)
		q.Basis = append(q.Basis, fmt.Sprintf("%d LOC → %.0f sweep question(s) (cap %d)", sig.LOC, questions, capQ))
	}
	if questions > float64(capQ) {
		questions = float64(capQ)
	}
	if questions < 1 {
		questions = 1
	}

	// Token model per sweep question: ~4k input (focused excerpt + prompt frame),
	// ~350 output (candidate verdict). Same constants codesweep's excerpt caps imply.
	u := cloudengine.Usage{
		InputTokens:  int64(questions)*4500 + 3000, // +3k system/prompt frame
		OutputTokens: int64(questions) * 350,
	}
	q.TokensIn, q.TokensOut = u.InputTokens, u.OutputTokens
	q.CostUSD = cloudengine.EstimateCost(model, u)
	q.Basis = append(q.Basis, fmt.Sprintf("priced at %s rates (unknown models use the default book, disclosed)", model))
	return q, nil, true
}
