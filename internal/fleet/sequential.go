package fleet

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/webagent"
)

// SequentialResult is a chunked engagement's output: the merged worldview, the plan (with its
// overflow disclosure), and each chunk worker's untouched report. The fleet coordinator
// (RunFleet) returns the same shape plus its halt/skip disclosures, so callers read ONE result
// type across Phases B and C.
type SequentialResult struct {
	Worldview   *Worldview         `json:"-"`
	Plan        DecomposeResult    `json:"plan"`
	Reports     []*webagent.Report `json:"reports"`
	KnownRoutes []string           `json:"known_routes"`
	// Waves is how many state-coupled groups the plan split into (1 when everything was disjoint).
	Waves int `json:"waves"`
	// SkippedChunks names chunk ids NOT run because prior verdicts had already settled their
	// declared route×class (CoverK) — budget spent once, disclosed when not spent.
	SkippedChunks []string `json:"skipped_chunks,omitempty"`
	// Disclosures carries every honest halt: breaker latch, stall watchdog, envelope exhaustion.
	// Empty means the plan ran to completion.
	Disclosures []string `json:"disclosures,omitempty"`
	// Contexts holds each worker's live engagement context, aligned index-for-index with Reports —
	// the full transcripts a caller needs for evidence bundles / audit (RunFleet and RunSequential).
	Contexts []*webagent.Context `json:"-"`
	// Adjudications records every contested pair the Phase-D panel resolved — or kept contested
	// (fail-open) — with its votes and rationales. Nil when no adjudication ran.
	Adjudications []Adjudication `json:"adjudications,omitempty"`
	// Engagement-wide token/cost accounting (ADR 0030 Phase D): captured as a delta over the whole
	// fleet run from a cloudengine.UsageReporter brain, so concurrent workers sharing one client
	// still yield EXACT totals. Zero does not mean free — it means the brain did not report usage
	// (local fakes, providers that omit it), and callers must say "unknown", never "$0".
	TokensIn  int64   `json:"tokens_in,omitempty"`
	TokensOut int64   `json:"tokens_out,omitempty"`
	CostUSD   float64 `json:"cost_usd,omitempty"`
}

// CostPerFinding is $/finding over the reports' grounded findings. Zero findings returns NaN-free
// 0 — callers render absolute cost beside it rather than implying a division happened.
func (r *SequentialResult) CostPerFinding() float64 {
	n := 0
	for _, rep := range r.Reports {
		n += len(rep.Findings)
	}
	if n == 0 {
		return 0
	}
	return r.CostUSD / float64(n)
}

// RunSequential is ADR 0030 Phase B: decompose the surface into an ordered chunk plan, then run one
// worker per chunk ONE AT A TIME, merging each debrief into a single shared worldview. Sequential on
// purpose — it validates decomposition + adjudication on real runs with ZERO rate/state risk before
// Phase C adds the governor and parallelism.
//
// Each worker is today's webagent.Investigate over a chunk-scoped Options (its seeds + routes), called
// UNCHANGED — the strangler discipline holds per chunk exactly as RunSingle holds for the whole
// surface. Two chunks touching the same route that DISAGREE produce a Contested verdict via the
// worldview merge, never a silent clobber (TestFleet_SequentialContestedNotClobbered).
func RunSequential(ctx context.Context, llm cloudengine.LLM, target string, in FrontierInput, baseOpts webagent.Options) (*SequentialResult, error) {
	if in.Target == "" {
		in.Target = target
	}
	plan := Decompose(in)
	w := New()
	var reports []*webagent.Report
	var contexts []*webagent.Context
	var known []string
	for _, chunk := range plan.Chunks {
		cc := &webagent.Context{Target: target}
		contexts = append(contexts, cc)
		opts := baseOpts
		opts.Seed = append(append([]string{}, baseOpts.Seed...), chunk.Routes...)
		opts.SeedFindings = chunk.Seeds
		report, err := webagent.Investigate(ctx, llm, cc, opts)
		if err != nil {
			return nil, err
		}
		reports = append(reports, report)
		if claims := ClaimsFromChunk(chunk, report.Findings, cc.History); len(claims) > 0 {
			if err := w.Update(claims); err != nil {
				return nil, err
			}
		}
		known = append(known, CanonicalRoutes(cc.Routes)...)
	}
	return &SequentialResult{Worldview: w, Plan: plan, Reports: reports, KnownRoutes: sortUnique(known), Contexts: contexts}, nil
}

// Ledger renders the coverage ledger for a sequential engagement (same shape as Result.Ledger, plus
// the frontier overflow disclosure so a capped run says what it did not reach).
func (r *SequentialResult) Ledger() string {
	res := &Result{Worldview: r.Worldview, KnownRoutes: r.KnownRoutes}
	out := res.Ledger()
	if r.Plan.Disclosure != "" {
		out += "  " + r.Plan.Disclosure + "\n"
	}
	for _, adj := range r.Adjudications {
		if adj.Resolved == Contested {
			out += fmt.Sprintf("  adjudication %s×%s: panel deadlocked — kept CONTESTED (%s)\n",
				shortRoute(adj.Route), adj.Class, strings.Join(adj.Votes, "; "))
			continue
		}
		out += fmt.Sprintf("  adjudication %s×%s → %s (%s)\n",
			shortRoute(adj.Route), adj.Class, adj.Resolved, strings.Join(adj.Votes, "; "))
	}
	if r.CostUSD > 0 {
		out += fmt.Sprintf("  spend: $%.4f (%d in / %d out tokens, $%.4f/finding)\n",
			r.CostUSD, r.TokensIn, r.TokensOut, r.CostPerFinding())
	}
	return out
}

// shortRoute trims a canonical id to its path-ish tail for one-line rendering.
func shortRoute(id string) string {
	if i := strings.LastIndex(id, "/"); i >= 0 && i < len(id)-1 {
		return id[i+1:]
	}
	return id
}
