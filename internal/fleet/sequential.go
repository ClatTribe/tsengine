package fleet

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/webagent"
)

// SequentialResult is a chunked engagement's output: the merged worldview, the plan (with its
// overflow disclosure), and each chunk worker's untouched report.
type SequentialResult struct {
	Worldview   *Worldview         `json:"-"`
	Plan        DecomposeResult    `json:"plan"`
	Reports     []*webagent.Report `json:"reports"`
	KnownRoutes []string           `json:"known_routes"`
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
	var known []string
	for _, chunk := range plan.Chunks {
		cc := &webagent.Context{Target: target}
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
	return &SequentialResult{Worldview: w, Plan: plan, Reports: reports, KnownRoutes: sortUnique(known)}, nil
}

// Ledger renders the coverage ledger for a sequential engagement (same shape as Result.Ledger, plus
// the frontier overflow disclosure so a capped run says what it did not reach).
func (r *SequentialResult) Ledger() string {
	res := &Result{Worldview: r.Worldview, KnownRoutes: r.KnownRoutes}
	out := res.Ledger()
	if r.Plan.Disclosure != "" {
		out += "  " + r.Plan.Disclosure + "\n"
	}
	return out
}
