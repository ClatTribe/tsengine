package fleet

import (
	"context"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/webagent"
)

// Result is one engagement's output: the worker's UNTOUCHED report plus the worldview built from its
// debrief, and the known-route surface the ledger measures coverage against.
type Result struct {
	Report      *webagent.Report `json:"report"`
	Worldview   *Worldview       `json:"-"` // rendered via Ledger(); the map is unexported
	KnownRoutes []string         `json:"known_routes"`
}

// RunSingle is ADR 0030 Phase A: run ONE worker over the whole authorized surface (today's
// webagent.Investigate, called unchanged), then build the worldview from its findings post-hoc.
//
// STRANGLER GUARANTEE (D2): a 1-chunk, 1-worker fleet changes the worker's output by NOTHING —
// Result.Report IS exactly what webagent.Investigate returns, byte for byte. The worldview is purely
// additive, computed after the fact. TestFleet_SingleWorkerMatchesDirectInvestigate pins this before
// any parallelism ships, so the coordinator can never silently alter an engagement.
func RunSingle(ctx context.Context, llm cloudengine.LLM, cc *webagent.Context, opts webagent.Options) (*Result, error) {
	report, err := webagent.Investigate(ctx, llm, cc, opts)
	if err != nil {
		return nil, err
	}
	w := New()
	// Findings are pre-grounded by webagent's own indicator gate, so every claim carries evidence;
	// Update still enforces evidence-or-refuse as the structural backstop. A finding reaching here
	// without evidence is a contract violation — surfaced, never swallowed.
	if claims := ClaimsFromFindings(report.Findings); len(claims) > 0 {
		if err := w.Update(claims); err != nil {
			return nil, err
		}
	}
	// cc.Routes holds the surface the worker knew (target + seeds + discovered) after the run.
	return &Result{Report: report, Worldview: w, KnownRoutes: CanonicalRoutes(cc.Routes)}, nil
}
