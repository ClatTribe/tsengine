package platformapi

import (
	"net/http"
	"sort"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// aivalue.go: what the AI cost, against what it proved, per surface (GET /v1/ai-value).
//
// The capital-allocation question — "which surface should get the tokens?" — cannot be answered without
// first knowing what each surface's tokens bought. Three rules keep the view honest:
//   - Unknown is not free. A run whose model reported no usage is counted as a run with UNKNOWN cost, and
//     cost-per-proof is withheld for a surface with any such run, because dividing a partial cost by the
//     whole outcome would make the AI look cheaper than it was.
//   - Proven, not claimed. The outcome is findings the run itself VERIFIED (a predicate ran), counted when
//     the run happened — not findings it mentioned.
//   - Fixes proven closed are shown as CONTEXT, not credited to the AI: a re-test proved the fix, but the
//     fix may have come from anywhere, and claiming it would be the overclaim this view exists to avoid.

type surfaceValue struct {
	Surface         string `json:"surface"`
	Runs            int    `json:"runs"`
	UnknownCostRuns int    `json:"unknown_cost_runs"`
	// Calls are single model calls recorded by the metering wrapper outside any run that prices itself
	// (aimeter.go) — the code sweep, exploit proposals, CWE attribution and the rest. They are spend, so
	// they count toward Spent and the monthly ceiling, but they are not runs.
	Calls            int `json:"calls"`
	UnknownCostCalls int `json:"unknown_cost_calls"`
	// SelfHosted counts runs and calls served by the tenant's own self-hosted model: $0 with the cost
	// known, shown as such so a bare $0 does not read as a missing number.
	SelfHosted      int      `json:"self_hosted"`
	USD             float64  `json:"usd"`
	Verified        int      `json:"verified"`
	CostPerVerified *float64 `json:"cost_per_verified,omitempty"`
	// Fix attribution. A call spent writing a fix carries the Action it produced (AISpend.ActionID); when a
	// re-test proves that fix closed the finding, the fix is VERIFIED. The cost per proven fix divides ALL
	// fix spend — including fixes that did not close, or are not re-tested yet — by the proven ones, because
	// dividing only the successes' cost would make the AI look cheaper than it was.
	FixesAttempted     int      `json:"fixes_attempted"`
	VerifiedFixes      int      `json:"verified_fixes"`
	CostPerVerifiedFix *float64 `json:"cost_per_verified_fix,omitempty"`
	// NoOutcomeUSD is priced spend on calls that produce neither a verified finding nor a fix (the code
	// sweep's candidates, CWE attribution, eval scoring). Shown so it is neither hidden in a cost-per-proof
	// numerator — inflating it — nor dropped from the total.
	NoOutcomeUSD float64 `json:"no_outcome_usd"`

	runUSD      float64 // priced spend of runs, the only rows that can verify findings
	fixUSD      float64
	fixUnpriced bool
}

type aiValueView struct {
	Days              int            `json:"days"`
	Surfaces          []surfaceValue `json:"surfaces"`
	Total             surfaceValue   `json:"total"`
	FixesProvenClosed int            `json:"fixes_proven_closed"`
	// Unmetered names the AI paths whose runs are not in this view yet, so a total is never read as all
	// AI spend.
	Unmetered []string `json:"unmetered"`
}

var unmeteredAIPaths = []string{
	// The Detection Skill triage runs on the operator's model inside the detector, below the per-tenant
	// resolve every other path goes through, so the meter never sees it.
	"Detection Skill triage of newly opened incidents",
}

func (d Deps) handleAIValue(w http.ResponseWriter, r *http.Request, tenantID string) {
	days := 30
	since := time.Now().UTC().AddDate(0, 0, -days)
	rows, err := d.Store.ListAISpend(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	var free map[string]bool
	if t, terr := d.Store.GetTenant(r.Context(), tenantID); terr == nil {
		free = selfHostedModels(t)
	}
	by := map[string]*surfaceValue{}
	view := aiValueView{Days: days, Surfaces: []surfaceValue{}, Total: surfaceValue{Surface: "all"}, Unmetered: unmeteredAIPaths}
	actionSurface := map[string]string{} // action id → the surface its fix spend was recorded on
	for _, e := range rows {
		if e.At.Before(since) {
			continue
		}
		sv := by[e.Surface]
		if sv == nil {
			sv = &surfaceValue{Surface: e.Surface}
			by[e.Surface] = sv
		}
		if e.ActionID != "" {
			actionSurface[e.ActionID] = e.Surface
		}
		if spendFree(e, free) {
			e.USD, e.CostKnown = 0, true
		}
		for _, v := range []*surfaceValue{sv, &view.Total} {
			v.Verified += e.Verified
			if e.CostKnown {
				v.USD += e.USD
			}
			if spendFree(e, free) {
				v.SelfHosted++
			}
			switch {
			case e.ActionID != "":
				v.Calls++
				if e.CostKnown {
					v.fixUSD += e.USD
				} else {
					v.UnknownCostCalls++
					v.fixUnpriced = true
				}
			case e.PerCall:
				v.Calls++
				if e.CostKnown {
					v.NoOutcomeUSD += e.USD
				} else {
					v.UnknownCostCalls++
				}
			default:
				v.Runs++
				if e.CostKnown {
					v.runUSD += e.USD
				} else {
					v.UnknownCostRuns++
				}
			}
		}
	}
	// Which of the fixes the AI wrote has a re-test proven closed. Read once; a store error leaves the fix
	// columns at zero attempted rather than pretending fixes failed.
	if len(actionSurface) > 0 {
		if acts, err := d.Store.ListActions(r.Context(), tenantID); err == nil {
			for _, a := range acts {
				s, ok := actionSurface[a.ID]
				if !ok {
					continue
				}
				proven := a.Verification != nil && (a.Verification.Status == platform.FixStatusFixed || a.Verification.Status == "closed_with_proof")
				for _, v := range []*surfaceValue{by[s], &view.Total} {
					v.FixesAttempted++
					if proven {
						v.VerifiedFixes++
					}
				}
			}
		}
	}
	for _, sv := range by {
		view.Surfaces = append(view.Surfaces, *sv)
	}
	view.Surfaces = append(view.Surfaces, view.Total)
	for i := range view.Surfaces {
		v := &view.Surfaces[i]
		// Per proven FINDING: only runs can verify a finding, so only their spend is the cost of one.
		// A known $0 is a real price — the tenant's own self-hosted model (#1533) — so it is shown, not
		// withheld; only an UNKNOWN cost withholds the figure.
		if v.Verified > 0 && v.UnknownCostRuns == 0 {
			c := v.runUSD / float64(v.Verified)
			v.CostPerVerified = &c
		}
		// Per proven FIX: all fix spend, failures included, over the fixes a re-test proved.
		if v.VerifiedFixes > 0 && !v.fixUnpriced {
			c := v.fixUSD / float64(v.VerifiedFixes)
			v.CostPerVerifiedFix = &c
		}
	}
	view.Total = view.Surfaces[len(view.Surfaces)-1]
	view.Surfaces = view.Surfaces[:len(view.Surfaces)-1]
	sort.Slice(view.Surfaces, func(i, j int) bool { return view.Surfaces[i].USD > view.Surfaces[j].USD })

	if acts, err := d.Store.ListActions(r.Context(), tenantID); err == nil {
		for _, a := range acts {
			if v := a.Verification; v != nil && !v.VerifiedAt.Before(since) &&
				(v.Status == platform.FixStatusFixed || v.Status == "closed_with_proof") {
				view.FixesProvenClosed++
			}
		}
	}
	writeJSON(w, http.StatusOK, view)
}
