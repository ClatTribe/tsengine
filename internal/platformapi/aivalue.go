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
	for _, e := range rows {
		if e.At.Before(since) {
			continue
		}
		sv := by[e.Surface]
		if sv == nil {
			sv = &surfaceValue{Surface: e.Surface}
			by[e.Surface] = sv
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
			case e.PerCall:
				v.Calls++
				if !e.CostKnown {
					v.UnknownCostCalls++
				}
			default:
				v.Runs++
				if !e.CostKnown {
					v.UnknownCostRuns++
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
		if v.Verified > 0 && v.UnknownCostRuns == 0 && v.UnknownCostCalls == 0 && v.USD > 0 {
			c := v.USD / float64(v.Verified)
			v.CostPerVerified = &c
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
