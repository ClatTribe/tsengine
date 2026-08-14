package platformapi

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
)

// aimode.go is the customer's own control over how much AI runs, and what it is costing them.
//
// WHY IT IS A PRODUCT CONTROL. Whether an agent runs was previously decided entirely by us — the plan
// they bought, plus whether they had pasted a key. A customer could not say "not yet". At the
// seed/Series-A stage the reasons to say it are real and common: predictable cost, a trust ramp
// (watch the deterministic engine for a month before letting a model open PRs against your repo), or
// a policy position on sending source to a third-party model. Forcing all-or-nothing loses the
// customer who would have said yes in six weeks.
//
// It also makes the pricing honest. A deterministic tier we cannot actually deliver — because the
// switch does not exist — is not a tier, it is a line on a page.
//
// SPEND IS SHOWN, NOT JUST CAPPED. l2.Budget already bounds a single run. What a customer needs is
// the monthly number: what have the agents cost me, against what I expected. A cost you cannot see is
// a cost you assume the worst about.

// aiModeResponse is the settings view: what is on, why, and what it has cost.
type aiModeResponse struct {
	Mode      string `json:"mode"`
	Engineer  bool   `json:"engineer"`
	Pentester bool   `json:"pentester"`
	// Reason explains the current state in the customer's terms — including WHY something is off, so a
	// disabled surface reads as a choice rather than a broken feature.
	Reason string `json:"reason"`
	// Choices are the modes this tenant may select, each with what it does and what it costs.
	Choices []aiChoice `json:"choices"`
	// SpendUSD is what the agents have cost this calendar month. Zero is a real answer.
	SpendUSD float64 `json:"spend_usd"`
	// Runs is how many agent runs are behind that number, so the figure is checkable.
	Runs int `json:"runs"`
	// UsingOwnKey reports whether the spend lands on the customer's LLM bill rather than ours — which
	// changes what the number means to them entirely.
	UsingOwnKey bool `json:"using_own_key"`
	// BudgetUSD is the tenant's hard monthly ceiling (0 = none), and RemainingUSD is what is left.
	// Showing the remainder rather than only the spend is the difference between a number someone reads
	// and a number someone can plan against.
	BudgetUSD    float64 `json:"budget_usd"`
	RemainingUSD float64 `json:"remaining_usd"`
}

type aiChoice struct {
	Mode      string `json:"mode"`
	Label     string `json:"label"`
	Detail    string `json:"detail"`
	Cost      string `json:"cost"`
	Available bool   `json:"available"`
	// Why explains an unavailable choice rather than just greying it out.
	Why string `json:"why,omitempty"`
}

// handleGetAIMode returns the tenant's AI mode, what each option means, and this month's spend.
func (d Deps) handleGetAIMode(w http.ResponseWriter, r *http.Request, tenantID string) {
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	perms := d.aiAllowed(r.Context(), tenantID)
	lim := platform.Entitlements(t.Plan)
	ownKey := t.LLM.Usable()
	canAI := lim.AIEnabled || ownKey

	spend, runs := d.monthlyAISpend(r.Context(), tenantID)

	writeJSON(w, http.StatusOK, aiModeResponse{
		Mode: string(perms.Mode), Engineer: perms.Engineer, Pentester: perms.Pentester,
		Reason: perms.Reason, SpendUSD: spend, Runs: runs, UsingOwnKey: ownKey,
		BudgetUSD: t.MonthlyAIBudgetUSD, RemainingUSD: remainingBudget(t.MonthlyAIBudgetUSD, spend),
		Choices: []aiChoice{
			{
				Mode: string(platform.AIModeDeterministic), Label: "Deterministic only",
				Detail:    "30+ scanners, cross-surface correlation, threat intel, compliance mapping and plain-English findings. No model is called.",
				Cost:      "No token cost",
				Available: true,
			},
			{
				Mode: string(platform.AIModeEngineer), Label: "+ AI Security Engineer",
				Detail:    "Triages what matters, explains the chain, and proposes fixes for you to approve. It never applies anything on its own.",
				Cost:      costLabel(ownKey),
				Available: canAI,
				Why:       unavailableWhy(canAI, true),
			},
			{
				Mode: string(platform.AIModeFull), Label: "+ AI Pentester",
				Detail:    "Also attempts real exploitation to prove which findings are genuinely exploitable, and re-tests after a fix.",
				Cost:      costLabel(ownKey),
				Available: canAI && (lim.AutonomousPentest || ownKey),
				Why:       unavailableWhy(canAI, lim.AutonomousPentest || ownKey),
			},
		},
	})
}

func costLabel(ownKey bool) string {
	if ownKey {
		return "Billed to your own LLM key"
	}
	return "Included in your plan's monthly budget"
}

func unavailableWhy(canAI, extra bool) string {
	switch {
	case !canAI:
		return "Needs an AI-enabled plan, or add your own LLM key in Settings to turn it on immediately."
	case !extra:
		return "Needs the pentest add-on on your plan, or your own LLM key."
	}
	return ""
}

// handleSetAIMode records the tenant's choice.
//
// The mode is validated strictly: an unrecognised value is REFUSED rather than normalised to a
// default, because silently resolving a typo to a different tier than the customer selected is the
// kind of quiet wrongness that costs money or leaks work they meant to withhold.
func (d Deps) handleSetAIMode(w http.ResponseWriter, r *http.Request, tenantID string) {
	raw, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<16))
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid request"))
		return
	}
	var req struct {
		Mode string `json:"mode"`
		// MonthlyBudgetUSD is optional. A nil pointer leaves the existing ceiling alone — so a client
		// changing only the mode cannot silently clear a budget the customer set.
		MonthlyBudgetUSD *float64 `json:"monthly_budget_usd,omitempty"`
	}
	if err := json.Unmarshal(raw, &req); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid body: "+err.Error()))
		return
	}
	if !platform.ValidAIMode(req.Mode) {
		writeJSON(w, http.StatusBadRequest, errBody(
			"unknown mode "+req.Mode+" (want deterministic, engineer, or full)"))
		return
	}
	t, err := d.Store.GetTenant(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if req.MonthlyBudgetUSD != nil {
		if *req.MonthlyBudgetUSD < 0 {
			writeJSON(w, http.StatusBadRequest, errBody("monthly_budget_usd cannot be negative"))
			return
		}
		t.MonthlyAIBudgetUSD = *req.MonthlyBudgetUSD
	}
	t.AIMode = platform.NormalizeAIMode(req.Mode)
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		respond(w, nil, err)
		return
	}
	if d.Recorder != nil {
		// Ledger-recorded like the kill-switch: turning the agents on or off is a governance decision,
		// and "who allowed the model to touch our repo, and when" must be answerable later.
		d.Recorder.Record("ai mode set", "governance",
			map[string]any{"tenant_id": tenantID, "mode": string(t.AIMode)}, "customer AI-mode preference")
	}
	d.handleGetAIMode(w, r, tenantID)
}

// monthlyAISpend totals what the agents cost this calendar month, from the persisted analyses that
// recorded a real cost. Grounded: it sums observed run costs rather than estimating from token
// prices, so the number matches what actually happened — and reads 0 when nothing has run.
func (d Deps) monthlyAISpend(ctx context.Context, tenantID string) (float64, int) {
	all, err := d.Store.ListAIAnalyses(ctx, tenantID)
	if err != nil {
		return 0, 0
	}
	now := time.Now().UTC()
	var total float64
	runs := 0
	for _, a := range all {
		if a.CreatedAt.Year() != now.Year() || a.CreatedAt.Month() != now.Month() {
			continue
		}
		if a.CostUSD > 0 {
			total += a.CostUSD
		}
		runs++
	}
	return total, runs
}

// remainingBudget is what is left of the month's ceiling. Never negative: an overshoot reads as zero
// remaining rather than a negative number, which tells the reader nothing useful and looks like a bug.
func remainingBudget(budget, spent float64) float64 {
	if budget <= 0 {
		return 0
	}
	if spent >= budget {
		return 0
	}
	return budget - spent
}
