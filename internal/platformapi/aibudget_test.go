package platformapi

import (
	"context"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// spendThisMonth records a persisted analysis carrying a real cost, so the budget check has something
// to count.
func spendThisMonth(t *testing.T, d Deps, tid string, usd float64) {
	t.Helper()
	if err := d.Store.PutAIAnalysis(context.Background(), platform.AIAnalysis{
		ID: "a-" + tid, TenantID: tid, Kind: "triage", Title: "x",
		CostUSD: usd, CreatedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatal(err)
	}
}

func setBudget(t *testing.T, d Deps, tid string, usd float64) {
	t.Helper()
	ctx := context.Background()
	tn, _ := d.Store.GetTenant(ctx, tid)
	tn.MonthlyAIBudgetUSD = usd
	if err := d.Store.PutTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
}

// ── THE CEILING ──────────────────────────────────────────────────────────────────────────────────

// An exhausted budget STOPS the agents. Unpredictable spend is a real reason people decline to switch
// AI on at all, so the ceiling has to actually hold.
func TestBudget_ExhaustedStopsTheAgents(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, nil)
	setBudget(t, d, tid, 10)
	spendThisMonth(t, d, tid, 12) // over

	if d.resolveLeadClient(context.Background(), tid) != nil {
		t.Error("the agents kept running past the monthly ceiling")
	}
	if d.aiAllowed(context.Background(), tid).Engineer {
		t.Error("permissions still report the engineer as available past the ceiling")
	}
}

// THE HONESTY REQUIREMENT. "The budget ran out" and "the agent found nothing" must never look the same
// to a customer — otherwise an unexamined estate reads as a clean one.
func TestBudget_ExhaustedSaysSoInTheCustomersTerms(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, nil)
	setBudget(t, d, tid, 10)
	spendThisMonth(t, d, tid, 12)

	reason := strings.ToLower(d.aiAllowed(context.Background(), tid).Reason)
	if !strings.Contains(reason, "budget") {
		t.Errorf("an exhausted budget did not say so: %q", reason)
	}
	if !strings.Contains(reason, "deterministic scanning continues") {
		t.Errorf("the reason does not say what IS still running, so it reads as a total outage: %q", reason)
	}
	if !strings.Contains(reason, "raise the budget") {
		t.Errorf("the reason does not say how to resume: %q", reason)
	}
}

// Under budget → unaffected. A ceiling that throttles early is a ceiling nobody sets.
func TestBudget_UnderBudgetIsUnaffected(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, nil)
	setBudget(t, d, tid, 100)
	spendThisMonth(t, d, tid, 12)

	if !d.aiAllowed(context.Background(), tid).Engineer {
		t.Error("a tenant well under budget lost the engineer")
	}
}

// No budget set → no ceiling. Existing tenants must be unaffected by this landing.
func TestBudget_ZeroMeansNoCeiling(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, nil)
	spendThisMonth(t, d, tid, 9999)

	if !d.aiAllowed(context.Background(), tid).Engineer {
		t.Error("a tenant with NO budget set was throttled — the feature is not additive")
	}
}

// The budget reason must be distinguishable from the entitlement reason. A tenant who is entitled and
// opted in but out of budget being told "AI is not enabled" would send them to the wrong fix.
func TestBudget_ReasonIsNotConfusedWithEntitlement(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, nil)
	setBudget(t, d, tid, 10)
	spendThisMonth(t, d, tid, 12)
	budgetReason := d.aiAllowed(context.Background(), tid).Reason

	// A Free tenant with no key: not entitled at all — a different cause, a different message.
	d2, tid2, _ := httpEngineerDeps(t, nil)
	tn, _ := d2.Store.GetTenant(context.Background(), tid2)
	tn.Plan = platform.PlanFree
	_ = d2.Store.PutTenant(context.Background(), tn)
	entitlementReason := d2.aiAllowed(context.Background(), tid2).Reason

	if budgetReason == entitlementReason {
		t.Error("the budget and entitlement causes produce the same message — the customer cannot tell which fix applies")
	}
}

// ── THE ENDPOINT ─────────────────────────────────────────────────────────────────────────────────

func TestBudget_EndpointReportsCapAndRemaining(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, []l2.Response{})
	d.Token = "platform-tok"
	setBudget(t, d, tid, 50)
	spendThisMonth(t, d, tid, 20)

	rec := do(NewHandler(d), "GET", "/v1/settings/ai-mode", tid, "")
	if rec.Code != 200 {
		t.Fatalf("GET = %d: %s", rec.Code, rec.Body.String())
	}
	var got aiModeResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.BudgetUSD != 50 {
		t.Errorf("budget = %v, want 50", got.BudgetUSD)
	}
	if got.RemainingUSD != 30 {
		t.Errorf("remaining = %v, want 30 — the remainder is what someone plans against", got.RemainingUSD)
	}
}

// Changing only the mode must NOT clear a budget the customer set. That is the kind of silent side
// effect that shows up later as an unexpected bill.
func TestBudget_ModeChangeDoesNotClearTheBudget(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, nil)
	d.Token = "platform-tok"
	setBudget(t, d, tid, 50)

	if rec := do(NewHandler(d), "PUT", "/v1/settings/ai-mode", tid, `{"mode":"engineer"}`); rec.Code != 200 {
		t.Fatalf("PUT = %d: %s", rec.Code, rec.Body.String())
	}
	tn, _ := d.Store.GetTenant(context.Background(), tid)
	if tn.MonthlyAIBudgetUSD != 50 {
		t.Errorf("a mode-only change reset the budget to %v", tn.MonthlyAIBudgetUSD)
	}
}

func TestBudget_RejectsNegative(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, nil)
	d.Token = "platform-tok"
	if rec := do(NewHandler(d), "PUT", "/v1/settings/ai-mode", tid, `{"mode":"engineer","monthly_budget_usd":-5}`); rec.Code != 400 {
		t.Errorf("a negative budget got %d, want 400", rec.Code)
	}
}

func TestRemainingBudget_NeverNegative(t *testing.T) {
	if got := remainingBudget(10, 25); got != 0 {
		t.Errorf("overspend produced %v; a negative remainder tells the reader nothing and looks like a bug", got)
	}
	if got := remainingBudget(0, 25); got != 0 {
		t.Errorf("no budget produced %v", got)
	}
	if got := remainingBudget(50, 20); got != 30 {
		t.Errorf("remaining = %v, want 30", got)
	}
}

// ── THE MONTHLY CEILING HAS TO BE A CAP, NOT A DOORMAN ───────────────────────────────────────────

// aiAllowed refuses to START a run once the month is spent. That is a pre-flight check: a tenant with
// a few cents left passed it and then got a run allowed the full per-run cap, finishing over the
// ceiling — while Tenant.MonthlyAIBudgetUSD is documented as "a hard ceiling" and Settings tells them
// the agents pause when it is reached. Clamping the run to the remainder is what makes those true.
func TestRemainingAIBudget_IsWhatARunMayStillSpend(t *testing.T) {
	d, tid, _ := httpEngineerDeps(t, nil)
	ctx := context.Background()

	// No ceiling → 0, meaning "do not clamp" rather than "nothing left".
	if got := d.remainingAIBudget(ctx, tid); got != 0 {
		t.Errorf("with no ceiling set, remaining = %v, want 0 (unbounded)", got)
	}

	tn, _ := d.Store.GetTenant(ctx, tid)
	tn.MonthlyAIBudgetUSD = 5
	if err := d.Store.PutTenant(ctx, tn); err != nil {
		t.Fatal(err)
	}
	// Nothing spent yet → the whole ceiling is available.
	if got := d.remainingAIBudget(ctx, tid); got != 5 {
		t.Errorf("remaining = %v, want 5", got)
	}
}

// The clamp only ever LOWERS the per-run cap. A large remaining allowance must not raise it above the
// per-run default, or the monthly ceiling would become a licence to spend it all in one run.
func TestClamp_OnlyLowersThePerRunCap(t *testing.T) {
	def := 1.00 // l2.DefaultBudget().MaxCostUSD
	for _, tc := range []struct{ remaining, want float64 }{
		{remaining: 0, want: def},     // no ceiling → untouched
		{remaining: 10, want: def},    // plenty left → untouched
		{remaining: 0.25, want: 0.25}, // nearly out → clamped down
	} {
		got := clampToRemaining(def, tc.remaining)
		if got != tc.want {
			t.Errorf("remaining %v → cap %v, want %v", tc.remaining, got, tc.want)
		}
	}
}
