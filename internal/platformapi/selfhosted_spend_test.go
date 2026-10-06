package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// A tenant whose default model is self-hosted, with a per-role override on a paid cloud model.
func selfHostedTenantDeps(t *testing.T, budget float64) (Deps, store.Store) {
	t.Helper()
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{
		ID: "t1", Plan: platform.PlanGrowth, MonthlyAIBudgetUSD: budget,
		LLM: &platform.LLMConfig{Provider: "ollama", Model: "qwen3:8b", BaseURL: "http://gpu-box:11434/v1"},
		LLMRoles: map[platform.AgentRole]*platform.LLMConfig{
			platform.RoleCode: {Provider: "openai", Model: "gpt-5.5", KeyRef: "sealed"},
		},
	})
	return Deps{Store: st}, st
}

func TestSpend_SelfHostedRunIsFreeAndKnown(t *testing.T) {
	d, st := selfHostedTenantDeps(t, 0)
	ctx := context.Background()
	d.recordAISpend(ctx, "t1", "triage", "estate", 0.27, true, "qwen3:8b", 0) // priced at the default rate by a meter
	d.recordAISpend(ctx, "t1", "code", "code", 1.50, true, "gpt-5.5", 0)      // the paid role override
	d.recordAISpend(ctx, "t1", "triage", "estate", 0.40, true, "", 0)         // no model named
	rows, _ := st.ListAISpend(ctx, "t1")
	if len(rows) != 3 {
		t.Fatalf("want 3 rows, got %d", len(rows))
	}
	for _, e := range rows {
		switch e.Model {
		case "qwen3:8b":
			if e.USD != 0 || !e.CostKnown || !e.SelfHosted {
				t.Errorf("a self-hosted run must be $0 with the cost KNOWN: %+v", e)
			}
		case "gpt-5.5":
			if e.USD != 1.50 || e.SelfHosted {
				t.Errorf("a cloud model must stay priced even for a self-hosting tenant: %+v", e)
			}
		case "":
			if e.SelfHosted || e.USD != 0.40 {
				t.Errorf("a row naming no model is never assumed free: %+v", e)
			}
		}
	}
}

// Rows written at the default frontier rate before this rule existed must stop charging the budget now,
// not at the next month boundary — including the legacy AIAnalysis cost the budget still reads.
func TestBudget_IgnoresPhantomSelfHostedSpendRecordedEarlier(t *testing.T) {
	d, st := selfHostedTenantDeps(t, 1.00)
	ctx := context.Background()
	now := time.Now().UTC()
	_ = st.PutAISpend(ctx, platform.AISpend{ID: "old1", TenantID: "t1", At: now, Kind: "triage", Surface: "estate",
		USD: 4.00, CostKnown: true, Model: "qwen3:8b"}) // written before the rule: unflagged, priced
	_ = st.PutAIAnalysis(ctx, platform.AIAnalysis{ID: "triage:estate", TenantID: "t1", Kind: "triage", Scope: "estate",
		Model: "qwen3:8b", CostUSD: 6.00, CreatedAt: now})
	spent, _ := d.monthlyAISpend(ctx, "t1")
	if spent != 0 {
		t.Fatalf("self-hosted spend must not count toward the budget, got $%.2f", spent)
	}
	if !d.aiAllowed(ctx, "t1").Engineer {
		t.Fatal("a $1 budget must not be 'used up' by a model that costs nothing")
	}
	// And a real cloud spend still counts.
	_ = st.PutAISpend(ctx, platform.AISpend{ID: "c1", TenantID: "t1", At: now, Kind: "code", Surface: "code",
		USD: 2.00, CostKnown: true, Model: "gpt-5.5"})
	if spent, _ := d.monthlyAISpend(ctx, "t1"); spent != 2.00 {
		t.Fatalf("cloud spend must still count: $%.2f", spent)
	}
}

func TestAIValue_CountsSelfHostedRunsAtZero(t *testing.T) {
	d, st := selfHostedTenantDeps(t, 0)
	ctx := context.Background()
	_ = st.PutAISpend(ctx, platform.AISpend{ID: "a", TenantID: "t1", At: time.Now().UTC(), Kind: "triage", Surface: "estate",
		USD: 3.00, CostKnown: true, Model: "qwen3:8b"})
	rec := httptest.NewRecorder()
	d.handleAIValue(rec, httptest.NewRequest(http.MethodGet, "/v1/ai/value", nil), "t1")
	var v aiValueView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Total.USD != 0 || v.Total.SelfHosted != 1 || v.Total.UnknownCostRuns != 0 {
		t.Fatalf("self-hosted run must read $0, counted as self-hosted, not unpriced: %+v", v.Total)
	}
}
