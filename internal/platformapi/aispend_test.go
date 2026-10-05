package platformapi

import (
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// THE BUDGET BUG: two whole-estate reviews in a month, plus one that returned nothing, must all count.
// AIAnalysis (one row per kind:scope, and none at all for an empty run) counted only the last.
func TestMonthlySpend_CountsEveryRun(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	d := Deps{Store: st}
	now := time.Now().UTC()
	full := l2.Outcome{CostUSD: 0.40, Tokens: 1000, Model: "m", Summary: &l2.FinalReport{ExecutiveSummary: "ok"}}
	empty := l2.Outcome{CostUSD: 0.25, Tokens: 500, Model: "m"} // paid for, produced nothing
	d.persistAIAnalysis(ctx, "t1", "triage", "", "t", full, now)
	d.persistAIAnalysis(ctx, "t1", "triage", "", "t", full, now)
	d.persistAIAnalysis(ctx, "t1", "triage", "", "t", empty, now)
	spent, runs := d.monthlyAISpend(ctx, "t1")
	if runs != 3 || spent < 1.04 || spent > 1.06 {
		t.Fatalf("every run must count toward the budget: spent=%.2f runs=%d, want 1.05 over 3", spent, runs)
	}
}

// The deploy month: spend recorded only in the old place must not be forgotten (that would reset a
// nearly-spent budget mid-month).
func TestMonthlySpend_TransitionNeverResets(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutAIAnalysis(ctx, platform.AIAnalysis{ID: "triage:", TenantID: "t1", Kind: "triage", CostUSD: 4.5, CreatedAt: time.Now().UTC()})
	if spent, _ := (Deps{Store: st}).monthlyAISpend(ctx, "t1"); spent != 4.5 {
		t.Fatalf("legacy spend this month must still count: %.2f", spent)
	}
}

// Unknown is not free; proven is not claimed; a fix proven closed is context, not credit.
func TestAIValue_HonestPerSurface(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := Deps{Store: st}
	now := time.Now().UTC()
	for _, e := range []platform.AISpend{
		{ID: "a", TenantID: "t1", At: now, Surface: "cloud", USD: 2, CostKnown: true, Verified: 4},
		{ID: "b", TenantID: "t1", At: now, Surface: "code", USD: 1, CostKnown: true, Verified: 0},
		{ID: "c", TenantID: "t1", At: now, Surface: "code", CostKnown: false, Verified: 1},
		{ID: "old", TenantID: "t1", At: now.AddDate(0, -2, 0), Surface: "cloud", USD: 99, CostKnown: true},
	} {
		_ = st.PutAISpend(ctx, e)
	}
	_ = st.PutAction(ctx, platform.Action{ID: "x", TenantID: "t1", Verification: &platform.FixVerification{Status: platform.FixStatusFixed, VerifiedAt: now}})
	rec := httptest.NewRecorder()
	d.handleAIValue(rec, httptest.NewRequest("GET", "/v1/ai-value", nil), "t1")
	var v aiValueView
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	by := map[string]surfaceValue{}
	for _, s := range v.Surfaces {
		by[s.Surface] = s
	}
	if c := by["cloud"]; c.USD != 2 || c.Verified != 4 || c.CostPerVerified == nil || *c.CostPerVerified != 0.5 {
		t.Errorf("cloud: %+v", c)
	}
	if c := by["code"]; c.UnknownCostRuns != 1 || c.CostPerVerified != nil {
		t.Errorf("a surface with an unknown-cost run must withhold cost-per-proof: %+v", c)
	}
	if v.Total.Runs != 3 || v.Total.USD != 3 {
		t.Errorf("total must cover the window only: %+v", v.Total)
	}
	if v.FixesProvenClosed != 1 || len(v.Unmetered) == 0 {
		t.Errorf("fixes proven closed shown as context, unmetered paths named: %+v", v)
	}
}

type meteredLLM struct{ u cloudengine.Usage }

func (m *meteredLLM) TotalUsage() cloudengine.Usage { return m.u }
func (m *meteredLLM) ModelName() string             { return "claude-sonnet-5-5" }

// A specialist run is priced from the usage it added, not the client's lifetime total; a client that
// reports no usage leaves the cost UNKNOWN.
func TestUsageMeter_PricesTheRunsOwnUsage(t *testing.T) {
	m := &meteredLLM{u: cloudengine.Usage{InputTokens: 1_000_000}}
	meter, model := usageMeter(m)
	m.u.InputTokens += 1_000_000
	cost, known := meter()
	want := cloudengine.EstimateCost(model, cloudengine.Usage{InputTokens: 1_000_000})
	if !known || cost != want {
		t.Errorf("cost=%v known=%v, want %v", cost, known, want)
	}
	if _, known := func() (float64, bool) { f, _ := usageMeter(struct{}{}); return f() }(); known {
		t.Error("a client without usage reporting must be UNKNOWN cost, never zero")
	}
	_ = types.VerificationVerified
}

// A client that reports usage but added none this run (cached, aborted before a call) is UNKNOWN cost.
func TestUsageMeter_NoNewUsageIsUnknown(t *testing.T) {
	m := &meteredLLM{u: cloudengine.Usage{InputTokens: 500}}
	meter, _ := usageMeter(m)
	if _, known := meter(); known {
		t.Error("a run that added no usage must not be priced at $0")
	}
}

// Runs recorded back to back must each be kept: a clock-derived id collides inside one tick and the store
// keys by id, so the second would overwrite the first.
func TestRecordAISpend_BackToBackRunsAreAllKept(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	d := Deps{Store: st}
	for i := 0; i < 500; i++ {
		d.recordAISpend(ctx, "t1", "triage", "estate", 0.01, true, "m", 0)
	}
	if rows, _ := st.ListAISpend(ctx, "t1"); len(rows) != 500 {
		t.Fatalf("500 runs recorded back to back, %d kept", len(rows))
	}
}
