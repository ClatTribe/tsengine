package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

type fakeLeadClient struct{}

func (fakeLeadClient) Generate(context.Context, string, []l2.Message, []l2.ToolSchema) (l2.Response, error) {
	return l2.Response{}, nil
}
func (fakeLeadClient) Model() string      { return "fake" }
func (fakeLeadClient) ContextWindow() int { return 8000 }

// TestAutoReview_SeedsVCISORisks proves the Task-2 fix: a routine scan→auto-review now clusters the
// tenant's high+ findings into candidate risks on the vCISO desk (agent proposes → human disposes, §18.4),
// the SAME step the on-demand cloud investigation does. Before this, high+ findings from a normal scan
// never reached the vCISO desk unless a human manually POSTed /v1/risks/seed.
func TestAutoReview_SeedsVCISORisks(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	seedCodeToCloudEstate(t, st, "t1") // AI-entitled tenant + two high findings that cluster into a risk
	d := Deps{Store: st, LeadClient: fakeLeadClient{}}

	// Precondition: no risks yet.
	if r, _ := st.ListRisks(ctx, "t1"); len(r) != 0 {
		t.Fatalf("precondition: expected no seeded risks, got %d", len(r))
	}

	findings, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	d.AutoReviewAfterScan(ctx, "t1", findings, 1)

	risks, err := st.ListRisks(ctx, "t1")
	if err != nil {
		t.Fatalf("list risks: %v", err)
	}
	if len(risks) == 0 {
		t.Fatal("the auto-review must seed at least one candidate risk from the high+ findings")
	}
	for _, rk := range risks {
		if !rk.Proposed || rk.DecidedBy != "" {
			t.Errorf("a seeded risk must be a PROPOSAL awaiting a human decision, got %+v", rk)
		}
	}
}

// recordingLeadClient flags whether the L2 loop was driven (so a test can assert the auto-review DID or
// did NOT spend the model). Returns a finishing response so the agent loop terminates immediately.
type recordingLeadClient struct{ called *bool }

func (c recordingLeadClient) Generate(context.Context, string, []l2.Message, []l2.ToolSchema) (l2.Response, error) {
	*c.called = true
	return l2.Response{}, nil
}
func (recordingLeadClient) Model() string      { return "rec" }
func (recordingLeadClient) ContextWindow() int { return 8000 }

// TestAutoReview_ContinuousBounded: the continuous auto-review fires on a tenant's FIRST review (no prior
// analysis) even with no new incident — so a newly-connected SMB gets an initial analysis automatically —
// and SKIPS a static re-scan (prior analysis + no new incident) so it doesn't re-spend the LLM every pass.
func TestAutoReview_ContinuousBounded(t *testing.T) {
	ctx := context.Background()
	findings := []types.Finding{{ID: "f1", Severity: types.SeverityHigh, Title: "SQLi"}}

	fire := func(seedPrior bool, opened int) bool {
		st := store.NewMemory()
		_ = st.PutTenant(ctx, platform.Tenant{ID: "t", Plan: platform.PlanEnterprise})
		if seedPrior {
			_ = st.PutAIAnalysis(ctx, platform.AIAnalysis{ID: "triage:", TenantID: "t", Kind: "triage", Summary: "prior"})
		}
		called := false
		d := Deps{Store: st, LeadClient: recordingLeadClient{called: &called}}
		d.AutoReviewAfterScan(ctx, "t", findings, opened)
		return called
	}

	if !fire(false, 0) {
		t.Error("first review (no prior analysis) must fire even with 0 new incidents")
	}
	if fire(true, 0) {
		t.Error("a static estate (prior review + 0 new incidents) must NOT re-spend the LLM")
	}
	if !fire(true, 1) {
		t.Error("a new incident must trigger a re-review even when a prior analysis exists")
	}
}

// TestDevLLMAllPlans_Override: the DEV-only flag lets a Free tenant use the operator LLM (so `make dev` +
// the proxy powers any test tenant), while OFF (the default) the economic gate still blocks Free.
func TestDevLLMAllPlans_Override(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "free", Plan: platform.PlanFree})
	d := Deps{Store: st, LeadClient: fakeLeadClient{}}

	// default (flag unset): Free tenant is gated off the operator LLM.
	if d.resolveLeadClient(ctx, "free") != nil {
		t.Error("without the dev flag, a Free tenant must NOT use the operator LLM")
	}
	// dev flag on: Free tenant may use the operator LLM (dev/proxy convenience).
	t.Setenv("TSENGINE_DEV_LLM_ALL_PLANS", "1")
	if d.resolveLeadClient(ctx, "free") == nil {
		t.Error("with TSENGINE_DEV_LLM_ALL_PLANS=1, a Free tenant should use the operator LLM (dev proxy)")
	}
}

// TestResolveLeadClient_EconomicGate locks the invariant that the post-scan AI auto-review never spends
// the OPERATOR's LLM budget for a non-AI-entitled tenant — only an AI-entitled plan (or a tenant's own
// key) may drive it. This is the economic gate that keeps the Free tier free to run.
func TestResolveLeadClient_EconomicGate(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "free", Plan: platform.PlanFree})
	_ = st.PutTenant(ctx, platform.Tenant{ID: "paid", Plan: platform.PlanEnterprise})

	// No operator client configured at all → nil for everyone (nothing to spend).
	if (Deps{Store: st}).resolveLeadClient(ctx, "paid") != nil {
		t.Error("no LeadClient + no own key → must be nil")
	}

	d := Deps{Store: st, LeadClient: fakeLeadClient{}}
	// Free tenant without its own key MUST NOT use the operator LLM (the economic invariant).
	if d.resolveLeadClient(ctx, "free") != nil {
		t.Error("Free tenant must NOT auto-spend the operator LLM budget")
	}
	// An AI-entitled (Growth) tenant may use the operator LLM for auto-review.
	if d.resolveLeadClient(ctx, "paid") == nil {
		t.Error("AI-entitled tenant should use the operator LLM for auto-review")
	}
}
