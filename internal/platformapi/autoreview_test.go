package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
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
