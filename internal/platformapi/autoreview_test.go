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

// TestAutoReviewClient_EconomicGate locks the invariant that the post-scan AI auto-review never spends
// the OPERATOR's LLM budget for a non-AI-entitled tenant — only an AI-entitled plan (or a tenant's own
// key) may drive it. This is the economic gate that keeps the Free tier free to run.
func TestAutoReviewClient_EconomicGate(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "free", Plan: platform.PlanFree})
	_ = st.PutTenant(ctx, platform.Tenant{ID: "paid", Plan: platform.PlanGrowth})

	// No operator client configured at all → nil for everyone (nothing to spend).
	if (Deps{Store: st}).autoReviewClient(ctx, "paid") != nil {
		t.Error("no LeadClient + no own key → must be nil")
	}

	d := Deps{Store: st, LeadClient: fakeLeadClient{}}
	// Free tenant without its own key MUST NOT use the operator LLM (the economic invariant).
	if d.autoReviewClient(ctx, "free") != nil {
		t.Error("Free tenant must NOT auto-spend the operator LLM budget")
	}
	// An AI-entitled (Growth) tenant may use the operator LLM for auto-review.
	if d.autoReviewClient(ctx, "paid") == nil {
		t.Error("AI-entitled tenant should use the operator LLM for auto-review")
	}
}
