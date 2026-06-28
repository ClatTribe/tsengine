package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestL2Translate_GatesAndRuns(t *testing.T) {
	st := store.NewMemory()

	// Gating: no LeadClient (and no env) → 400, never a fabricated report.
	d0 := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}
	if rec := do(NewHandler(d0), "POST", "/v1/l2/translate", "t1", "{}"); rec.Code != 400 {
		t.Fatalf("no tool-calling LLM → 400, got %d: %s", rec.Code, rec.Body.String())
	}

	// Economic gate: a Free tenant without its own key must NOT spend the operator LLM → 400 even
	// with an operator LeadClient configured.
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "free", Plan: platform.PlanFree})
	dFree := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", LeadClient: &l2.MockClient{}}
	if rec := do(NewHandler(dFree), "POST", "/v1/l2/translate", "free", "{}"); rec.Code != 400 {
		t.Fatalf("Free tenant must not use the operator LLM → 400, got %d", rec.Code)
	}

	// Happy path: an AI-entitled (Growth) tenant + a mock tool-calling client + a finding → 200.
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Plan: platform.PlanGrowth})
	_ = st.PutFinding(context.Background(), "t1", types.Finding{
		ID: "f-1", RuleID: "nuclei::sqli", Tool: "nuclei", Severity: types.SeverityHigh,
		Endpoint: "https://x/s?q=", Title: "SQL injection in q",
	})
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", LeadClient: &l2.MockClient{}}
	if rec := do(NewHandler(d), "POST", "/v1/l2/translate", "t1", "{}"); rec.Code != 200 {
		t.Fatalf("translate should be 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// An AI-entitled tenant gets the operator-global client.
	if got := d.resolveLeadClient(context.Background(), "t1"); got == nil {
		t.Error("AI-entitled tenant should get the operator-global LeadClient")
	}
}

func TestL2Translate_NoFindingsIsOK(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Plan: platform.PlanGrowth}) // AI-entitled
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", LeadClient: &l2.MockClient{}}
	if rec := do(NewHandler(d), "POST", "/v1/l2/translate", "t1", "{}"); rec.Code != 200 {
		t.Fatalf("no findings → 200 (nothing to translate), got %d", rec.Code)
	}
}
