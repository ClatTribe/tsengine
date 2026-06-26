package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/l2"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestL2Translate_GatesAndRuns(t *testing.T) {
	st := store.NewMemory()

	// Gating: no LeadClient (and no env) → 400, never a fabricated report.
	d0 := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}
	if rec := do(NewHandler(d0), "POST", "/v1/l2/translate", "t1", "{}"); rec.Code != 400 {
		t.Fatalf("no tool-calling LLM → 400, got %d: %s", rec.Code, rec.Body.String())
	}

	// Happy path: a mock tool-calling client + a finding → the Lead runs → 200.
	_ = st.PutFinding(context.Background(), "t1", types.Finding{
		ID: "f-1", RuleID: "nuclei::sqli", Tool: "nuclei", Severity: types.SeverityHigh,
		Endpoint: "https://x/s?q=", Title: "SQL injection in q",
	})
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", LeadClient: &l2.MockClient{}}
	if rec := do(NewHandler(d), "POST", "/v1/l2/translate", "t1", "{}"); rec.Code != 200 {
		t.Fatalf("translate should be 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// resolveLeadClient falls back to the operator-global client when no per-tenant config is set.
	if got := d.resolveLeadClient(context.Background(), "t1"); got == nil {
		t.Error("resolveLeadClient should fall back to the operator-global LeadClient")
	}
}

func TestL2Translate_NoFindingsIsOK(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", LeadClient: &l2.MockClient{}}
	if rec := do(NewHandler(d), "POST", "/v1/l2/translate", "t1", "{}"); rec.Code != 200 {
		t.Fatalf("no findings → 200 (nothing to translate), got %d", rec.Code)
	}
}
