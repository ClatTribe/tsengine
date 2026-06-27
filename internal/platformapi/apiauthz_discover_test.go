package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

type scriptedDiscoverLLM string

func (s scriptedDiscoverLLM) Generate(context.Context, string) (string, error) { return string(s), nil }

func TestAuthzDiscover_GatedAndRuns(t *testing.T) {
	st := store.NewMemory()
	_ = st.PutTenant(context.Background(), platform.Tenant{ID: "t1", Plan: platform.PlanGrowth}) // AI is a paid feature
	// No LLM → 400.
	d0 := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}
	if rec := do(NewHandler(d0), "POST", "/v1/apiauthz/discover", "t1", `{"operations":[]}`); rec.Code != 400 {
		t.Fatalf("no LLM → 400, got %d: %s", rec.Code, rec.Body.String())
	}
	// With an LLM returning candidate ops → 200 (the proposer parses the scripted JSON).
	llm := scriptedDiscoverLLM(`[{"method":"GET","url":"https://api.x/orders/2","class":"bola","marker":"m"}]`)
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", AgentLLM: llm}
	rec := do(NewHandler(d), "POST", "/v1/apiauthz/discover", "t1",
		`{"operations":[{"method":"GET","url":"https://api.x/orders/1","class":"bola"}]}`)
	if rec.Code != 200 {
		t.Fatalf("discover should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
}
