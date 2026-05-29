package api

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/inql"
	_ "github.com/ClatTribe/tsengine/internal/tool/kiterunner"
)

func TestPlanEscalation_SpecAndGraphQL(t *testing.T) {
	h := NewHandler()
	target := types.Asset{Type: types.AssetAPI, Target: "https://api.x"}
	surface := []string{
		"SPEC https://api.x/openapi.json",
		"GET https://api.x/users/{id}",
		"POST https://api.x/graphql",
	}
	findings := []types.Finding{
		{RuleID: "openapi_spec_ingest::spec-found", Tool: "openapi_spec_ingest", Endpoint: "https://api.x/openapi.json"},
	}
	out := h.PlanEscalation(target, surface, findings)

	byTool := map[string]string{} // tool → target
	for _, d := range out {
		byTool[d.Tool.Name()] = d.Args["target"].(string)
	}
	if got := byTool["kiterunner"]; got != "https://api.x" {
		t.Errorf("kiterunner should brute the target after a spec is found; got %q", got)
	}
	if got := byTool["inql"]; got != "https://api.x/graphql" {
		t.Errorf("inql should fire on the /graphql endpoint; got %q", got)
	}
}

func TestPlanEscalation_NoSpecNoKiterunner(t *testing.T) {
	h := NewHandler()
	target := types.Asset{Type: types.AssetAPI, Target: "https://api.x"}
	// No spec-found finding, no graphql endpoint → no escalation.
	out := h.PlanEscalation(target, []string{"GET https://api.x/users"}, nil)
	if len(out) != 0 {
		t.Errorf("no signals → no escalation, got %d", len(out))
	}
}
