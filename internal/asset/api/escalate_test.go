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

// TestPlanEscalation_EmptySurfaceTriggersRouteDiscovery pins the gap OWASP crAPI exposed.
//
// kiterunner's job is finding routes, and it fired only when a spec had ALREADY been ingested — so
// an API with no discoverable spec got no route discovery, and therefore no surface, and therefore
// almost no scan. Measured: crAPI (no spec at /openapi.json, /swagger.json, /api-docs, /v3/api-docs)
// produced ONE finding, where VAmPI (publishes /openapi.json) produced 11-12 and detected SQLi.
//
// Most real APIs look like crAPI. The self-authored VAmPI fixture hid this because it happened to
// pick a spec-publishing target.
func TestPlanEscalation_EmptySurfaceTriggersRouteDiscovery(t *testing.T) {
	h := NewHandler()
	target := types.Asset{Type: types.AssetAPI, Target: "https://api.x"}
	// Recon found nothing callable — only the bare target itself.
	out := h.PlanEscalation(target, []string{"https://api.x"}, nil)

	var kite int
	for _, d := range out {
		if d.Tool.Name() == "kiterunner" {
			kite++
		}
	}
	if kite != 1 {
		t.Fatalf("an empty surface must trigger route discovery, got %d kiterunner dispatches.\n"+
			"Without it an API with no published spec is never scanned at all.", kite)
	}
}

// The escalation invariant (§5.3) still holds: this is gated on a SPECIFIC state, not fired blanket.
// An API whose operations were discovered some other way already has a surface and must not pay for
// brute-forcing.
func TestPlanEscalation_KnownOperationsSkipRouteDiscovery(t *testing.T) {
	h := NewHandler()
	target := types.Asset{Type: types.AssetAPI, Target: "https://api.x"}
	out := h.PlanEscalation(target, []string{"GET https://api.x/users", "POST https://api.x/orders"}, nil)
	for _, d := range out {
		if d.Tool.Name() == "kiterunner" {
			t.Error("routes are already known — brute-forcing them is the blanket firing §5.3 forbids")
		}
	}
}
