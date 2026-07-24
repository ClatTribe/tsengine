package api

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/inql"
	_ "github.com/ClatTribe/tsengine/internal/tool/kiterunner"
	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
	_ "github.com/ClatTribe/tsengine/internal/tool/openapi"
	_ "github.com/ClatTribe/tsengine/internal/tool/schemathesis"
)

func TestRegistryTier_ResolvesDigDeeperTools(t *testing.T) {
	// The api registry (on-demand replay tier) exposes kiterunner (shadow routes) + inql (GraphQL
	// introspection). Empty before — the "dig deeper" capability didn't exist for the api asset.
	got := names(NewHandler().Registry())
	want := map[string]bool{"kiterunner": true, "inql": true}
	for _, n := range got {
		delete(want, n)
	}
	if len(want) != 0 {
		t.Errorf("api registry tier missing tools %v; got %v", want, got)
	}
}

func TestHandler_TypeAndAnchors(t *testing.T) {
	h := NewHandler()
	if h.Type() != types.AssetAPI {
		t.Errorf("Type: %q", h.Type())
	}
	if len(h.Anchors()) != 1 || h.Anchors()[0].Name() != "nuclei" {
		t.Errorf("Anchors: got %v, want [nuclei]", names(h.Anchors()))
	}
}

func TestPlanAnchors_AddsNucleiAPITags(t *testing.T) {
	h := NewHandler()
	out := h.PlanAnchors(types.Asset{Type: types.AssetAPI, Target: "https://api.example.com"})
	if len(out) != 1 {
		t.Fatalf("got %d dispatches", len(out))
	}
	if got := out[0].Args["tags"]; got != "api,graphql,jwt,oauth" {
		t.Errorf("tags arg lost: %v", got)
	}
	if got := out[0].Args["target"]; got != "https://api.example.com" {
		t.Errorf("target arg lost: %v", got)
	}
}

func TestFilter_DropsHealthAndSpec(t *testing.T) {
	h := NewHandler()
	mk := func(target string) asset.Dispatch {
		return asset.Dispatch{Tool: &fakeTool{name: "nuclei"}, Args: tool.Args{"target": target}}
	}
	in := []asset.Dispatch{
		mk("https://api.example.com/v1/users"),
		mk("https://api.example.com/healthz"),
		mk("https://api.example.com/metrics"),
		mk("https://api.example.com/swagger.json"),
		mk("https://api.example.com/openapi.json"),
		mk("https://api.example.com/v3/api-docs"),
		mk("https://api.example.com/v1/orders"),
	}
	out := h.Filter(context.Background(), types.Asset{Type: types.AssetAPI}, in)
	if len(out) != 2 {
		t.Errorf("Filter kept %d; want 2 (v1/users + v1/orders)", len(out))
	}
}

func TestRecon_OffersOpenAPI(t *testing.T) {
	if len(NewHandler().Recon()) != 1 {
		t.Fatal("Recon() should offer openapi_spec_ingest when registered")
	}
}

func TestPlanRecon_PassesTarget(t *testing.T) {
	out := NewHandler().PlanRecon(types.Asset{Type: types.AssetAPI, Target: "https://api.x"})
	if len(out) != 1 || out[0].Args["target"] != "https://api.x" {
		t.Fatalf("PlanRecon = %+v", out)
	}
}

// PlanFanout: the SPEC marker → schemathesis; the operation URLs →
// nuclei list mode (deduped).
func TestPlanFanout_SpecFuzzAndSignatureScan(t *testing.T) {
	h := NewHandler()
	surface := []string{
		"SPEC https://api.x/openapi.json",
		"GET https://api.x/users/{id}",
		"POST https://api.x/users",
		"GET https://api.x/users/{id}", // dup endpoint
	}
	out := h.PlanFanout(types.Asset{Type: types.AssetAPI, Target: "https://api.x"}, surface)

	byTool := map[string]int{}
	var specURL, nucleiTargets, nucleiTags string
	for _, d := range out {
		byTool[d.Tool.Name()]++
		switch d.Tool.Name() {
		case "schemathesis":
			specURL, _ = d.Args["spec_url"].(string)
		case "nuclei":
			nucleiTargets, _ = d.Args["targets"].(string)
			nucleiTags, _ = d.Args["tags"].(string)
		}
	}
	if byTool["schemathesis"] != 1 || specURL != "https://api.x/openapi.json" {
		t.Errorf("schemathesis should run once on the resolved spec; got %d url=%q", byTool["schemathesis"], specURL)
	}
	if byTool["nuclei"] != 1 || nucleiTags != "api,graphql,jwt,oauth" {
		t.Errorf("nuclei should run once with api tags; got %d tags=%q", byTool["nuclei"], nucleiTags)
	}
	// Endpoints deduped: 2 unique URLs.
	if got := len(splitLines(nucleiTargets)); got != 2 {
		t.Errorf("nuclei targets = %q, want 2 unique endpoints", nucleiTargets)
	}
}

func TestClassifyOp_PerMethodRouting(t *testing.T) {
	cases := []struct {
		method, path, want string
	}{
		{"GET", "/users/{id}", ProbeIDOR},
		{"GET", "/users", ProbeGeneric},
		{"DELETE", "/sessions/{id}", ProbeBFLA},
		{"POST", "/users", ProbeMassAssignment},
		{"PUT", "/users/{id}", ProbeMassAssignment},
	}
	for _, c := range cases {
		if got := classifyOp(c.method, c.path); got != c.want {
			t.Errorf("classifyOp(%s %s) = %q, want %q", c.method, c.path, got, c.want)
		}
	}
}

func TestSplitOp(t *testing.T) {
	if m, u, ok := splitOp("GET https://api.x/a"); !ok || m != "GET" || u != "https://api.x/a" {
		t.Errorf("splitOp op failed: %s %s %v", m, u, ok)
	}
	if _, _, ok := splitOp("SPEC https://api.x/openapi.json"); ok {
		t.Error("SPEC marker should not parse as an operation")
	}
	if _, _, ok := splitOp("https://api.x"); ok {
		t.Error("bare URL should not parse as an operation")
	}
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	for _, ln := range splitOnNewline(s) {
		if ln != "" {
			out = append(out, ln)
		}
	}
	return out
}

func splitOnNewline(s string) []string {
	var out []string
	cur := ""
	for _, r := range s {
		if r == '\n' {
			out = append(out, cur)
			cur = ""
			continue
		}
		cur += string(r)
	}
	out = append(out, cur)
	return out
}

type fakeTool struct{ name string }

func (f *fakeTool) Name() string                                      { return f.name }
func (*fakeTool) SandboxExecution() bool                              { return true }
func (*fakeTool) MITRETechniques() []string                           { return nil }
func (*fakeTool) Run(context.Context, tool.Args) (tool.Result, error) { return tool.Result{}, nil }

func names(ts []tool.Tool) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Name())
	}
	return out
}
