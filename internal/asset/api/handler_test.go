package api

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
)

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

type fakeTool struct{ name string }

func (f *fakeTool) Name() string                                    { return f.name }
func (*fakeTool) SandboxExecution() bool                            { return true }
func (*fakeTool) MITRETechniques() []string                         { return nil }
func (*fakeTool) Run(context.Context, tool.Args) (tool.Result, error) { return tool.Result{}, nil }

func names(ts []tool.Tool) []string {
	out := make([]string, 0, len(ts))
	for _, t := range ts {
		out = append(out, t.Name())
	}
	return out
}
