package orchestrator

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/tool"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// reconMockHandler implements both asset.Handler and asset.ReconHandler.
type reconMockHandler struct {
	mockHandler
	recon    []tool.Tool
	fanoutFn func(target types.Asset, surface []string) []asset.Dispatch
}

func (h *reconMockHandler) Recon() []tool.Tool { return h.recon }
func (h *reconMockHandler) PlanFanout(target types.Asset, surface []string) []asset.Dispatch {
	return h.fanoutFn(target, surface)
}

func TestRun_ReconStage_FansOutAcrossSurface(t *testing.T) {
	var fanoutSurface []string
	h := &reconMockHandler{
		recon: []tool.Tool{&mockTool{"katana"}},
		fanoutFn: func(_ types.Asset, surface []string) []asset.Dispatch {
			fanoutSurface = surface
			out := make([]asset.Dispatch, 0, len(surface))
			for _, u := range surface {
				out = append(out, asset.Dispatch{Tool: &mockTool{"nuclei"}, Args: tool.Args{"target": u}})
			}
			return out
		},
	}
	d := &mockDispatcher{
		resultsByTool: map[string]tool.Result{
			// katana returns a surface of 2 URLs.
			"katana": {DiscoveredURLs: []string{"https://x/a", "https://x/b"}},
			"nuclei": {Findings: []types.SandboxEmittedFinding{{RuleID: "r"}}},
		},
	}

	_, fired, err := Run(context.Background(),
		types.Asset{Type: types.AssetWebApplication, Target: "https://x/"}, h, d)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	// Surface = target + 2 discovered = 3 (target always included first).
	if len(fanoutSurface) != 3 || fanoutSurface[0] != "https://x/" {
		t.Errorf("surface: %v (want target-first + 2 discovered)", fanoutSurface)
	}
	// fired = katana (recon) + 3× nuclei (fan-out).
	gotKatana, gotNuclei := 0, 0
	for _, f := range fired {
		switch f {
		case "katana":
			gotKatana++
		case "nuclei":
			gotNuclei++
		}
	}
	if gotKatana != 1 || gotNuclei != 3 {
		t.Errorf("fired: katana=%d nuclei=%d (want 1, 3); full=%v", gotKatana, gotNuclei, fired)
	}
}

func TestRun_ReconEmpty_FallsBackToTarget(t *testing.T) {
	// katana runs but discovers nothing → surface is just the target.
	var surfaceLen int
	h := &reconMockHandler{
		recon: []tool.Tool{&mockTool{"katana"}},
		fanoutFn: func(_ types.Asset, surface []string) []asset.Dispatch {
			surfaceLen = len(surface)
			return []asset.Dispatch{{Tool: &mockTool{"nuclei"}, Args: tool.Args{"target": surface[0]}}}
		},
	}
	d := &mockDispatcher{resultsByTool: map[string]tool.Result{
		"katana": {DiscoveredURLs: nil}, // found nothing
		"nuclei": {},
	}}
	_, _, err := Run(context.Background(),
		types.Asset{Type: types.AssetWebApplication, Target: "https://x/"}, h, d)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if surfaceLen != 1 {
		t.Errorf("empty recon should still scan the target; surface=%d", surfaceLen)
	}
}

func TestRun_NoReconTools_UsesPlanAnchors(t *testing.T) {
	// ReconHandler implemented but Recon() empty → PlanAnchors path.
	h := &reconMockHandler{
		mockHandler: mockHandler{anchors: []tool.Tool{&mockTool{"nuclei"}}},
		recon:       nil, // no recon tools
	}
	d := &mockDispatcher{resultsByTool: map[string]tool.Result{"nuclei": {}}}
	_, fired, err := Run(context.Background(),
		types.Asset{Type: types.AssetWebApplication, Target: "https://x/"}, h, d)
	if err != nil {
		t.Fatalf("Run: %v", err)
	}
	if len(fired) != 1 || fired[0] != "nuclei" {
		t.Errorf("expected PlanAnchors fallback; fired=%v", fired)
	}
}

func TestCollectSurface_DedupesCapsTargetFirst(t *testing.T) {
	results := []tool.Result{
		{DiscoveredURLs: []string{"https://x/b", "https://x/a", "https://x/b"}},
		{DiscoveredURLs: []string{"https://x/c"}},
	}
	got := asset.CollectSurface("https://x/", results, 10)
	want := []string{"https://x/", "https://x/b", "https://x/a", "https://x/c"}
	if len(got) != len(want) {
		t.Fatalf("got %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("surface[%d]: got %q want %q", i, got[i], want[i])
		}
	}
	// Cap respected.
	capped := asset.CollectSurface("https://x/", results, 2)
	if len(capped) != 2 || capped[0] != "https://x/" {
		t.Errorf("cap not respected: %v", capped)
	}
}
