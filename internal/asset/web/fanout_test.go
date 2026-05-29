package web

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/dalfox"
	_ "github.com/ClatTribe/tsengine/internal/tool/httpx"
	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
)

func TestPlanFanout_ListToolsOnceParamToolsPerURL(t *testing.T) {
	h := NewHandler()
	surface := []string{
		"https://x/",            // no params
		"https://x/search?q=1",  // params → dalfox
		"https://x/p?id=2",      // params → dalfox
	}
	out := h.PlanFanout(types.Asset{Type: types.AssetWebApplication, Target: "https://x/"}, surface)

	byTool := map[string]int{}
	var nucleiTargets string
	for _, d := range out {
		byTool[d.Tool.Name()]++
		if d.Tool.Name() == "nuclei" {
			nucleiTargets, _ = d.Args["targets"].(string)
		}
	}

	// nuclei + httpx: exactly one dispatch each (whole-surface list).
	if byTool["nuclei"] != 1 {
		t.Errorf("nuclei dispatches: got %d, want 1 (list mode)", byTool["nuclei"])
	}
	if byTool["httpx"] != 1 {
		t.Errorf("httpx dispatches: got %d, want 1 (list mode)", byTool["httpx"])
	}
	// nuclei's list carries the whole surface.
	if strings.Count(nucleiTargets, "\n")+1 != 3 {
		t.Errorf("nuclei targets list should hold 3 URLs; got %q", nucleiTargets)
	}
	// dalfox: one per param-bearing URL (2 of 3).
	if byTool["dalfox"] != 2 {
		t.Errorf("dalfox dispatches: got %d, want 2 (param URLs only)", byTool["dalfox"])
	}
}

func TestRecon_OffersKatanaWhenRegistered(t *testing.T) {
	// katana isn't imported here, so Recon() resolves empty — proving the
	// graceful-fallback contract (orchestrator → PlanAnchors).
	h := NewHandler()
	if len(h.Recon()) != 0 {
		t.Errorf("katana not imported in this test → Recon() should be empty; got %d", len(h.Recon()))
	}
}
