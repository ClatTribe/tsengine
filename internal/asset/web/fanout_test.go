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
		"https://x/",           // no params
		"https://x/search?q=1", // params → dalfox
		"https://x/p?id=2",     // params → dalfox
	}
	out := h.PlanFanout(types.Asset{Type: types.AssetWebApplication, Target: "https://x/"}, surface)

	var nucleiList, nucleiDast, dalfox, httpx int
	var nucleiTargets string
	for _, d := range out {
		switch d.Tool.Name() {
		case "nuclei":
			if _, isList := d.Args["targets"]; isList {
				nucleiList++
				nucleiTargets, _ = d.Args["targets"].(string)
			} else if dast, _ := d.Args["dast"].(bool); dast {
				nucleiDast++
			}
		case "httpx":
			httpx++
		case "dalfox":
			dalfox++
		}
	}

	// nuclei (signature templates) + httpx run ONCE over the whole surface.
	if nucleiList != 1 {
		t.Errorf("nuclei list-mode dispatches: got %d, want 1", nucleiList)
	}
	if httpx != 1 {
		t.Errorf("httpx dispatches: got %d, want 1 (list mode)", httpx)
	}
	if strings.Count(nucleiTargets, "\n")+1 != 3 {
		t.Errorf("nuclei list should hold the whole surface (3 URLs); got %q", nucleiTargets)
	}
	// Active per-param tools fan over the 2 param-bearing URLs: dalfox (XSS)
	// + nuclei -dast (fuzzing: path-traversal / redirect / SSRF).
	if dalfox != 2 {
		t.Errorf("dalfox dispatches: got %d, want 2 (param URLs only)", dalfox)
	}
	if nucleiDast != 2 {
		t.Errorf("nuclei -dast dispatches: got %d, want 2 (one per param URL)", nucleiDast)
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
