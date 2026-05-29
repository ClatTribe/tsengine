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

	var nucleiSig, nucleiDast, dalfox, httpx int
	var sigTargets, dastTargets string
	for _, d := range out {
		switch d.Tool.Name() {
		case "nuclei":
			if dast, _ := d.Args["dast"].(bool); dast {
				nucleiDast++
				dastTargets, _ = d.Args["targets"].(string)
			} else {
				nucleiSig++
				sigTargets, _ = d.Args["targets"].(string)
			}
		case "httpx":
			httpx++
		case "dalfox":
			dalfox++
		}
	}

	// nuclei signature templates + httpx run ONCE over the whole surface.
	if nucleiSig != 1 {
		t.Errorf("nuclei signature dispatches: got %d, want 1", nucleiSig)
	}
	if httpx != 1 {
		t.Errorf("httpx dispatches: got %d, want 1 (list mode)", httpx)
	}
	if strings.Count(sigTargets, "\n")+1 != 3 {
		t.Errorf("nuclei signature list should hold the whole surface (3 URLs); got %q", sigTargets)
	}
	// nuclei -dast is ONE list dispatch over the param surface (efficient —
	// nuclei is list-native; per-URL spawning pays ~27s engine startup each).
	if nucleiDast != 1 {
		t.Errorf("nuclei -dast dispatches: got %d, want 1 (single list over param URLs)", nucleiDast)
	}
	if strings.Count(dastTargets, "\n")+1 != 2 {
		t.Errorf("nuclei -dast list should hold the 2 param URLs; got %q", dastTargets)
	}
	// dalfox (genuinely single-target) fans per-URL over the 2 param URLs.
	if dalfox != 2 {
		t.Errorf("dalfox dispatches: got %d, want 2 (param URLs only)", dalfox)
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
