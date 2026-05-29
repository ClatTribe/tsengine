package web

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/ffuf"
	_ "github.com/ClatTribe/tsengine/internal/tool/nuclei"
)

// A rich surface: param URLs → nuclei DAST/OAST; a login URL →
// default-logins; surface is large so ffuf does NOT fire.
func TestPlanEscalation_ParamAndLogin(t *testing.T) {
	h := NewHandler()
	target := types.Asset{Type: types.AssetWebApplication, Target: "https://x/"}
	surface := []string{
		"https://x/", "https://x/a", "https://x/b", "https://x/c",
		"https://x/search?q=1", "https://x/p?id=2", "https://x/login",
	}
	out := h.PlanEscalation(target, surface, nil)

	var dast, defLogins bool
	ffufFired := false
	for _, d := range out {
		if d.Tool.Name() == "ffuf" {
			ffufFired = true
		}
		if d.Tool.Name() == "nuclei" {
			if v, _ := d.Args["dast"].(bool); v {
				dast = true
				// list mode over the param URLs.
				if n := strings.Count(d.Args["targets"].(string), "\n") + 1; n != 2 {
					t.Errorf("dast targets should be the 2 param URLs, got %d", n)
				}
			}
			if d.Args["tags"] == "default-logins" {
				defLogins = true
			}
		}
	}
	if !dast {
		t.Error("expected a nuclei DAST/OAST dispatch for param URLs")
	}
	if !defLogins {
		t.Error("expected a nuclei default-logins dispatch for the login URL")
	}
	if ffufFired {
		t.Error("ffuf should NOT fire on a rich (non-thin) surface")
	}
}

// Thin surface → ffuf content discovery fires.
func TestPlanEscalation_ThinSurfaceTriggersFfuf(t *testing.T) {
	h := NewHandler()
	target := types.Asset{Type: types.AssetWebApplication, Target: "https://x/"}
	out := h.PlanEscalation(target, []string{"https://x/"}, nil)
	found := false
	for _, d := range out {
		if d.Tool.Name() == "ffuf" {
			found = true
			if d.Args["target"] != "https://x/" || d.EscalatedFrom == "" {
				t.Errorf("ffuf dispatch = %+v", d)
			}
		}
	}
	if !found {
		t.Error("thin surface should trigger ffuf")
	}
}
