package ip

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/httpx"
	_ "github.com/ClatTribe/tsengine/internal/tool/nmap"
)

func TestHandler_TypeAndAnchors(t *testing.T) {
	h := NewHandler()
	if h.Type() != types.AssetIPAddress {
		t.Errorf("Type: %q", h.Type())
	}
	got := map[string]bool{}
	for _, a := range h.Anchors() {
		got[a.Name()] = true
	}
	for _, want := range []string{"nmap", "httpx"} {
		if !got[want] {
			t.Errorf("missing anchor %q (got %v)", want, got)
		}
	}
}

func TestPlanAnchors_PassesTarget(t *testing.T) {
	h := NewHandler()
	out := h.PlanAnchors(types.Asset{Type: types.AssetIPAddress, Target: "10.0.0.0/24"})
	if len(out) != 2 {
		t.Fatalf("dispatches: %d, want 2", len(out))
	}
	for _, d := range out {
		if d.Args["target"] != "10.0.0.0/24" {
			t.Errorf("%s target: %v", d.Tool.Name(), d.Args["target"])
		}
	}
}
