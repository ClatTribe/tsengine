package container

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/dockle"
	_ "github.com/ClatTribe/tsengine/internal/tool/grype"
	_ "github.com/ClatTribe/tsengine/internal/tool/trivy"
)

func TestHandler_TypeAndAnchors(t *testing.T) {
	h := NewHandler()
	if h.Type() != types.AssetContainerImage {
		t.Errorf("Type: %q", h.Type())
	}
	got := map[string]bool{}
	for _, a := range h.Anchors() {
		got[a.Name()] = true
	}
	for _, want := range []string{"trivy", "grype", "dockle"} {
		if !got[want] {
			t.Errorf("missing anchor %q (got %v)", want, got)
		}
	}
}

func TestPlanAnchors_TrivyImageMode(t *testing.T) {
	h := NewHandler()
	out := h.PlanAnchors(types.Asset{Type: types.AssetContainerImage, Target: "alpine:3.18"})
	if len(out) != 3 {
		t.Fatalf("dispatches: %d, want 3", len(out))
	}
	for _, d := range out {
		if d.Args["target"] != "alpine:3.18" {
			t.Errorf("%s target: %v", d.Tool.Name(), d.Args["target"])
		}
		if d.Tool.Name() == "trivy" && d.Args["mode"] != "image" {
			t.Errorf("trivy mode: %v, want image", d.Args["mode"])
		}
	}
}
