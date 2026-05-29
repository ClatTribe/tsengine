package cloud

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/cloudfox"
	_ "github.com/ClatTribe/tsengine/internal/tool/prowler"
	_ "github.com/ClatTribe/tsengine/internal/tool/scoutsuite"
)

func TestHandler_NotSkeleton(t *testing.T) {
	h := NewHandler()
	if h.Type() != types.AssetCloudAccount {
		t.Errorf("Type: %q", h.Type())
	}
	got := map[string]bool{}
	for _, a := range h.Anchors() {
		got[a.Name()] = true
	}
	for _, want := range []string{"prowler", "scoutsuite"} {
		if !got[want] {
			t.Errorf("missing anchor %q (got %v)", want, anchorNamesOf(h))
		}
	}
}

func TestPlanAnchors_PassesProvider(t *testing.T) {
	h := NewHandler()
	out := h.PlanAnchors(types.Asset{Type: types.AssetCloudAccount, Target: "aws"})
	if len(out) != 2 {
		t.Fatalf("dispatches: %d, want 2 (prowler+scoutsuite)", len(out))
	}
	for _, d := range out {
		if d.Args["target"] != "aws" {
			t.Errorf("%s provider not passed: %+v", d.Tool.Name(), d.Args)
		}
	}
}

// cloudfox is registry-tier — wrapped + registered, but NOT an anchor.
func TestCloudFox_RegistryNotAnchor(t *testing.T) {
	h := NewHandler()
	for _, a := range h.Anchors() {
		if a.Name() == "cloudfox" {
			t.Error("cloudfox must be registry-tier, not an anchor")
		}
	}
	got := map[string]bool{}
	for _, r := range h.Registry() {
		got[r.Name()] = true
	}
	if !got["cloudfox"] {
		t.Error("cloudfox should be in the registry tier")
	}
}

func anchorNamesOf(h *Handler) []string {
	out := make([]string, 0)
	for _, a := range h.Anchors() {
		out = append(out, a.Name())
	}
	return out
}
