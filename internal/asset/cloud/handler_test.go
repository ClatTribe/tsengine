package cloud

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/prowler"
)

func TestHandler_NotSkeleton(t *testing.T) {
	h := NewHandler()
	if h.Type() != types.AssetCloudAccount {
		t.Errorf("Type: %q", h.Type())
	}
	if len(h.Anchors()) != 1 || h.Anchors()[0].Name() != "prowler" {
		t.Errorf("anchors: want [prowler], got %v", anchorNamesOf(h))
	}
}

func TestPlanAnchors_PassesProvider(t *testing.T) {
	h := NewHandler()
	out := h.PlanAnchors(types.Asset{Type: types.AssetCloudAccount, Target: "aws"})
	if len(out) != 1 || out[0].Args["target"] != "aws" {
		t.Errorf("provider not passed: %+v", out)
	}
}

func anchorNamesOf(h *Handler) []string {
	out := make([]string, 0)
	for _, a := range h.Anchors() {
		out = append(out, a.Name())
	}
	return out
}
