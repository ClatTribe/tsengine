package mobile

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/gitleaks"
	_ "github.com/ClatTribe/tsengine/internal/tool/mobsfscan"
	_ "github.com/ClatTribe/tsengine/internal/tool/semgrep"
	_ "github.com/ClatTribe/tsengine/internal/tool/trivy"
	_ "github.com/ClatTribe/tsengine/internal/tool/trufflehog"
)

func TestHandler_Type(t *testing.T) {
	if got := NewHandler().Type(); got != types.AssetMobileApplication {
		t.Errorf("Type: %q, want %q", got, types.AssetMobileApplication)
	}
}

func TestHandler_AnchorsAndRegistry(t *testing.T) {
	h := NewHandler()
	anchors := map[string]bool{}
	for _, a := range h.Anchors() {
		anchors[a.Name()] = true
	}
	// mobsfscan is the mobile-specific tool — it MUST be present (the asset
	// is pointless without it). gitleaks + trivy corroborate.
	for _, want := range []string{"mobsfscan", "gitleaks", "trivy"} {
		if !anchors[want] {
			t.Errorf("missing anchor %q (got %v)", want, anchors)
		}
	}
	if len(h.Anchors()) == 0 {
		t.Fatal("no anchors resolved — sandbox tools not registered in test")
	}
	reg := map[string]bool{}
	for _, r := range h.Registry() {
		reg[r.Name()] = true
	}
	if !reg["semgrep"] {
		t.Errorf("expected semgrep in registry tier, got %v", reg)
	}
}

func TestPlanAnchors_TargetsWorkspace(t *testing.T) {
	h := NewHandler()
	out := h.PlanAnchors(types.Asset{Type: types.AssetMobileApplication, Target: "/home/user/MyApp"})
	if len(out) != len(h.Anchors()) {
		t.Fatalf("dispatches: %d, want %d", len(out), len(h.Anchors()))
	}
	for _, d := range out {
		if d.Args["target"] != WorkspacePath {
			t.Errorf("%s target = %v, want %s (host path must not leak to the tool)", d.Tool.Name(), d.Args["target"], WorkspacePath)
		}
		if d.Tool.Name() == "trivy" && d.Args["mode"] != "fs" {
			t.Errorf("trivy must run in fs mode for a bundle scan, got %+v", d.Args)
		}
	}
}

func TestFilter_NoOp(t *testing.T) {
	h := NewHandler()
	in := h.PlanAnchors(types.Asset{Type: types.AssetMobileApplication, Target: "/x"})
	if got := h.Filter(context.Background(), types.Asset{}, in); len(got) != len(in) {
		t.Errorf("Filter dropped dispatches: %d -> %d", len(in), len(got))
	}
}
