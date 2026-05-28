package repository

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/gitleaks"
	_ "github.com/ClatTribe/tsengine/internal/tool/grype"
	_ "github.com/ClatTribe/tsengine/internal/tool/semgrep"
	_ "github.com/ClatTribe/tsengine/internal/tool/trivy"
	_ "github.com/ClatTribe/tsengine/internal/tool/trufflehog"
)

func TestHandler_NotSkeleton(t *testing.T) {
	h := NewHandler()
	if h.Type() != types.AssetRepository {
		t.Errorf("Type: %q", h.Type())
	}
	got := map[string]bool{}
	for _, a := range h.Anchors() {
		got[a.Name()] = true
	}
	for _, want := range []string{"semgrep", "gitleaks", "trufflehog", "trivy", "grype"} {
		if !got[want] {
			t.Errorf("missing anchor %q (got %v)", want, got)
		}
	}
}

func TestPlanAnchors_TargetsWorkspace_ToolModes(t *testing.T) {
	h := NewHandler()
	out := h.PlanAnchors(types.Asset{Type: types.AssetRepository, Target: "/home/user/myrepo"})
	if len(out) != 5 {
		t.Fatalf("dispatches: %d, want 5", len(out))
	}
	for _, d := range out {
		switch d.Tool.Name() {
		case "trivy":
			if d.Args["target"] != WorkspacePath || d.Args["mode"] != "fs" {
				t.Errorf("trivy args: %+v", d.Args)
			}
		case "grype":
			// grype takes a dir: source string.
			if d.Args["target"] != "dir:"+WorkspacePath {
				t.Errorf("grype target: %v, want dir:%s", d.Args["target"], WorkspacePath)
			}
		default:
			if d.Args["target"] != WorkspacePath {
				t.Errorf("%s target: %v, want %s", d.Tool.Name(), d.Args["target"], WorkspacePath)
			}
		}
	}
}
