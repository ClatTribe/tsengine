package domain

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"

	_ "github.com/ClatTribe/tsengine/internal/tool/subfinder"
)

func TestHandler_TypeAndAnchors(t *testing.T) {
	h := NewHandler()
	if h.Type() != types.AssetDomain {
		t.Errorf("Type: %q", h.Type())
	}
	if len(h.Anchors()) != 1 || h.Anchors()[0].Name() != "subfinder" {
		t.Errorf("Anchors: %v", h.Anchors())
	}
}

func TestPlanAnchors_NormalizesToApex(t *testing.T) {
	h := NewHandler()
	cases := map[string]string{
		"https://www.example.com/path":  "www.example.com",
		"example.com":                   "example.com",
		"http://api.example.com:8080/x": "api.example.com",
		"EXAMPLE.COM":                   "example.com",
	}
	for in, want := range cases {
		out := h.PlanAnchors(types.Asset{Type: types.AssetDomain, Target: in})
		if len(out) != 1 {
			t.Fatalf("dispatches: %d", len(out))
		}
		if got := out[0].Args["target"]; got != want {
			t.Errorf("apex(%q): got %q, want %q", in, got, want)
		}
	}
}
