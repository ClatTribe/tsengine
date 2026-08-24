package sandbox

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestScanImages_TemplateSelectsThePerAssetImage(t *testing.T) {
	s := ScanImages{Full: "ghcr.io/acme/sandbox:full", Template: "ghcr.io/acme/sandbox:{toolset}-latest"}
	for at, wantToolset := range AssetToolset {
		img, slim := s.For(at)
		if !slim {
			t.Errorf("%s did not resolve to a slim image", at)
			continue
		}
		if want := "ghcr.io/acme/sandbox:" + wantToolset + "-latest"; img != want {
			t.Errorf("%s → %q, want %q", at, img, want)
		}
	}
}

// TestScanImages_FallsBackToFull is the safety property. Every unresolvable case must land on the
// image that carries every tool. A slim image missing a scanner stubs it to exit 127, which the tool
// layer reports as "did not run" — so a wrong guess here does not produce silent bad results, but it
// does turn a scan that could have been complete into a degraded one.
func TestScanImages_FallsBackToFull(t *testing.T) {
	full := "ghcr.io/acme/sandbox:full"
	cases := map[string]ScanImages{
		"no template":                  {Full: full},
		"template without placeholder": {Full: full, Template: "ghcr.io/acme/sandbox:latest"},
		"empty template":               {Full: full, Template: "   "},
	}
	for name, s := range cases {
		if img, slim := s.For(types.AssetRepository); img != full || slim {
			t.Errorf("%s: got %q slim=%v, want %q slim=false", name, img, slim, full)
		}
	}
	// An asset type we do not model has no toolset, so there is no slim image to name.
	s := ScanImages{Full: full, Template: "ghcr.io/acme/sandbox:{toolset}-latest"}
	if img, slim := s.For(types.AssetType("quantum_computer")); img != full || slim {
		t.Errorf("unknown asset: got %q slim=%v, want the full image", img, slim)
	}
}

func TestScanImages_OverrideBeatsTemplate(t *testing.T) {
	s := ScanImages{
		Full:      "ghcr.io/acme/sandbox:full",
		Template:  "ghcr.io/acme/sandbox:{toolset}-latest",
		Overrides: map[types.AssetType]string{types.AssetRepository: "ghcr.io/acme/sandbox@sha256:deadbeef"},
	}
	if img, _ := s.For(types.AssetRepository); img != "ghcr.io/acme/sandbox@sha256:deadbeef" {
		t.Errorf("override ignored: %q", img)
	}
	// and it must not leak to other assets
	if img, _ := s.For(types.AssetAPI); !strings.Contains(img, "api-latest") {
		t.Errorf("override leaked to another asset: %q", img)
	}
}

// TestAssetToolset_CoversEveryFocusAsset guards the mapping against a new asset type being added
// without a toolset — which would silently put it on the full image forever while the deployment
// believed it was running slim ones. Pinned against types.AllAssetTypes so it cannot drift.
func TestAssetToolset_CoversEveryFocusAsset(t *testing.T) {
	// mobile_application is deprecated (CLAUDE.md §3) and deliberately has no slim image.
	deprecated := map[types.AssetType]bool{types.AssetMobileApplication: true}
	var missing []string
	for _, at := range types.AllAssetTypes() {
		if deprecated[at] {
			continue
		}
		if _, ok := AssetToolset[at]; !ok {
			missing = append(missing, string(at))
		}
	}
	if len(missing) > 0 {
		t.Errorf("asset type(s) with no toolset mapping: %v.\n\nEach falls back to the full image, "+
			"which is safe but silent: the deployment pulls slim images for every other asset and this "+
			"one quietly keeps pulling everything. Add it to AssetToolset and to the CI build matrix, "+
			"or state here why it has no slim image.", missing)
	}
}
