package main

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/assetregistry"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestPlatformRegistersScanToolsForEveryAsset guards the bug class fixed in #588: the platform binary must
// register the OSS tool wrappers (via internal/toolsbundle, blank-imported by main) so the global tool registry
// is populated. A handler resolves its anchor/recon tools FROM that registry at construction, so an empty
// registry means every handler plans zero work → platform-driven scans (Scan now, the scheduler, connector
// scans) silently produce ZERO findings for every asset — which is exactly what shipped before #588.
//
// This test lives in package main so it inherits cmd/platform's EXACT import set: if someone drops the
// toolsbundle import (or removes a wrapper an asset depends on), an asset resolves no tools and this fails
// loudly at CI time instead of silently in production.
func TestPlatformRegistersScanToolsForEveryAsset(t *testing.T) {
	for _, at := range types.AllAssetTypes() {
		h, err := assetregistry.HandlerFor(at)
		if err != nil {
			t.Fatalf("HandlerFor(%s): %v", at, err)
		}
		target := types.Asset{Type: at, Target: "example.com"}
		anchors := len(h.PlanAnchors(target))
		recon := 0
		if rh, ok := h.(asset.ReconHandler); ok {
			recon = len(rh.Recon())
		}
		if anchors == 0 && recon == 0 {
			t.Errorf("asset %q resolves 0 anchor + 0 recon tools — OSS tools not registered. "+
				"cmd/platform must blank-import internal/toolsbundle so the registry is populated.", at)
		}
	}
}
