package assetregistry

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// escalatingAssets are the asset types CLAUDE.md §5.3 documents as having a conditional depth stage.
// Each per-asset package unit-tests its own trigger table, and the orchestrator unit-tests that it
// calls PlanEscalation on a handler implementing the interface — but both use their own fixtures, so
// nothing covered the SEAM: that the handler the registry really returns still satisfies
// asset.EscalationPlanner.
//
// That seam is exactly where PR #588 bit (cmd/platform resolved handlers against an empty tool
// registry: every unit test passed, every scan silently produced zero findings). A break here is the
// same shape — the type assertion in orchestrator.Run quietly fails, no depth tool ever fires, and
// the customer sees a thinner scan rather than an error. A value/pointer receiver change or a
// wrapper type is all it takes.
var escalatingAssets = []types.AssetType{
	types.AssetWebApplication, // param URL → nuclei DAST/OAST · thin surface → ffuf · WordPress → wpscan
	types.AssetAPI,            // spec ingested → kiterunner · /graphql → inql
	types.AssetRepository,     // semgrep injection → CodeQL · mobile files → mobsfscan
	types.AssetIPAddress,      // open auth port → hydra
}

func TestDocumentedEscalatingAssetsAreReachableAsPlanners(t *testing.T) {
	for _, at := range escalatingAssets {
		t.Run(string(at), func(t *testing.T) {
			h, err := HandlerFor(at)
			if err != nil {
				t.Fatalf("HandlerFor(%s): %v", at, err)
			}
			if _, ok := h.(asset.EscalationPlanner); !ok {
				t.Fatalf("%s is documented to escalate (§5.3) but the handler the registry returns does "+
					"NOT satisfy asset.EscalationPlanner — orchestrator.Run's type assertion will silently "+
					"skip its depth stage, so the tools never fire and the scan just looks thin", at)
			}
		})
	}
}

// The converse, so the list above cannot rot into a rubber stamp: an asset type with no documented
// depth stage must not silently acquire one unnoticed. If this fails, the §5.3 table and the code
// have diverged — update BOTH, which is the point.
func TestNonEscalatingAssetsHaveNoDepthStage(t *testing.T) {
	for _, at := range []types.AssetType{types.AssetContainerImage, types.AssetCloudAccount} {
		t.Run(string(at), func(t *testing.T) {
			h, err := HandlerFor(at)
			if err != nil {
				t.Fatalf("HandlerFor(%s): %v", at, err)
			}
			if _, ok := h.(asset.EscalationPlanner); ok {
				t.Errorf("%s gained an escalation stage that §5.3 does not document — update CLAUDE.md "+
					"and this list together, so the docs keep describing what actually runs", at)
			}
		})
	}
}
