package cloudengine

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Phase 4 (ADR 0009): the engine reasons over GCP + Azure inventories, not just AWS. The path
// finder + jewel predicate already run over the normalized graph; these tests prove the DSPM +
// CWPP lenses fire on GCP/Azure resource types via the provider-aware classifier.

func TestAssess_GCP_DSPMandCWPP(t *testing.T) {
	s := &cloudgraph.Snapshot{AccountID: "proj-acme", Provider: "gcp", Nodes: map[string]*cloudgraph.Node{}}
	// A public GCS bucket holding PII → DSPM.
	s.AddNode(&cloudgraph.Node{ID: "//storage.googleapis.com/acme-pii", Kind: cloudgraph.KindData,
		Type: "storage.googleapis.com/Bucket", Name: "acme-pii", Public: true, Sensitive: cloudgraph.SensHigh})
	// A public Cloud Run service running a vulnerable image → CWPP toxic combo.
	s.AddNode(&cloudgraph.Node{ID: "//run.googleapis.com/api", Kind: cloudgraph.KindResource,
		Type: "run.googleapis.com/Service", Name: "api", Public: true,
		Attrs: map[string]string{"image": "gcr.io/acme/api:1"}})

	a := Assess(s, nil, SnapshotOracle{}, Options{
		WorkloadVulns: []WorkloadVuln{{Image: "gcr.io/acme/api:1", Critical: 1, TopCVE: "CVE-2024-1"}},
	})
	assertAffected(t, a, "//storage.googleapis.com/acme-pii", "GCP DSPM (public GCS bucket with PII)")
	assertAffected(t, a, "//run.googleapis.com/api", "GCP CWPP (public Cloud Run + vuln image)")
}

func TestAssess_Azure_DSPMandCWPP(t *testing.T) {
	s := &cloudgraph.Snapshot{AccountID: "sub-acme", Provider: "azure", Nodes: map[string]*cloudgraph.Node{}}
	// A public Azure blob with sensitive data → DSPM.
	s.AddNode(&cloudgraph.Node{ID: "/subscriptions/x/blob/acme", Kind: cloudgraph.KindData,
		Type: "Microsoft.Storage/storageAccounts/blobServices", Name: "acmeblob", Public: true, Sensitive: cloudgraph.SensHigh})
	// A public AKS workload running a vulnerable image → CWPP.
	s.AddNode(&cloudgraph.Node{ID: "/subscriptions/x/aks/api", Kind: cloudgraph.KindResource,
		Type: "Microsoft.ContainerService/managedClusters", Name: "api", Public: true,
		Attrs: map[string]string{"image": "acme.azurecr.io/api:2"}})

	a := Assess(s, nil, SnapshotOracle{}, Options{
		WorkloadVulns: []WorkloadVuln{{Image: "acme.azurecr.io/api:2", High: 3, TopCVE: "CVE-2024-2"}},
	})
	assertAffected(t, a, "/subscriptions/x/blob/acme", "Azure DSPM (public blob with sensitive data)")
	assertAffected(t, a, "/subscriptions/x/aks/api", "Azure CWPP (public AKS + vuln image)")
}

func assertAffected(t *testing.T, a *types.AIAssessment, id, what string) {
	t.Helper()
	for _, p := range a.Paths {
		for _, r := range p.Affected {
			if r == id {
				return
			}
		}
	}
	t.Errorf("%s: expected a finding affecting %q, got none (paths=%d)", what, id, len(a.Paths))
}
