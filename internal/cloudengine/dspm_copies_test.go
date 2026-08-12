package cloudengine

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// THE POINT, END TO END. Inheritance is only worth having if it produces a FINDING the customer sees.
//
// The scenario is the classic cloud breach: a sensitive production database, correctly locked down, and
// a snapshot of it sitting public in another region that nobody classified. Before copy lineage, DSPM
// saw an unremarkable public store with no sensitivity and stayed silent.
func TestDSPM_PublicSnapshotOfSensitiveDBIsExposed(t *testing.T) {
	inv := cloudgraph.Inventory{
		AccountID: "1", Provider: "aws",
		Resources: []cloudgraph.InvResource{
			// The primary: sensitive, and correctly NOT public.
			{ID: "db-prod", Kind: cloudgraph.KindData, Type: "rds_instance", Name: "prod", Sensitive: cloudgraph.SensHigh},
			// The forgotten copy: public, and nobody tagged it.
			{ID: "snap-2024", Kind: cloudgraph.KindData, Type: "rds_snapshot", Name: "prod-2024", Public: true},
		},
		Copies: []cloudgraph.InvCopy{{Copy: "snap-2024", Source: "db-prod", Detail: "rds snapshot"}},
	}
	snap := cloudgraph.Ingest(inv)

	paths := DSPMExposures(snap, map[string]bool{})
	found := false
	for _, p := range paths {
		for _, a := range p.Affected {
			if a == "snap-2024" {
				found = true
			}
		}
	}
	if !found {
		t.Errorf("the PUBLIC SNAPSHOT of a sensitive database produced no DSPM exposure. This is the "+
			"canonical cloud breach — the primary is locked down and the copy is not — and it stays "+
			"invisible unless the copy inherits its source's classification. paths=%+v", paths)
	}

	// The primary itself must NOT be reported: it is sensitive but correctly private.
	for _, p := range paths {
		for _, a := range p.Affected {
			if a == "db-prod" {
				t.Errorf("the correctly-locked-down primary was reported as exposed: %+v", p.Affected)
			}
		}
	}
}
