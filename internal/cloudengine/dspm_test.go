package cloudengine

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func dspmSnap() *cloudgraph.Snapshot {
	s := &cloudgraph.Snapshot{AccountID: "111122223333", Provider: "aws", Nodes: map[string]*cloudgraph.Node{}}
	// A public bucket holding PII → the DSPM trigger.
	s.AddNode(&cloudgraph.Node{ID: "arn:pii", Kind: cloudgraph.KindData, Type: "AWS::S3::Bucket", Name: "customer-pii", Public: true, Sensitive: cloudgraph.SensHigh})
	// A public bucket with low-sensitivity data → still DSPM, lower severity.
	s.AddNode(&cloudgraph.Node{ID: "arn:logs", Kind: cloudgraph.KindData, Type: "AWS::S3::Bucket", Name: "app-logs", Public: true, Sensitive: cloudgraph.SensLow})
	// A public bucket with NO sensitivity class → NOT DSPM (CSPM/prowler territory).
	s.AddNode(&cloudgraph.Node{ID: "arn:assets", Kind: cloudgraph.KindData, Type: "AWS::S3::Bucket", Name: "static", Public: true})
	// A sensitive bucket that is NOT public → NOT a direct exposure (grounded: needs Public).
	s.AddNode(&cloudgraph.Node{ID: "arn:private", Kind: cloudgraph.KindData, Type: "AWS::S3::Bucket", Name: "private-pii", Sensitive: cloudgraph.SensHigh})
	// A public + privileged IAM role → public but NOT a data store, so not DSPM.
	s.AddNode(&cloudgraph.Node{ID: "arn:role", Kind: cloudgraph.KindPrincipal, Type: "AWS::IAM::Role", Name: "admin", Public: true, Privileged: true})
	return s
}

func TestDSPMExposures_GroundedTriggers(t *testing.T) {
	exp := DSPMExposures(dspmSnap(), nil)
	got := map[string]bool{}
	for _, e := range exp {
		for _, a := range e.Affected {
			got[a] = true
		}
	}
	// Only the two public+sensitive data stores fire.
	if !got["arn:pii"] || !got["arn:logs"] {
		t.Errorf("public+sensitive stores must be flagged, got %v", got)
	}
	if got["arn:assets"] {
		t.Error("a public store with NO sensitivity class is CSPM, not DSPM — must not fire")
	}
	if got["arn:private"] {
		t.Error("a sensitive but NON-public store is not a direct exposure — must not fire (grounded)")
	}
	if got["arn:role"] {
		t.Error("a public IAM role is not a data store — must not fire")
	}
	if len(exp) != 2 {
		t.Fatalf("want exactly 2 DSPM exposures, got %d", len(exp))
	}
}

func TestDSPMExposures_SeverityAndCompliance(t *testing.T) {
	exp := DSPMExposures(dspmSnap(), nil)
	var pii *exposureView
	for i := range exp {
		if affects(exp[i].Affected, "arn:pii") {
			e := exp[i]
			pii = &exposureView{e.RealImpact.DataSensitivity, e.Compliance, e.Narrative}
		}
	}
	if pii == nil {
		t.Fatal("the PII store should produce a DSPM exposure")
	}
	if pii.sens != "high" {
		t.Errorf("PII exposure should carry high data-sensitivity, got %q", pii.sens)
	}
	if pii.narrative == "" {
		t.Error("DSPM finding needs a plain-English narrative")
	}
	// The compliance crosswalk should cite data-protection controls for the PII store.
	if pii.compliance == nil || len(pii.compliance.GDPR) == 0 || len(pii.compliance.CCPA) == 0 {
		t.Errorf("public PII exposure should cite GDPR + CCPA, got %+v", pii.compliance)
	}
}

func affects(list []string, id string) bool {
	for _, x := range list {
		if x == id {
			return true
		}
	}
	return false
}

func TestDSPMExposures_DedupAgainstCoveredPaths(t *testing.T) {
	// If a store is already on a discovered multi-hop path, don't double-report it.
	covered := map[string]bool{"arn:pii": true}
	exp := DSPMExposures(dspmSnap(), covered)
	for _, e := range exp {
		for _, a := range e.Affected {
			if a == "arn:pii" {
				t.Error("a store already covered by a discovered path must be deduped out of DSPM")
			}
		}
	}
	if len(exp) != 1 { // only arn:logs remains
		t.Fatalf("want 1 after dedup, got %d", len(exp))
	}
}

type exposureView struct {
	sens       string
	compliance *types.Compliance
	narrative  string
}
