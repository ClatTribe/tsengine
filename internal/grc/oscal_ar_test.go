package grc

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestOSCALAssessmentResults_FindingsAsEvidence: a tenant with one gap control (driven by a real finding)
// and one met control produces a valid OSCAL assessment-results — the gap is a not-satisfied finding
// citing an observation built from the backing security finding, the met control is satisfied, and the
// document parses as OSCAL. This is the per-tenant, auditor-ingestible evidence artifact.
func TestOSCALAssessmentResults_FindingsAsEvidence(t *testing.T) {
	ctx := context.Background()
	g := &GRC{Store: store.NewMemory()}

	// a high finding that maps to SOC 2 CC6.1 → opens the gap and becomes the evidence.
	f := types.Finding{
		ID: "f-sqli", Title: "SQL injection in /search", Severity: types.SeverityHigh, Tool: "nuclei",
		Endpoint: "https://app/search", Compliance: &types.Compliance{SOC2: []string{"CC6.1"}},
	}
	if err := g.Store.PutFinding(ctx, "t1", f); err != nil {
		t.Fatal(err)
	}
	if err := g.Apply(ctx, "t1", f); err != nil { // marks CC6.1 a gap with EvidenceRefs=[f-sqli]
		t.Fatal(err)
	}
	// a met control (no finding touches it).
	if err := g.Store.UpsertControlState(ctx, platform.ControlState{
		TenantID: "t1", Framework: "soc2", ControlID: "CC7.2", State: platform.ControlMet,
	}); err != nil {
		t.Fatal(err)
	}

	b, err := g.OSCALAssessmentResults(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}

	// must be valid OSCAL assessment-results.
	var doc struct {
		AR struct {
			UUID     string `json:"uuid"`
			ImportAP struct {
				Href string `json:"href"`
			} `json:"import-ap"`
			Results []struct {
				Observations []struct {
					UUID        string `json:"uuid"`
					Description string `json:"description"`
				} `json:"observations"`
				Findings []struct {
					Title  string `json:"title"`
					Target struct {
						TargetID string `json:"target-id"`
						Status   struct {
							State string `json:"state"`
						} `json:"status"`
					} `json:"target"`
					RelatedObservations []struct {
						ObservationUUID string `json:"observation-uuid"`
					} `json:"related-observations"`
				} `json:"findings"`
			} `json:"results"`
		} `json:"assessment-results"`
	}
	if err := json.Unmarshal(b, &doc); err != nil {
		t.Fatalf("output must be valid OSCAL AR JSON: %v\n%s", err, b)
	}
	if doc.AR.UUID == "" || doc.AR.ImportAP.Href == "" || len(doc.AR.Results) != 1 {
		t.Fatalf("AR must have a uuid, an import-ap, and one result, got %+v", doc.AR)
	}
	res := doc.AR.Results[0]

	// the CC6.1 gap must be a not-satisfied finding citing the observation from the backing finding.
	var gapCited bool
	var obsUUID string
	for _, fin := range res.Findings {
		switch fin.Target.TargetID {
		case "CC6.1":
			if fin.Target.Status.State != "not-satisfied" {
				t.Errorf("CC6.1 (driven by a finding) must be not-satisfied, got %q", fin.Target.Status.State)
			}
			if len(fin.RelatedObservations) != 1 {
				t.Fatalf("the gap must cite exactly one observation, got %d", len(fin.RelatedObservations))
			}
			gapCited = true
			obsUUID = fin.RelatedObservations[0].ObservationUUID
		case "CC7.2":
			if fin.Target.Status.State != "satisfied" {
				t.Errorf("CC7.2 (no finding) must be satisfied, got %q", fin.Target.Status.State)
			}
		}
	}
	if !gapCited {
		t.Fatal("expected a not-satisfied OSCAL finding for CC6.1")
	}
	// the cited observation must exist and describe the backing finding.
	var found bool
	for _, o := range res.Observations {
		if o.UUID == obsUUID {
			found = true
			if !strings.Contains(o.Description, "SQL injection") {
				t.Errorf("the observation must describe the backing finding, got %q", o.Description)
			}
		}
	}
	if !found {
		t.Error("the gap's cited observation must appear in the result's observations (grounded evidence link)")
	}

	// determinism: a second render is byte-identical (diffable evidence).
	b2, _ := g.OSCALAssessmentResults(ctx, "t1")
	if string(b) != string(b2) {
		t.Error("OSCAL AR must be deterministic (byte-identical across renders)")
	}
}
