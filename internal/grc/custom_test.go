package grc

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestDeriveCustomPosture_MapsFindingsAndStaysHonest(t *testing.T) {
	cf := platform.CustomFramework{
		ID: "cf-1", Name: "ACME Framework",
		Controls: []platform.CustomControl{
			{ID: "ACME-1", MapsTo: []string{"cwe:CWE-89"}},   // injection
			{ID: "ACME-2", MapsTo: []string{"soc2:CC6.1"}},   // built-in control ref
			{ID: "ACME-3", MapsTo: []string{"rule:secrets"}}, // rule substring
			{ID: "ACME-4"}, // no maps_to → attestation-only
			{ID: "ACME-5", MapsTo: []string{"cwe:CWE-999999"}}, // mapped but no finding → unassessed
		},
	}
	findings := []types.Finding{
		{ID: "f1", CWE: []string{"CWE-89"}},
		{ID: "f2", Compliance: &types.Compliance{SOC2: []string{"CC6.1"}}},
		{ID: "f3", RuleID: "gitleaks::aws-secrets"},
	}
	states, cov := DeriveCustomPosture(cf, findings)
	// ACME-1/2/3 should be gaps with evidence; ACME-4/5 absent (unassessed, never auto-met).
	gap := map[string]string{}
	for _, s := range states {
		if s.State == platform.ControlGap && len(s.EvidenceRefs) > 0 {
			gap[s.ControlID] = s.EvidenceRefs[0]
		}
	}
	if gap["ACME-1"] != "f1" || gap["ACME-2"] != "f2" || gap["ACME-3"] != "f3" {
		t.Errorf("expected ACME-1/2/3 gaps w/ evidence, got %+v", gap)
	}
	if _, ok := gap["ACME-4"]; ok {
		t.Error("ACME-4 (no maps_to) must NOT be auto-gapped")
	}
	if _, ok := gap["ACME-5"]; ok {
		t.Error("ACME-5 (mapped, no finding) must stay unassessed, never auto-met/gap")
	}
	// 4 of 5 controls are auto-evaluable (have maps_to); never certifiable.
	if cov.AssessableControls != 4 || cov.Certifiable {
		t.Errorf("coverage wrong: %+v", cov)
	}
}
