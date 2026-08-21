package hooks

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func kevCorpus() map[string]corpusEntry {
	return map[string]corpusEntry{
		"CVE-2021-44228": {
			KEV: &types.KEVStatus{Listed: true, Ransomware: true,
				CWEs: []string{"CWE-20", "CWE-400", "CWE-502"}},
		},
	}
}

// THE GAP. compliance.Apply returns early on a finding with no CWE, and grype and
// osv-scanner never set one — so a KEV-listed, ransomware-linked CVE found in a container
// image got NO control mapping at all, while CISA published its CWE in a feed we already
// fetch. The hook order (§11: threat_intel is 6, compliance is 7) is what makes filling it
// here reach the crosswalk in the same pass.
func TestThreatIntel_BackfillsCWEWhenTheScannerHasNone(t *testing.T) {
	h := &ThreatIntel{corpus: kevCorpus()}
	f := types.Finding{ID: "f1", RuleID: "grype::CVE-2021-44228", Tool: "grype", Severity: types.SeverityHigh}
	got, audit, keep := h.Apply(f)
	if !keep {
		t.Fatal("the finding must be kept")
	}
	if len(got.CWE) != 3 {
		t.Fatalf("CWE = %v, want CISA's three — without them the compliance crosswalk never runs", got.CWE)
	}
	var sawBackfill bool
	for _, a := range audit {
		if a.Rule == "threat_intel::kev-cwe-backfill" {
			sawBackfill = true
			if !strings.Contains(a.Reason, "CWE-502") {
				t.Errorf("the audit entry must name what was added: %q", a.Reason)
			}
		}
	}
	if !sawBackfill {
		t.Error("a backfilled CWE must be recorded in the audit log — it is a value the scanner did not report")
	}
}

// NEVER overwrite. The scanner looked at the actual package in the actual image; CISA's list
// describes the CVE in general. Where the scanner has an opinion it is the better-situated
// one, and replacing it trades specific evidence for generic.
func TestThreatIntel_DoesNotOverwriteTheScannersCWE(t *testing.T) {
	h := &ThreatIntel{corpus: kevCorpus()}
	f := types.Finding{ID: "f1", RuleID: "trivy::CVE-2021-44228", Tool: "trivy",
		Severity: types.SeverityHigh, CWE: []string{"CWE-502"}}
	got, audit, _ := h.Apply(f)
	if len(got.CWE) != 1 || got.CWE[0] != "CWE-502" {
		t.Errorf("CWE = %v, want the scanner's own kept intact", got.CWE)
	}
	for _, a := range audit {
		if a.Rule == "threat_intel::kev-cwe-backfill" {
			t.Error("nothing was backfilled, so nothing should be logged as backfilled")
		}
	}
}

// A CVE the corpus knows but CISA published no CWE for adds nothing. 11% of the catalog has
// none, and inventing one would be worse than the empty field.
func TestThreatIntel_NoKEVCWEAddsNothing(t *testing.T) {
	h := &ThreatIntel{corpus: map[string]corpusEntry{
		"CVE-2000-0001": {KEV: &types.KEVStatus{Listed: true}},
	}}
	f := types.Finding{ID: "f1", RuleID: "grype::CVE-2000-0001", Tool: "grype", Severity: types.SeverityHigh}
	if got, _, _ := h.Apply(f); len(got.CWE) != 0 {
		t.Errorf("CWE = %v, want none", got.CWE)
	}
}

// The KEV annotation must survive the change — the backfill rides alongside it, not instead.
func TestThreatIntel_BackfillDoesNotSwallowTheKEVAnnotation(t *testing.T) {
	h := &ThreatIntel{corpus: kevCorpus()}
	f := types.Finding{ID: "f1", RuleID: "grype::CVE-2021-44228", Tool: "grype", Severity: types.SeverityHigh}
	_, audit, _ := h.Apply(f)
	var sawKEV bool
	for _, a := range audit {
		if a.Rule == "threat_intel::kev-listed" {
			sawKEV = true
		}
	}
	if !sawKEV {
		t.Error("the KEV listing annotation was lost — the compliance audience reads it as the SLA-clock trigger")
	}
}

// The payoff, end to end through the real chain order. A grype finding for Log4Shell —
// KEV-listed, ransomware-linked, and carrying no CWE from the scanner — must come out of the
// pass with actual compliance controls on it. Before the backfill it came out with none, and
// the compliance layer the whole §8 story rests on silently did not run for it.
func TestChain_GrypeKEVFindingReachesComplianceControls(t *testing.T) {
	ti := &ThreatIntel{corpus: kevCorpus()}
	cm := NewCompliance()

	f := types.Finding{ID: "f1", RuleID: "grype::CVE-2021-44228", Tool: "grype",
		Severity: types.SeverityCritical, Endpoint: "acme:1.0"}

	// Hook 6 then hook 7, the documented order.
	f, _, _ = ti.Apply(f)
	f, _, _ = cm.Apply(f)

	if f.Compliance == nil {
		t.Fatal("no compliance annotation — the crosswalk still did not run on a KEV-listed CVE")
	}
	if len(f.Compliance.SOC2) == 0 && len(f.Compliance.NIST80053) == 0 && len(f.Compliance.CISv8) == 0 {
		t.Errorf("compliance annotation is empty: %+v", f.Compliance)
	}
	t.Logf("grype Log4Shell now maps to soc2=%v cis=%v nist=%v",
		f.Compliance.SOC2, f.Compliance.CISv8, f.Compliance.NIST80053)
}
