package platformapi

import (
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// TestEnrichFindings_PlatformNativeGetsL15 proves the fix for the L1.5 asymmetry: a finding that enters
// through a platform-native ingest path (OSINT / identity / SaaS / TPRM / device / cloud-drift / TLS) gets
// the SAME L1.5 quality signal an engine-scanned finding gets — verification_status + a confidence scalar —
// instead of landing raw. Before this, only engine findings (routed through the sandbox tracer) were
// enriched; platform ingest called PutFinding directly and bypassed the whole chain (§11).
func TestEnrichFindings_PlatformNativeGetsL15(t *testing.T) {
	in := []types.Finding{{
		Tool:     "osint",
		RuleID:   "osint::exposed-host",
		Severity: types.SeverityHigh,
		Endpoint: "shadow.example.com",
	}}

	out := enrichFindings(in)
	if len(out) != 1 {
		t.Fatalf("enrichFindings changed cardinality: got %d, want 1", len(out))
	}
	// The confidence finalize hook stamps every finding — the observable proof enrichment ran.
	if out[0].VerificationStatus == "" {
		t.Errorf("verification_status not set — the L1.5 confidence hook did not run on a platform-native finding")
	}
	if out[0].Confidence <= 0 {
		t.Errorf("confidence not set (%v) — L1.5 enrichment did not run", out[0].Confidence)
	}
}

// TestEnrichFindings_PreservesInlineCompliance proves enrichment is SAFE for posture/config findings that
// already carry an inline compliance mapping (identity, SaaS, cloud-drift all set it at emission): the
// compliance.map hook MERGES, it never clobbers, so the detector's own control mapping survives.
func TestEnrichFindings_PreservesInlineCompliance(t *testing.T) {
	in := []types.Finding{{
		Tool:       "identity",
		RuleID:     "identitythreat::mfa_removed",
		Severity:   types.SeverityHigh,
		Endpoint:   "user@example.com",
		Compliance: &types.Compliance{SOC2: []string{"CC6.1"}},
	}}

	out := enrichFindings(in)
	if out[0].Compliance == nil {
		t.Fatalf("inline compliance was dropped by enrichment")
	}
	found := false
	for _, c := range out[0].Compliance.SOC2 {
		if c == "CC6.1" {
			found = true
		}
	}
	if !found {
		t.Errorf("inline SOC2 CC6.1 mapping was clobbered by the compliance hook; got %+v", out[0].Compliance.SOC2)
	}
}

// TestEnrichFindings_Empty is the trivial-input guard: no findings in, no findings out, no panic.
func TestEnrichFindings_Empty(t *testing.T) {
	if got := enrichFindings(nil); len(got) != 0 {
		t.Errorf("enrichFindings(nil) = %d findings, want 0", len(got))
	}
}
