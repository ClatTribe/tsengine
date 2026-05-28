package hooks

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/tracer"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestCorroborator_CrossToolAgreement(t *testing.T) {
	h := NewCorroborator()
	in := []types.Finding{
		{ID: "f-1", RuleID: "nuclei::sqli", Tool: "nuclei", Endpoint: "https://x/q", CWE: []string{"CWE-89"}},
		{ID: "f-2", RuleID: "sqlmap::sqli", Tool: "sqlmap", Endpoint: "https://x/q", CWE: []string{"CWE-89"}},
	}
	out, audit := h.Finalize(in)
	if len(out[0].CorroboratedBy) != 1 || out[0].CorroboratedBy[0] != "sqlmap::sqli" {
		t.Errorf("f-1 corroborated_by: %v", out[0].CorroboratedBy)
	}
	if len(out[1].CorroboratedBy) != 1 || out[1].CorroboratedBy[0] != "nuclei::sqli" {
		t.Errorf("f-2 corroborated_by: %v", out[1].CorroboratedBy)
	}
	if len(audit) != 1 || audit[0].Rule != "corroborator::cross-tool-agreement" {
		t.Errorf("audit: %+v", audit)
	}
}

func TestCorroborator_CVEAcrossTools(t *testing.T) {
	// trivy + grype reporting the same CVE corroborate even with
	// different endpoint formats and no CWE — the container/SCA case.
	h := NewCorroborator()
	in := []types.Finding{
		{ID: "f-1", RuleID: "trivy::CVE-2016-2779", Tool: "trivy", Endpoint: "nginx:1.14 (debian) [util-linux@2.29]"},
		{ID: "f-2", RuleID: "grype::CVE-2016-2779", Tool: "grype", Endpoint: "nginx:1.14 [util-linux@2.29.2-1]"},
	}
	out, audit := h.Finalize(in)
	if len(out[0].CorroboratedBy) != 1 || out[0].CorroboratedBy[0] != "grype::CVE-2016-2779" {
		t.Errorf("f-1 corroborated_by: %v", out[0].CorroboratedBy)
	}
	if len(audit) != 1 {
		t.Errorf("expected 1 corroboration audit entry; got %d", len(audit))
	}
}

func TestCorroborator_SameToolDoesNotCorroborate(t *testing.T) {
	h := NewCorroborator()
	in := []types.Finding{
		{ID: "f-1", RuleID: "nuclei::a", Tool: "nuclei", Endpoint: "https://x/q", CWE: []string{"CWE-89"}},
		{ID: "f-2", RuleID: "nuclei::b", Tool: "nuclei", Endpoint: "https://x/q", CWE: []string{"CWE-89"}},
	}
	out, audit := h.Finalize(in)
	if out[0].CorroboratedBy != nil {
		t.Error("same-tool findings should not corroborate")
	}
	if len(audit) != 0 {
		t.Errorf("no audit expected: %+v", audit)
	}
}

func TestCorroborator_NoCWENoCorroboration(t *testing.T) {
	h := NewCorroborator()
	in := []types.Finding{
		{ID: "f-1", RuleID: "a", Tool: "nuclei", Endpoint: "https://x/q"},
		{ID: "f-2", RuleID: "b", Tool: "sqlmap", Endpoint: "https://x/q"},
	}
	out, _ := h.Finalize(in)
	if out[0].CorroboratedBy != nil {
		t.Error("endpoint-only match (no CWE) should not corroborate")
	}
}

func TestCrossToolMerge_CollapsesExactDuplicates(t *testing.T) {
	h := NewCrossToolMerge()
	in := []types.Finding{
		{ID: "f-1", RuleID: "nuclei::x", Tool: "nuclei", Endpoint: "https://x"},
		{ID: "f-2", RuleID: "nuclei::x", Tool: "nuclei", Endpoint: "https://x"},
		{ID: "f-3", RuleID: "nuclei::y", Tool: "nuclei", Endpoint: "https://x"},
	}
	out, audit := h.Finalize(in)
	if len(out) != 2 {
		t.Fatalf("got %d findings; want 2 (one dup collapsed)", len(out))
	}
	if len(audit) != 1 || audit[0].Action != "merge" {
		t.Errorf("merge not logged: %+v", audit)
	}
}

func TestCrossToolMerge_KeepsCrossToolFindings(t *testing.T) {
	h := NewCrossToolMerge()
	// Same endpoint + rule essence but DIFFERENT tools must not merge —
	// that's corroboration territory.
	in := []types.Finding{
		{ID: "f-1", RuleID: "nuclei::sqli", Tool: "nuclei", Endpoint: "https://x"},
		{ID: "f-2", RuleID: "sqlmap::sqli", Tool: "sqlmap", Endpoint: "https://x"},
	}
	out, _ := h.Finalize(in)
	if len(out) != 2 {
		t.Errorf("cross-tool findings should not merge; got %d", len(out))
	}
}

func TestPostEmitVerifier_DisabledByDefault(t *testing.T) {
	t.Setenv("TSENGINE_L15_POST_EMIT_VERIFY", "")
	h := NewPostEmitVerifier()
	in := []types.Finding{{ID: "f-1"}}
	out, audit := h.Finalize(in)
	if len(out) != 1 || len(audit) != 0 {
		t.Errorf("verifier should be inert; out=%d audit=%d", len(out), len(audit))
	}
}

func TestDefaultChains_Wired(t *testing.T) {
	pf := DefaultPerFinding()
	if len(pf) != 5 {
		t.Errorf("per-finding chain: got %d hooks, want 5", len(pf))
	}
	fin := DefaultFinalize()
	if len(fin) != 3 {
		t.Errorf("finalize chain: got %d hooks, want 3", len(fin))
	}
	// Confirm they satisfy the tracer interfaces (compile-time + names).
	var _ []tracer.PerFindingHook = pf
	var _ []tracer.FinalizeHook = fin
	wantPF := []string{"fp_filter", "surface_priority", "exploitability", "threat_intel", "compliance"}
	for i, h := range pf {
		if h.Name() != wantPF[i] {
			t.Errorf("per-finding[%d]: got %q, want %q", i, h.Name(), wantPF[i])
		}
	}
	wantFin := []string{"corroborator", "post_emit_verifier", "cross_tool_merge"}
	for i, h := range fin {
		if h.Name() != wantFin[i] {
			t.Errorf("finalize[%d]: got %q, want %q", i, h.Name(), wantFin[i])
		}
	}
}
