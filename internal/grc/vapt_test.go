package grc

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestVAPTReport_GroundedSummaryAndMarkdown(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme Inc"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "a1", TenantID: "t1", Type: "web_application", Target: "https://acme.example"})
	_ = st.PutFinding(ctx, "t1", types.Finding{
		ID: "f-1", RuleID: "nuclei::sqli", Tool: "nuclei", Severity: types.SeverityCritical,
		Title: "SQL injection in /search", Endpoint: "https://acme.example/search?q=", CWE: []string{"CWE-89"},
		VerificationStatus: "verified", ThreatIntel: &types.ThreatIntel{CVSS: 9.8, KEV: &types.KEVStatus{}},
	})
	_ = st.PutFinding(ctx, "t1", types.Finding{
		ID: "f-2", RuleID: "nuclei::missing-hsts", Tool: "nuclei", Severity: types.SeverityLow,
		Title: "HSTS header not set", Endpoint: "https://acme.example", VerificationStatus: "pattern_match",
	})
	// a pending fix for f-1 → fixes_ready signal
	_ = st.PutAction(ctx, platform.Action{ID: "act-1", TenantID: "t1", FindingID: "f-1", Kind: platform.ActOpenPR, Status: platform.ActPendingApproval})

	g := &GRC{Store: st}
	r, err := g.VAPTReport(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}

	if r.TenantName != "Acme Inc" {
		t.Errorf("tenant name = %q", r.TenantName)
	}
	if r.Summary.Total != 2 || r.Summary.BySeverity["critical"] != 1 || r.Summary.BySeverity["low"] != 1 {
		t.Errorf("summary counts wrong: %+v", r.Summary)
	}
	if r.Summary.Verified != 1 {
		t.Errorf("verified count = %d, want 1", r.Summary.Verified)
	}
	// f-2 (HSTS) is pattern_match-only → the unconfirmed (FP-exposed) lead count.
	if r.Summary.Unconfirmed != 1 {
		t.Errorf("unconfirmed count = %d, want 1 (the pattern_match HSTS finding)", r.Summary.Unconfirmed)
	}
	if r.Summary.KEV != 1 {
		t.Errorf("KEV count = %d, want 1", r.Summary.KEV)
	}
	if r.Summary.FixesReady != 1 {
		t.Errorf("fixes-ready = %d, want 1 (f-1 has a pending PR)", r.Summary.FixesReady)
	}
	if r.Summary.RiskRating != "Critical" {
		t.Errorf("risk = %q, want Critical", r.Summary.RiskRating)
	}
	// worst-severity first
	if len(r.Findings) != 2 || r.Findings[0].ID != "f-1" {
		t.Errorf("findings should be severity-sorted (critical first): %+v", r.Findings)
	}

	// finding-level enrichment: SQLi (CWE-89) → OWASP A03 + parameterized-query remediation.
	if f := r.Findings[0]; len(f.OWASP) == 0 || !strings.Contains(f.OWASP[0], "A03") || !strings.Contains(f.Remediation, "parameterized") {
		t.Errorf("SQLi finding should carry OWASP A03 + a parameterized-query fix, got owasp=%v rem=%q", f.OWASP, f.Remediation)
	}

	md := RenderVAPTMarkdown(r)
	for _, want := range []string{
		"Vulnerability Assessment & Penetration Test — Acme Inc",
		"Overall risk rating: Critical",
		"This assessment of Acme Inc identified", // the narrative executive summary
		"https://acme.example",                   // scope
		"SQL injection in /search",
		"`nuclei` · `nuclei::sqli`", // tool/rule evidence
		"CWE-89",
		"A03:2021 Injection",     // OWASP mapping
		"Recommended fix:",       // per-finding remediation guidance
		"parameterized",          // the actual fix text
		"awaiting your approval", // fix-ready tie-in
		"actively exploited (CISA KEV)",
		"cites the tool and rule that proves it",               // the grounding statement
		"1 unconfirmed",                                        // summary FP-exposure count
		"unconfirmed (pattern match — validate before action)", // per-finding label on f-2
		"Methodology & confidence",                             // the confidence-tier explainer
	} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
}

func TestVAPTReport_ConfirmedLeadsUnconfirmed(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	// Two HIGH findings: one corroborated (confirmed), one pattern_match (unconfirmed).
	// The confirmed one must lead within the severity tier, so a false positive
	// never fronts a proven result.
	_ = st.PutFinding(ctx, "t1", types.Finding{
		ID: "b-unconfirmed", RuleID: "nuclei::reflected", Tool: "nuclei", Severity: types.SeverityHigh,
		Title: "Reflected value", VerificationStatus: "pattern_match", Confidence: 0.55,
	})
	_ = st.PutFinding(ctx, "t1", types.Finding{
		ID: "a-confirmed", RuleID: "nuclei::sqli", Tool: "nuclei", Severity: types.SeverityHigh,
		Title: "SQL injection", VerificationStatus: "corroborated", Confidence: 0.9,
	})

	g := &GRC{Store: st}
	r, err := g.VAPTReport(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Findings) != 2 || r.Findings[0].ID != "a-confirmed" || r.Findings[1].ID != "b-unconfirmed" {
		t.Fatalf("confirmed finding must lead the same-severity unconfirmed one, got %+v", r.Findings)
	}
	if r.Findings[0].Unconfirmed || !r.Findings[1].Unconfirmed {
		t.Errorf("Unconfirmed flags wrong: %+v", r.Findings)
	}
	md := RenderVAPTMarkdown(r)
	if !strings.Contains(md, "confidence 90%") || !strings.Contains(md, "confidence 55%") {
		t.Errorf("per-finding confidence%% should render:\n%s", md)
	}
}

func TestVAPTReport_CleanTenant(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Clean Co"})
	g := &GRC{Store: st}
	r, err := g.VAPTReport(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if r.Summary.RiskRating != "Clear" || r.Summary.Total != 0 {
		t.Errorf("a clean tenant must rate Clear with 0 findings, got %+v", r.Summary)
	}
	if md := RenderVAPTMarkdown(r); !strings.Contains(md, "every monitored asset is currently clean") {
		t.Errorf("clean report should say so:\n%s", md)
	}
}
