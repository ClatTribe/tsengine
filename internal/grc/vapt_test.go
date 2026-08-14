package grc

import (
	"context"
	"strings"
	"testing"
	"time"

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

// TestVAPT_ExploitationProvenSurfaced: a finding carrying the active-driver PoC line is counted as
// exploitation-proven, the PoC is split out of the description into its own distinguished block,
// and the summary reflects it — the XBOW "we proved it" evidence, not buried in prose.
func TestVAPT_ExploitationProvenSurfaced(t *testing.T) {
	poc := "[Exploitation PoC · cors-misconfiguration] GET https://api/data → reflected Origin with credentials (HTTP 200)"
	findings := []types.Finding{{
		ID: "f1", Title: "CORS Misconfiguration", Severity: types.SeverityHigh, Tool: "pentest",
		RuleID: "cors", Endpoint: "https://api/data", VerificationStatus: "verified",
		Description: "The API trusts arbitrary origins.\n\n" + poc,
	}}
	r := ReportFromFindings(findings, []string{"https://api"}, "Acme", time.Now().UTC(), nil)
	if r.Summary.ExploitProven != 1 {
		t.Fatalf("ExploitProven = %d, want 1", r.Summary.ExploitProven)
	}
	vf := r.Findings[0]
	if vf.PoC != poc {
		t.Errorf("PoC not extracted: %q", vf.PoC)
	}
	if strings.Contains(vf.Description, "[Exploitation PoC") {
		t.Error("PoC must be split OUT of the description body (not duplicated)")
	}
	md := RenderVAPTMarkdown(r)
	if !strings.Contains(md, "exploitation-proven") {
		t.Error("report must surface the exploitation-proven tier")
	}
	if !strings.Contains(md, "reproducible proof of concept") || !strings.Contains(md, poc) {
		t.Error("report must render the captured PoC as a distinguished, reproducible block")
	}
}

// TestVAPT_NoPoCWhenNoneCaptured: a plain finding (no captured proof) is not mislabeled proven.
func TestVAPT_NoPoCWhenNoneCaptured(t *testing.T) {
	findings := []types.Finding{{ID: "f2", Title: "Info leak", Severity: types.SeverityLow, Tool: "nuclei", RuleID: "x", Description: "A header disclosed the server version."}}
	r := ReportFromFindings(findings, nil, "Acme", time.Now().UTC(), nil)
	if r.Summary.ExploitProven != 0 || r.Findings[0].PoC != "" {
		t.Error("a finding with no captured PoC must not be marked exploitation-proven")
	}
}

// The VAPT report surfaces the L1.5 threat-intel enrichments — CVSS vector, EPSS probability, and
// public-exploit availability — not just the bare CVSS score, so the consultant's deliverable shows the
// full prioritization signal the engine computed.
func TestVAPTReport_SurfacesThreatIntelEnrichment(t *testing.T) {
	now := time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC)
	findings := []types.Finding{{
		ID: "f-1", RuleID: "grype::CVE-2021-44228", Tool: "grype", Severity: types.SeverityCritical,
		Title: "Log4Shell", Endpoint: "pkg:maven/log4j", VerificationStatus: "corroborated",
		ThreatIntel: &types.ThreatIntel{
			CVSS:       10.0,
			CVSSVector: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			EPSS:       &types.EPSSScore{Score: 0.97},
			Exploits:   []string{"exploitdb:EDB-50592"},
		},
	}}
	r := ReportFromFindings(findings, []string{"acme.example"}, "Acme", now, nil)
	vf := r.Findings[0]
	if vf.CVSSVector == "" || vf.EPSS != 0.97 || !vf.PublicExploit {
		t.Fatalf("enrichment not carried onto the VAPT finding: %+v", vf)
	}
	md := RenderVAPTMarkdown(r)
	for _, want := range []string{"AV:N/AC:L", "EPSS:", "97.0% exploit probability", "Public exploit available"} {
		if !strings.Contains(md, want) {
			t.Errorf("report markdown missing %q", want)
		}
	}
}

func TestVAPT_DependencyPatchability(t *testing.T) {
	findings := []types.Finding{
		{ID: "1", Tool: "trivy", Severity: types.SeverityHigh, RuleID: "trivy::CVE-1", ToolArgs: map[string]string{"fixable": "true", "fixed_version": "2.0"}},
		{ID: "2", Tool: "grype", Severity: types.SeverityHigh, RuleID: "grype::CVE-2", ToolArgs: map[string]string{"fixable": "true"}},
		{ID: "3", Tool: "osv-scanner", Severity: types.SeverityMedium, RuleID: "osv-scanner::CVE-3", ToolArgs: map[string]string{"fixable": "false"}},
		{ID: "4", Tool: "nuclei", Severity: types.SeverityHigh, RuleID: "nuclei::xss"}, // no fixable key → not counted
	}
	r := ReportFromFindings(findings, []string{"repo"}, "Acme", time.Now().UTC(), nil)
	if r.Summary.PatchAvailable != 2 || r.Summary.PatchUnavailable != 1 {
		t.Fatalf("patch counts wrong: available=%d unavailable=%d", r.Summary.PatchAvailable, r.Summary.PatchUnavailable)
	}
	md := RenderVAPTMarkdown(r)
	if !strings.Contains(md, "2 of 3 dependency findings have an upstream fix") {
		t.Errorf("patchability line missing from VAPT markdown:\n%s", md)
	}
}

// ── "NOTHING FOUND" AND "NOTHING TESTED" ARE DIFFERENT REPORTS ───────────────────────────────────

// The VAPT report is the artifact that leaves the building. It said "Overall risk rating: Clear …
// every monitored asset is currently clean" for a scope target no tool had ever run against, because
// zero findings from a scanned target and zero from an unscanned one are the same zero.
func TestVAPT_UnscannedScopeIsNotRatedClear(t *testing.T) {
	r := ReportFromFindings(nil, []string{"https://app.example.com"}, "Q3 pentest", time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC), nil)
	r.Untested = []string{"https://app.example.com"}
	Reassess(r)

	if r.Summary.RiskRating == "Clear" {
		t.Error("a scope nothing assessed was rated Clear — that is a verdict with no assessment behind it")
	}
	md := RenderVAPTMarkdown(r)
	if strings.Contains(md, "every monitored asset is currently clean") {
		t.Errorf("the report claims every asset is clean when none was scanned:\n%s", md)
	}
	if !strings.Contains(md, "app.example.com") {
		t.Error("the report does not name the target it could not assess")
	}
	// It has to be unmistakable, not a footnote.
	low := strings.ToLower(md)
	if !strings.Contains(low, "not assessed") && !strings.Contains(low, "not been assessed") {
		t.Errorf("the report does not say plainly that nothing was assessed:\n%s", md)
	}
}

// A PARTIALLY tested scope must credit what was tested and name what was not — collapsing to either
// extreme loses information the reader needs.
func TestVAPT_PartiallyTestedScopeNamesTheGap(t *testing.T) {
	r := ReportFromFindings(nil, []string{"https://a.example.com", "https://b.example.com"}, "Q3", time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC), nil)
	r.Untested = []string{"https://b.example.com"}
	Reassess(r)

	md := RenderVAPTMarkdown(r)
	if strings.Contains(md, "every monitored asset is currently clean") {
		t.Error("a partially-tested scope still claimed every asset is clean")
	}
	if !strings.Contains(md, "b.example.com") {
		t.Error("the untested target is not named")
	}
	// The rating still applies to what WAS tested — a partial scope is not "Not assessed".
	if r.Summary.RiskRating == "Not assessed" {
		t.Error("a partially-tested scope was reported as wholly unassessed")
	}
}

// THE OTHER DIRECTION, which matters just as much: a genuinely scanned-and-clean scope must still
// read as clean. An honesty fix that makes every report hedge is its own kind of useless.
func TestVAPT_ScannedAndCleanStillReadsClean(t *testing.T) {
	r := ReportFromFindings(nil, []string{"https://a.example.com"}, "Q3", time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC), nil)
	Reassess(r) // no Untested — everything in scope was scanned
	if r.Summary.RiskRating != "Clear" {
		t.Errorf("a scanned, clean scope was rated %q, want Clear", r.Summary.RiskRating)
	}
	if !strings.Contains(RenderVAPTMarkdown(r), "every monitored asset is currently clean") {
		t.Error("a genuinely clean report lost its clean statement")
	}
}

// A rating stated over a partly-examined scope must carry the qualification WHERE THE RATING IS —
// the executive summary is what gets read and quoted, not the scope list further down.
func TestVAPT_RatingWithFindingsStillNamesUnassessedScope(t *testing.T) {
	f := types.Finding{ID: "f1", RuleID: "r", Tool: "nuclei", Severity: types.SeverityHigh,
		Title: "Something", Endpoint: "https://a.example.com"}
	r := ReportFromFindings([]types.Finding{f},
		[]string{"https://a.example.com", "https://b.example.com"}, "Acme",
		time.Date(2026, 6, 27, 0, 0, 0, 0, time.UTC), nil)
	r.Untested = []string{"https://b.example.com"}
	Reassess(r)

	md := RenderVAPTMarkdown(r)
	summary := md
	if i := strings.Index(md, "## Methodology"); i > 0 {
		summary = md[:i] // the executive summary alone
	}
	if !strings.Contains(summary, "b.example.com") {
		t.Errorf("the executive summary states a rating without saying part of the scope was never "+
			"assessed:\n%s", summary)
	}
}
