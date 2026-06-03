package report

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/llmredteam"
	"github.com/ClatTribe/tsengine/internal/webagent"
	"github.com/ClatTribe/tsengine/pkg/types"
)

var fixedTime = time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

func TestFromScan_Render(t *testing.T) {
	scan := types.Scan{
		ScanID:       "scan-123",
		Asset:        types.Asset{Type: "web_application", Target: "https://shop.example"},
		Engine:       types.Engine{Version: "tsengine 0.4.2"},
		AnchorsFired: []string{"katana", "nuclei", "sqlmap_runner"},
		FindingsEnriched: []types.Finding{
			{
				ID: "f-001", RuleID: "nuclei::sqli", Tool: "nuclei", Severity: types.SeverityHigh,
				Title: "SQL injection in search", Endpoint: "https://shop.example/search?q=",
				CWE: []string{"CWE-89"}, VerificationStatus: types.VerificationVerified,
				Compliance:  &types.Compliance{SOC2: []string{"CC6.1"}, PCI: []string{"6.2.4"}},
				ThreatIntel: &types.ThreatIntel{CVSS: 9.8, KEV: &types.KEVStatus{Listed: true}},
				L2:          &types.L2Report{Remediation: "Use parameterized queries.", KillChain: "attacker → search param → DB"},
			},
			{
				ID: "f-002", RuleID: "nuclei::info-header", Tool: "nuclei", Severity: types.SeverityLow,
				Title: "Missing security header", Endpoint: "https://shop.example/",
			},
		},
		Attestation: &types.Attestation{Signer: "tsengine-prod-key-v1", SHA256: "abc123"},
	}
	r := FromScan(scan, fixedTime)

	if got := r.RiskRating(); got != "High" {
		t.Errorf("risk rating = %q, want High", got)
	}
	if r.Counts()["high"] != 1 || r.Counts()["low"] != 1 {
		t.Errorf("counts = %v", r.Counts())
	}
	// findings sorted: high before low
	if r.Findings[0].Severity != "high" {
		t.Errorf("findings not severity-sorted: %+v", r.Findings)
	}
	if !r.Signed || r.Signer != "tsengine-prod-key-v1" {
		t.Errorf("attestation not carried through")
	}

	md := Markdown(r)
	for _, want := range []string{"# Web Application Penetration Test — https://shop.example", "Executive summary", "SQL injection in search", "CVSS 9.8", "CISA KEV listed", "SOC 2 (CC6.1)", "✓ verified", "scan-123"} {
		if !strings.Contains(md, want) {
			t.Errorf("markdown missing %q", want)
		}
	}
	htmlOut := HTML(r)
	for _, want := range []string{"<!doctype html>", "Web Application Penetration Test", "sev-high", "SQL injection in search", "Remediation", "tsengine-prod-key-v1"} {
		if !strings.Contains(htmlOut, want) {
			t.Errorf("html missing %q", want)
		}
	}
	// XSS safety: the renderer must escape, never emit a raw script tag from data.
	scan.Asset.Target = "<script>alert(1)</script>"
	if strings.Contains(HTML(FromScan(scan, fixedTime)), "<script>alert(1)</script>") {
		t.Error("HTML renderer did not escape target — XSS in the report")
	}
}

func TestFromWebEvidence_Render(t *testing.T) {
	bundle := &webagent.EvidenceBundle{
		Target: "http://127.0.0.1:8771", Engine: "tsengine test",
		Findings: []webagent.EvidenceFinding{
			{
				Finding: webagent.Finding{ID: "web-001", Route: "http://127.0.0.1:8771/product?id=", Class: "sqli", Severity: "high", Verified: true, Rationale: "error-based SQLi"},
				ProvingTurns: []webagent.Turn{
					{ID: "t-001", Method: "GET", URL: "http://127.0.0.1:8771/product?id='", Status: 500, Indicators: []string{"sql_error"}, RespSnippet: "You have an error in your SQL syntax"},
				},
			},
		},
		Attestation: &webagent.EvidenceAttest{Signer: "k", SHA256: "deadbeef"},
	}
	r := FromWebEvidence(bundle, fixedTime)
	if len(r.Findings) != 1 || r.Findings[0].Title != "SQL Injection" {
		t.Fatalf("web evidence not adapted: %+v", r.Findings)
	}
	if r.Findings[0].Status != "verified" {
		t.Errorf("verified status not carried")
	}
	md := Markdown(r)
	if !strings.Contains(md, "sql_error") || !strings.Contains(md, "parameterized queries") {
		t.Errorf("web markdown missing evidence/remediation:\n%s", md)
	}
}

func TestFromLLMRedteam_Render(t *testing.T) {
	rep := &llmredteam.Report{
		Engagement: "llm-07", Turns: 6,
		Breaches: []llmredteam.Breach{
			{ID: "llm-001", Class: "secret_leak", Technique: "roleplay", Severity: "high", Evidence: []string{"t-003"}},
		},
	}
	r := FromLLMRedteam(rep, fixedTime)
	if len(r.Findings) != 1 || r.Findings[0].Title != "Secret / Canary Disclosure" {
		t.Fatalf("llm report not adapted: %+v", r.Findings)
	}
	md := Markdown(r)
	if !strings.Contains(md, "Technique: roleplay") || !strings.Contains(md, "LLM / Agentic Red-Team") {
		t.Errorf("llm markdown wrong:\n%s", md)
	}
}

func TestEmptyReport(t *testing.T) {
	r := FromScan(types.Scan{Asset: types.Asset{Type: "api", Target: "https://api.example"}}, fixedTime)
	if r.RiskRating() != "None" {
		t.Errorf("empty report risk = %q, want None", r.RiskRating())
	}
	if !strings.Contains(Markdown(r), "no exploitable findings") {
		t.Errorf("empty summary wrong")
	}
}
