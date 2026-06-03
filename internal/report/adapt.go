package report

import (
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/llmredteam"
	"github.com/ClatTribe/tsengine/internal/webagent"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// assetKind maps an L1 asset type to a human report kind.
var assetKind = map[string]string{
	"web_application": "Web Application Penetration Test",
	"api":             "API Penetration Test",
	"repository":      "Source Code Security Assessment",
	"container_image": "Container Image Assessment",
	"ip_address":      "Network Infrastructure Assessment",
	"domain":          "External Attack-Surface Assessment",
	"cloud_account":   "Cloud Security Assessment",
}

// humanClass turns an internal vuln/breach class into a report title.
var humanClass = map[string]string{
	"sqli":               "SQL Injection",
	"xss":                "Cross-Site Scripting (XSS)",
	"open_redirect":      "Open Redirect",
	"path_traversal":     "Path Traversal / LFI",
	"command_injection":  "OS Command Injection",
	"secret_leak":        "Secret / Canary Disclosure",
	"system_prompt_leak": "System-Prompt Disclosure",
	"forbidden_tool":     "Unauthorized Tool Invocation",
	"pii_leak":           "PII Disclosure",
}

// webRemediation is canned, class-level fix guidance for web findings.
var webRemediation = map[string]string{
	"sqli":              "Use parameterized queries / prepared statements; never concatenate untrusted input into SQL. Apply least-privilege DB accounts.",
	"xss":               "Context-encode all reflected output; adopt a strict Content-Security-Policy; prefer framework auto-escaping.",
	"open_redirect":     "Validate redirect targets against an allowlist of same-origin paths; never redirect to a host taken from user input.",
	"path_traversal":    "Resolve and canonicalize paths, then confirm they remain within an allowed base directory; reject any input containing traversal sequences.",
	"command_injection": "Avoid shelling out with user input; use library calls or an allowlisted argument vector with no shell interpolation.",
}

func human(class string) string {
	if h, ok := humanClass[strings.ToLower(class)]; ok {
		return h
	}
	return strings.Title(strings.ReplaceAll(class, "_", " ")) //nolint:staticcheck
}

// FromScan adapts an L1 dashboard scan (vulnerabilities.json) into a report. It
// prefers the enriched view (compliance + threat intel + L2 narrative); falls back
// to the raw view.
func FromScan(scan types.Scan, now time.Time) *Report {
	findings := scan.FindingsEnriched
	if len(findings) == 0 {
		findings = scan.FindingsRaw
	}
	kind := assetKind[string(scan.Asset.Type)]
	if kind == "" {
		kind = "Security Assessment"
	}
	r := &Report{
		Title:       kind + " — " + scan.Asset.Target,
		Kind:        kind,
		Target:      scan.Asset.Target,
		GeneratedAt: now.UTC(),
		Engine:      scan.Engine.Version,
		Methodology: defaultMethodology(),
		Meta: map[string]string{
			"scan_id":       scan.ScanID,
			"anchors_fired": strings.Join(scan.AnchorsFired, ", "),
		},
	}
	if scan.Attestation != nil {
		r.Signed = true
		r.Signer = scan.Attestation.Signer
		r.Meta["attestation_sha256"] = scan.Attestation.SHA256
	}
	if scan.Partial {
		r.Meta["partial"] = "true (scan stopped early: " + scan.StopReason + ")"
	}
	for _, f := range findings {
		r.Findings = append(r.Findings, fromScanFinding(f))
	}
	r.sortFindings()
	r.Summary = r.autoSummary()
	return r
}

func fromScanFinding(f types.Finding) Finding {
	rf := Finding{
		ID: f.ID, Title: f.Title, Severity: string(f.Severity), Status: string(f.VerificationStatus),
		Endpoint: f.Endpoint, Tool: f.Tool, Description: f.Description, CWE: f.CWE,
	}
	if rf.Title == "" {
		rf.Title = f.RuleID
	}
	rf.Evidence = append(rf.Evidence, fmt.Sprintf("Detected by %s (%s)", f.Tool, f.RuleID))
	if f.ThreatIntel != nil {
		rf.ThreatIntel = threatIntelLine(f.ThreatIntel)
	}
	if f.Compliance != nil {
		rf.Compliance = complianceMap(f.Compliance)
	}
	if f.L2 != nil {
		if f.L2.KillChain != "" {
			rf.Evidence = append(rf.Evidence, "Kill chain: "+f.L2.KillChain)
		}
		if f.L2.PlainEnglish != "" && rf.Description == "" {
			rf.Description = f.L2.PlainEnglish
		}
		rf.Remediation = f.L2.Remediation
	}
	return rf
}

func threatIntelLine(ti *types.ThreatIntel) string {
	var p []string
	if ti.CVSS > 0 {
		p = append(p, fmt.Sprintf("CVSS %.1f", ti.CVSS))
	}
	if ti.KEV != nil && ti.KEV.Listed {
		p = append(p, "CISA KEV listed")
	}
	if ti.EPSS != nil {
		p = append(p, fmt.Sprintf("EPSS %.2f (p%.0f)", ti.EPSS.Score, ti.EPSS.Percentile*100))
	}
	return strings.Join(p, " · ")
}

func complianceMap(c *types.Compliance) map[string][]string {
	m := map[string][]string{}
	add := func(k string, v []string) {
		if len(v) > 0 {
			m[k] = v
		}
	}
	add("SOC 2", c.SOC2)
	add("PCI-DSS", c.PCI)
	add("HIPAA", c.HIPAA)
	add("CIS v8", c.CISv8)
	add("NIST CSF", c.NISTCSF)
	add("ISO 27001", c.ISO27001)
	if len(m) == 0 {
		return nil
	}
	return m
}

// FromWebEvidence adapts a web agent signed evidence bundle into a report.
func FromWebEvidence(b *webagent.EvidenceBundle, now time.Time) *Report {
	r := &Report{
		Title:       "Web Application Penetration Test — " + b.Target,
		Kind:        "Web Application Penetration Test",
		Target:      b.Target,
		GeneratedAt: now.UTC(),
		Engine:      b.Engine,
		Summary:     b.Summary,
		Methodology: defaultMethodology(),
		Meta:        map[string]string{},
	}
	if b.Attestation != nil {
		r.Signed = true
		r.Signer = b.Attestation.Signer
		r.Meta["attestation_sha256"] = b.Attestation.SHA256
	}
	for _, ef := range b.Findings {
		f := Finding{
			ID: ef.ID, Title: human(ef.Class), Severity: nz(ef.Severity, "high"),
			Endpoint: ef.Route, Description: ef.Rationale, Tool: "webagent",
			Status: "pattern_match", Remediation: webRemediation[strings.ToLower(ef.Class)],
		}
		if ef.Verified {
			f.Status = "verified"
		}
		for _, t := range ef.ProvingTurns {
			line := fmt.Sprintf("%s %s → status %d, indicators [%s]", t.Method, t.URL, t.Status, strings.Join(t.Indicators, ", "))
			f.Evidence = append(f.Evidence, line)
			if t.RespSnippet != "" {
				f.Evidence = append(f.Evidence, "response: "+t.RespSnippet)
			}
		}
		r.Findings = append(r.Findings, f)
	}
	r.sortFindings()
	r.Summary = r.autoSummary()
	return r
}

// FromLLMRedteam adapts an LLM red-team report into a report.
func FromLLMRedteam(rep *llmredteam.Report, now time.Time) *Report {
	r := &Report{
		Title:       "LLM Red-Team Assessment — " + rep.Engagement,
		Kind:        "LLM / Agentic Red-Team Assessment",
		Target:      rep.Engagement,
		GeneratedAt: now.UTC(),
		Summary:     rep.Summary,
		Methodology: llmMethodology(),
		Meta:        map[string]string{"prompts_sent": itoa(rep.Turns)},
	}
	for _, b := range rep.Breaches {
		f := Finding{
			ID: b.ID, Title: human(b.Class), Severity: nz(b.Severity, "high"),
			Description: nz(b.Rationale, "Confirmed by the deterministic verifier."), Tool: "llmredteam",
			Status: "verified", Endpoint: rep.Engagement,
		}
		if b.Technique != "" {
			f.Evidence = append(f.Evidence, "Technique: "+b.Technique)
		}
		if len(b.Evidence) > 0 {
			f.Evidence = append(f.Evidence, "Proven on turns: "+strings.Join(b.Evidence, ", "))
		}
		f.Remediation = "Harden the system prompt, enforce output filtering for canaries/PII, and gate tool invocation behind explicit authorization."
		r.Findings = append(r.Findings, f)
	}
	r.sortFindings()
	r.Summary = r.autoSummary()
	return r
}

func nz(s, def string) string {
	if strings.TrimSpace(s) == "" {
		return def
	}
	return s
}

func defaultMethodology() []string {
	return []string{
		"Automated discovery of the in-scope surface (recon + crawl).",
		"Tool-driven detection across the relevant vulnerability classes.",
		"Autonomous agent triage: each candidate is probed and only recorded when a deterministic indicator confirms it (evidence-grounded — no unverified claims).",
		"Confirmation: high-impact findings are re-tested in isolation to eliminate false positives.",
	}
}

func llmMethodology() []string {
	return []string{
		"Multi-turn adversarial prompting (jailbreak, system-prompt extraction, indirect injection, tool-abuse).",
		"Deterministic verification: a breach is recorded only when the target's own output trips a planted tripwire (canary/sentinel leak, forbidden-tool firing, PII disclosure).",
		"No asserted successes — every breach is provable from the transcript.",
	}
}
