package grc

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// VAPTReport is the customer-facing Vulnerability Assessment & Penetration Test deliverable
// — the artifact an SMB hands an enterprise customer, insurer, or auditor in a security
// review ("do you have a recent pentest?"). It is built ENTIRELY from grounded scan findings
// (CLAUDE.md §10): every entry cites the tool + evidence that backs it, so nothing is
// asserted that a tool did not prove. This is the deterministic, evidence-grounded analogue
// of a manual pentest report — continuously regenerable, never stale.
type VAPTReport struct {
	TenantName  string        `json:"tenant_name"`
	GeneratedAt time.Time     `json:"generated_at"`
	Engine      string        `json:"engine"`
	Scope       []string      `json:"scope"` // the monitored asset targets assessed
	Summary     VAPTSummary   `json:"summary"`
	Findings    []VAPTFinding `json:"findings"` // worst-severity first
	// Attestation, when the report is signed (same scheme as the evidence pack).
	Signer string `json:"signer,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// VAPTSummary is the executive-summary roll-up.
type VAPTSummary struct {
	Total      int            `json:"total"`
	BySeverity map[string]int `json:"by_severity"` // critical/high/medium/low/info
	Verified   int            `json:"verified"`    // exploitation/tool-confirmed (not pattern-only)
	KEV        int            `json:"kev"`         // actively exploited in the wild (CISA KEV)
	FixesReady int            `json:"fixes_ready"` // findings with a remediation already prepared
	RiskRating string         `json:"risk_rating"` // Critical | High | Medium | Low | Clear
}

// VAPTFinding is one assessed vulnerability, grounded in its scanner evidence.
type VAPTFinding struct {
	ID           string   `json:"id"`
	Title        string   `json:"title"`
	Severity     string   `json:"severity"`
	CVSS         float64  `json:"cvss,omitempty"`
	Tool         string   `json:"tool"`    // the scanner that found it (evidence)
	RuleID       string   `json:"rule_id"` // the specific check
	Endpoint     string   `json:"endpoint,omitempty"`
	CWE          []string `json:"cwe,omitempty"`
	MITRE        []string `json:"mitre,omitempty"`
	Description  string   `json:"description,omitempty"`
	OWASP        []string `json:"owasp,omitempty"`        // OWASP Top 10 (2021) category mapping
	Remediation  string   `json:"remediation,omitempty"`  // the recommended fix (CWE-class standard)
	Verification string   `json:"verification,omitempty"` // verified | corroborated | pattern_match
	KEV          bool     `json:"kev,omitempty"`          // actively exploited
	FixReady     bool     `json:"fix_ready,omitempty"`    // a remediation is prepared/queued
}

// VAPTReport assembles the report for a tenant from its current findings + monitored assets.
func (g *GRC) VAPTReport(ctx context.Context, tenantID string) (*VAPTReport, error) {
	findings, err := g.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return nil, err
	}
	assets, err := g.Store.ListAssets(ctx, tenantID)
	if err != nil {
		return nil, err
	}
	pending, _ := g.Store.PendingApprovals(ctx, tenantID) // best-effort: fixes-ready signal
	fixReady := make(map[string]bool, len(pending))
	for _, a := range pending {
		if a.FindingID != "" {
			fixReady[a.FindingID] = true
		}
	}

	r := &VAPTReport{
		TenantName: tenantID, GeneratedAt: g.now(), Engine: "tsengine (TensorShield)",
		Summary: VAPTSummary{BySeverity: map[string]int{}},
	}
	if t, terr := g.Store.GetTenant(ctx, tenantID); terr == nil && t.Name != "" {
		r.TenantName = t.Name
	}
	for _, a := range assets {
		if a.Target != "" {
			r.Scope = append(r.Scope, a.Target)
		}
	}

	for _, f := range findings {
		sev := string(f.Severity)
		r.Summary.Total++
		r.Summary.BySeverity[sev]++
		if isVerified(f) {
			r.Summary.Verified++
		}
		kev := f.ThreatIntel != nil && f.ThreatIntel.KEV != nil
		if kev {
			r.Summary.KEV++
		}
		if fixReady[f.ID] {
			r.Summary.FixesReady++
		}
		vf := VAPTFinding{
			ID: f.ID, Title: f.Title, Severity: sev, Tool: f.Tool, RuleID: f.RuleID,
			Endpoint: f.Endpoint, CWE: f.CWE, MITRE: f.MITRETechniques, Description: f.Description,
			OWASP: owaspFor(f.CWE, f.Tool), Remediation: remediationFor(f.CWE, f.Tool),
			Verification: string(f.VerificationStatus), KEV: kev, FixReady: fixReady[f.ID],
		}
		if f.ThreatIntel != nil {
			vf.CVSS = f.ThreatIntel.CVSS
		}
		r.Findings = append(r.Findings, vf)
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		ri, rj := types.Severity(r.Findings[i].Severity).Rank(), types.Severity(r.Findings[j].Severity).Rank()
		if ri != rj {
			return ri > rj // higher rank = worse severity → worst first
		}
		return r.Findings[i].ID < r.Findings[j].ID
	})
	r.Summary.RiskRating = vaptRisk(r.Summary.BySeverity)
	return r, nil
}

func isVerified(f types.Finding) bool {
	return f.VerificationStatus == "verified" || f.VerificationStatus == "corroborated"
}

// vaptRisk derives an overall risk rating from the severity mix (matches the dashboard's
// owner-facing rating model: any critical → Critical, etc.).
func vaptRisk(by map[string]int) string {
	switch {
	case by["critical"] > 0:
		return "Critical"
	case by["high"] > 0:
		return "High"
	case by["medium"] > 0:
		return "Medium"
	case by["low"] > 0 || by["info"] > 0:
		return "Low"
	default:
		return "Clear"
	}
}

// RenderVAPTMarkdown renders the report as portable Markdown — the form an SMB attaches to a
// security questionnaire or emails a customer. Pure (no I/O), so it is deterministic + testable.
func RenderVAPTMarkdown(r *VAPTReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Vulnerability Assessment & Penetration Test — %s\n\n", r.TenantName)
	fmt.Fprintf(&b, "- **Generated:** %s\n", r.GeneratedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Assessed by:** %s — continuous automated assessment\n", r.Engine)
	if r.Signer != "" {
		fmt.Fprintf(&b, "- **Signed:** `%s` · sha256 `%s`\n", r.Signer, r.SHA256)
	}
	b.WriteString("\n## Executive summary\n\n")
	s := r.Summary
	fmt.Fprintf(&b, "- **Overall risk rating: %s**\n", s.RiskRating)
	fmt.Fprintf(&b, "- **%d findings** — Critical %d · High %d · Medium %d · Low %d · Info %d\n",
		s.Total, s.BySeverity["critical"], s.BySeverity["high"], s.BySeverity["medium"], s.BySeverity["low"], s.BySeverity["info"])
	fmt.Fprintf(&b, "- **%d tool-confirmed** (verified/corroborated, not pattern-only) · **%d actively exploited** (CISA KEV) · **%d with a fix already prepared**\n",
		s.Verified, s.KEV, s.FixesReady)
	b.WriteString("\n" + narrativeSummary(r) + "\n")
	b.WriteString("\n## Methodology\n\n")
	b.WriteString("Assessment is performed by the TensorShield engine, which wraps best-in-class open-source " +
		"scanners across every asset class (web, API, code, containers, cloud, identity) and verifies exploitable " +
		"findings through an evidence-grounded agent. **Every finding below cites the tool and rule that proves it** — " +
		"no result is asserted that a tool did not demonstrate (anti-hallucination grounding). The assessment is " +
		"continuous, so this report reflects the current state, not a point-in-time snapshot.\n\n")

	b.WriteString("## Scope\n\n")
	if len(r.Scope) == 0 {
		b.WriteString("_No assets in scope yet — connect a system to begin the assessment._\n\n")
	} else {
		for _, t := range r.Scope {
			fmt.Fprintf(&b, "- `%s`\n", t)
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Findings (%d)\n\n", len(r.Findings))
	if len(r.Findings) == 0 {
		b.WriteString("_No open vulnerabilities — every monitored asset is currently clean._\n")
		return b.String()
	}
	for _, f := range r.Findings {
		fmt.Fprintf(&b, "### [%s] %s\n\n", strings.ToUpper(f.Severity), f.Title)
		fmt.Fprintf(&b, "- **Tool / rule:** `%s` · `%s`\n", f.Tool, f.RuleID)
		if f.Endpoint != "" {
			fmt.Fprintf(&b, "- **Location:** `%s`\n", f.Endpoint)
		}
		if len(f.CWE) > 0 {
			fmt.Fprintf(&b, "- **CWE:** %s\n", strings.Join(f.CWE, ", "))
		}
		if len(f.OWASP) > 0 {
			fmt.Fprintf(&b, "- **OWASP Top 10:** %s\n", strings.Join(f.OWASP, "; "))
		}
		if len(f.MITRE) > 0 {
			fmt.Fprintf(&b, "- **MITRE ATT&CK:** %s\n", strings.Join(f.MITRE, ", "))
		}
		if f.CVSS > 0 {
			fmt.Fprintf(&b, "- **CVSS:** %.1f\n", f.CVSS)
		}
		status := f.Verification
		if status == "" {
			status = "detected"
		}
		if f.KEV {
			status += " · **actively exploited (CISA KEV)**"
		}
		fmt.Fprintf(&b, "- **Evidence strength:** %s\n", status)
		if f.Description != "" {
			fmt.Fprintf(&b, "\n%s\n", f.Description)
		}
		if f.Remediation != "" {
			fmt.Fprintf(&b, "\n**Recommended fix:** %s", f.Remediation)
			if f.FixReady {
				b.WriteString(" _(TensorShield has already prepared this fix — it's awaiting your approval.)_")
			}
			b.WriteString("\n")
		}
		b.WriteString("\n")
	}
	return b.String()
}
