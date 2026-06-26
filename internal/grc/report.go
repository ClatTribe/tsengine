package grc

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// frameworkTitle maps a framework key to its auditor-facing display name.
var frameworkTitle = map[string]string{
	FrameworkSOC2:       "SOC 2",
	FrameworkISO27001:   "ISO 27001:2022",
	FrameworkPCI:        "PCI-DSS v4.0",
	FrameworkHIPAA:      "HIPAA Security Rule",
	FrameworkCISv8:      "CIS Controls v8",
	FrameworkNISTCSF:    "NIST CSF 2.0",
	FrameworkGDPR:       "EU GDPR",
	FrameworkISO27701:   "ISO 27701:2019",
	FrameworkNIST80053:  "NIST SP 800-53 r5",
	FrameworkNIST800171: "NIST SP 800-171 r2",
	FrameworkCCPA:       "CCPA / CPRA",
	FrameworkSOX:        "SOX (ITGC)",
	FrameworkFedRAMP:    "FedRAMP Moderate",
	FrameworkDPDP:       "India DPDP Act 2023",
}

// FrameworkTitle returns the display name for a framework key (the key itself if unknown).
func FrameworkTitle(framework string) string {
	if t, ok := frameworkTitle[framework]; ok {
		return t
	}
	return framework
}

// Report is the human-readable compliance deliverable — the artifact a tenant hands an
// auditor or a customer. It resolves each gap's evidence finding IDs into titled,
// severity-ranked rows, so a reader sees not just "CC6.1 is a gap" but *why*.
type Report struct {
	TenantID    string
	TenantName  string
	Framework   string // key (soc2)
	Title       string // display (SOC 2)
	GeneratedAt time.Time
	Rows        []ReportRow
	MetCount    int
	GapCount    int
	// Coverage is the honesty layer — how much of the framework automated scanning actually assessed, so
	// a clean posture is never mis-read as a compliance certification (§ no-false-compliant).
	Coverage Coverage
	// Attestation, when the underlying pack was signed.
	Signer string
	SHA256 string
}

// ReportRow is one control's state plus the findings that drove it.
type ReportRow struct {
	ControlID string
	State     string // platform.ControlMet | ControlGap | ControlException
	Gap       bool
	Evidence  []ReportEvidence
}

// ReportEvidence is a resolved citing finding.
type ReportEvidence struct {
	FindingID string
	Title     string
	Severity  types.Severity
}

// Report assembles the compliance report for a framework: control state from the GRC
// posture, with each control's EvidenceRefs resolved into the citing findings.
func (g *GRC) Report(ctx context.Context, tenantID, framework string) (*Report, error) {
	cs, err := g.Posture(ctx, tenantID, framework)
	if err != nil {
		return nil, err
	}
	findings, err := g.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return nil, err
	}
	byID := make(map[string]types.Finding, len(findings))
	for _, f := range findings {
		byID[f.ID] = f
	}

	r := &Report{
		TenantID: tenantID, TenantName: tenantID,
		Framework: framework, Title: FrameworkTitle(framework), GeneratedAt: g.now(),
	}
	if t, terr := g.Store.GetTenant(ctx, tenantID); terr == nil && t.Name != "" {
		r.TenantName = t.Name
	}
	for _, c := range cs {
		row := ReportRow{ControlID: c.ControlID, State: c.State, Gap: c.State == platform.ControlGap}
		for _, ref := range c.EvidenceRefs {
			ev := ReportEvidence{FindingID: ref}
			if f, ok := byID[ref]; ok {
				ev.Title, ev.Severity = f.Title, f.Severity
			}
			row.Evidence = append(row.Evidence, ev)
		}
		// worst severity first within a control
		sort.SliceStable(row.Evidence, func(i, j int) bool {
			return row.Evidence[i].Severity.Rank() < row.Evidence[j].Severity.Rank()
		})
		if row.Gap {
			r.GapCount++
		} else {
			r.MetCount++
		}
		r.Rows = append(r.Rows, row)
	}
	r.Coverage = computeCoverage(framework, g.assessable(framework), r.MetCount, r.GapCount)
	return r, nil
}

// SignedReport builds the report and attaches the attestation from a signed EvidencePack
// over the same posture, so the report carries the auditor's tamper-evident signer/hash.
func (g *GRC) SignedReport(ctx context.Context, tenantID, framework string, pack *EvidencePack) (*Report, error) {
	r, err := g.Report(ctx, tenantID, framework)
	if err != nil {
		return nil, err
	}
	if pack != nil && pack.Attestation != nil {
		r.Signer, r.SHA256 = pack.Attestation.Signer, pack.Attestation.SHA256
	}
	return r, nil
}

// RenderMarkdown renders the report as portable Markdown — the form a tenant attaches to
// an audit or emails a customer. Pure (no I/O), so it is deterministic and testable.
func RenderMarkdown(r *Report) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# %s Compliance Report — %s\n\n", r.Title, r.TenantName)
	fmt.Fprintf(&b, "- **Generated:** %s\n", r.GeneratedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Framework:** %s (`%s`)\n", r.Title, r.Framework)
	cov := r.Coverage
	fmt.Fprintf(&b, "- **Automated assessment coverage:** %d of %d technical controls assessed (%.0f%%) · **Gap:** %d · **Met:** %d · **Not yet assessed:** %d\n",
		cov.AssessedControls, cov.AssessableControls, cov.AutomatedCoveragePct, cov.Gaps, cov.Met, cov.NotAssessed)
	if r.Signer != "" {
		fmt.Fprintf(&b, "- **Signed:** `%s` · sha256 `%s`\n", r.Signer, r.SHA256)
	}
	b.WriteString("\n")
	// The no-false-compliant disclaimer — ALWAYS present, before any "no gaps" line, so a clean automated
	// posture can never be mistaken for a compliance certification.
	b.WriteString("> ⚠️ **This is an automated technical assessment, not a compliance certification.** ")
	fmt.Fprintf(&b, "It covers only the %d control(s) our scanners can evaluate for %s; %d assessable control(s) have no scan evidence yet, and procedural controls (policies, training, vendor management, BCP) require auditor attestation. A clean automated posture does **not** mean you are compliant.\n\n",
		cov.AssessableControls, r.Title, cov.NotAssessed)
	fmt.Fprintf(&b, "**Status:** %s\n\n", cov.Readiness)

	gaps := filterRows(r.Rows, true)
	fmt.Fprintf(&b, "## Gaps (%d)\n\n", len(gaps))
	if len(gaps) == 0 {
		if cov.AssessedControls == 0 {
			b.WriteString("_No controls assessed yet — connect assets and run a scan. This is NOT \"compliant\"._\n\n")
		} else {
			fmt.Fprintf(&b, "_No automated gaps among the %d assessed control(s). The other %d assessable control(s) + all procedural controls still need auditor attestation before this framework can be called compliant._\n\n",
				cov.AssessedControls, cov.NotAssessed)
		}
	}
	for _, row := range gaps {
		fmt.Fprintf(&b, "### %s — GAP\n\n", row.ControlID)
		if len(row.Evidence) == 0 {
			b.WriteString("_No evidence finding on record._\n\n")
			continue
		}
		b.WriteString("Cited by:\n")
		for _, ev := range row.Evidence {
			fmt.Fprintf(&b, "- `%s` — %s (%s)\n", ev.FindingID, evTitle(ev), severityLabel(ev.Severity))
		}
		b.WriteString("\n")
	}

	met := filterRows(r.Rows, false)
	fmt.Fprintf(&b, "## Met (%d)\n\n", len(met))
	for _, row := range met {
		fmt.Fprintf(&b, "- %s\n", row.ControlID)
	}
	if len(met) == 0 {
		b.WriteString("_No controls currently met._\n")
	}
	return b.String()
}

func filterRows(rows []ReportRow, gap bool) []ReportRow {
	var out []ReportRow
	for _, r := range rows {
		if r.Gap == gap {
			out = append(out, r)
		}
	}
	return out
}

func evTitle(ev ReportEvidence) string {
	if ev.Title == "" {
		return "(finding detail unavailable)"
	}
	return ev.Title
}

func severityLabel(s types.Severity) string {
	if s == "" {
		return "unknown"
	}
	return string(s)
}
