package grc

import (
	"fmt"
	"html/template"
	"strings"
	"time"
)

// Print-ready HTML rendering of the VAPT report — the form a customer actually FORWARDS.
//
// The Markdown renderer is the developer/remediation deliverable, but the artifact an SMB
// attaches to a security questionnaire, emails an insurer, or hands a procurement team is a
// PDF. This produces a self-contained, print-optimised HTML document the customer saves as
// PDF from their own browser (Cmd/Ctrl-P → Save as PDF).
//
// WHY NOT GENERATE THE PDF SERVER-SIDE. Both options cost more than they return here. A Go PDF
// library means hand-laying out a paginated document (and a new dependency whose output we would
// then own); driving headless Chrome via the chromedp we already vendor means the platform image
// must CARRY Chrome — roughly a 10x size increase on a ~108MB image — and a report download that
// fails whenever the browser is missing from the container. The browser the customer already has
// is the best PDF renderer available, it is already on their machine, and this path cannot fail
// for want of a binary on ours. `@page` gives us the margins, page breaks and print fidelity that
// were the actual reason to want PDF.
//
// SECURITY: THE REPORT CARRIES ATTACKER-CONTROLLED TEXT. Finding titles, endpoints, descriptions
// and captured PoC payloads come from scanner output and from probes fired at a target the
// attacker may control — a stored `<script>` in a URL parameter or a reflected-XSS PoC is
// EXPECTED content here, not an edge case. Rendered unescaped, the vulnerability report would
// execute the payload it is reporting, in the browser of the customer, auditor or insurer who
// opened it — a security product shipping an XSS vector as its deliverable. This file therefore
// renders through html/template, which escapes by default, and the one place that emits markup
// (inlineMarkup) escapes BEFORE it converts. Never switch this to text/template or fmt-built
// HTML, and never mark a finding-derived value template.HTML.

// vaptHTMLTemplate is the whole document — self-contained (inline CSS, no external asset, no
// script), so it renders identically from a downloaded file, an email attachment, or a browser tab.
var vaptHTMLTemplate = template.Must(template.New("vapt").Funcs(template.FuncMap{
	"inline":  inlineMarkup,
	"pct":     func(f float64) string { return fmt.Sprintf("%.0f%%", f*100) },
	"pct1":    func(f float64) string { return fmt.Sprintf("%.1f%%", f*100) },
	"cvss":    func(f float64) string { return fmt.Sprintf("%.1f", f) },
	"date":    func(t time.Time) string { return t.UTC().Format("2006-01-02") },
	"rfc":     func(t time.Time) string { return t.UTC().Format(time.RFC3339) },
	"upper":   strings.ToUpper,
	"notZero": func(t time.Time) bool { return !t.IsZero() },
	"join":    func(s []string) string { return strings.Join(s, ", ") },
	"sevClass": func(s string) string {
		switch strings.ToLower(s) {
		case "critical", "high", "medium", "low":
			return "sev-" + strings.ToLower(s)
		default:
			return "sev-info"
		}
	},
	"has":         func(m map[string]bool, k string) bool { return m[k] },
	"vectorProse": cvssVectorProse,
}).Parse(vaptHTMLSource))

const vaptHTMLSource = `<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VAPT Report — {{.Report.TenantName}}</title>
<style>
  /* Print geometry. The margins and page-break rules are the reason this is HTML-for-print
     rather than a screen page: a finding split across a page boundary is the single thing that
     makes an automated report look automated. */
  @page { size: A4; margin: 16mm 14mm 18mm 14mm; }
  @media print {
    .no-print { display: none !important; }
    .finding, .cover-block { break-inside: avoid; page-break-inside: avoid; }
    h2 { break-after: avoid; page-break-after: avoid; }
    a { text-decoration: none; color: inherit; }
  }
  :root {
    --ink:#111827; --muted:#6b7280; --line:#e5e7eb; --bg:#fff;
    --crit:#b91c1c; --high:#c2410c; --med:#a16207; --low:#2563eb; --info:#6b7280;
    --ok:#15803d;
  }
  * { box-sizing:border-box; }
  body { margin:0; background:var(--bg); color:var(--ink);
    font:14px/1.55 -apple-system,BlinkMacSystemFont,"Segoe UI",Inter,Roboto,Helvetica,Arial,sans-serif;
    -webkit-print-color-adjust:exact; print-color-adjust:exact; }
  .page { max-width: 860px; margin: 0 auto; padding: 28px 24px 48px; }
  h1 { font-size:26px; line-height:1.2; margin:0 0 6px; letter-spacing:-.01em; }
  h2 { font-size:17px; margin:30px 0 10px; padding-bottom:6px; border-bottom:1px solid var(--line); }
  h3 { font-size:14.5px; margin:0 0 8px; }
  p { margin:0 0 10px; }
  code { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12.5px;
    background:#f3f4f6; padding:1px 5px; border-radius:4px; word-break:break-all; }
  pre { font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace; font-size:12px;
    background:#f9fafb; border:1px solid var(--line); border-left:3px solid var(--ok);
    border-radius:6px; padding:10px 12px; overflow-x:auto; white-space:pre-wrap; word-break:break-word; margin:8px 0; }
  ul { margin:0 0 10px; padding-left:18px; } li { margin:3px 0; }
  .muted { color:var(--muted); }
  .banner { background:#eff6ff; border:1px solid #bfdbfe; color:#1e3a8a; border-radius:8px;
    padding:10px 14px; font-size:13px; margin-bottom:22px; }
  .meta { color:var(--muted); font-size:12.5px; margin:0 0 2px; }
  .rating { display:inline-block; margin:14px 0 2px; padding:8px 16px; border-radius:8px;
    font-size:15px; font-weight:700; color:#fff; }
  .kv { margin:14px 0 0; padding:0; list-style:none; }
  .kv li { margin:4px 0; }
  .pill { display:inline-block; font-size:11px; font-weight:700; letter-spacing:.03em;
    padding:2px 8px; border-radius:999px; color:#fff; vertical-align:middle; }
  .sev-critical{background:var(--crit)} .sev-high{background:var(--high)}
  .sev-medium{background:var(--med)} .sev-low{background:var(--low)} .sev-info{background:var(--info)}
  .flag { display:inline-block; font-size:11px; font-weight:600; padding:2px 7px; border-radius:5px;
    border:1px solid var(--line); background:#f9fafb; color:var(--ink); margin:0 4px 4px 0; }
  .flag-danger { border-color:#fecaca; background:#fef2f2; color:var(--crit); }
  .flag-proven { border-color:#bbf7d0; background:#f0fdf4; color:var(--ok); }
  .flag-warn { border-color:#fed7aa; background:#fff7ed; color:var(--high); }
  .finding { border:1px solid var(--line); border-radius:10px; padding:14px 16px; margin:0 0 12px; }
  .finding.crit { border-left:4px solid var(--crit); }
  .finding.hi { border-left:4px solid var(--high); }
  .step { background:#fcfcfd; }
  .stepno { display:inline-grid; place-items:center; width:22px; height:22px; border-radius:50%;
    background:var(--ink); color:#fff; font-size:12px; font-weight:700; flex:none; }
  .fhead { display:flex; align-items:baseline; gap:8px; margin-bottom:8px; }
  .ftitle { font-size:14.5px; font-weight:650; }
  .facts { margin:0 0 8px; padding:0; list-style:none; font-size:12.5px; color:#374151; }
  .facts li { margin:2px 0; }
  .facts b { color:var(--ink); font-weight:600; }
  .fix { background:#f9fafb; border:1px solid var(--line); border-radius:6px; padding:9px 12px;
    font-size:13px; margin-top:8px; }
  .caveat { background:#fef2f2; border:1px solid #fecaca; color:#7f1d1d; border-radius:8px;
    padding:11px 14px; font-size:13px; margin:14px 0 0; }
  .foot { margin-top:34px; padding-top:12px; border-top:1px solid var(--line);
    font-size:11.5px; color:var(--muted); }
</style></head><body><div class="page">

<div class="banner no-print">
  <b>Save as PDF:</b> press <b>Ctrl&nbsp;+&nbsp;P</b> (<b>⌘&nbsp;+&nbsp;P</b> on Mac) and choose
  “Save as PDF”. This notice is not printed.
</div>

<div class="cover-block">
  <h1>Vulnerability Assessment &amp; Penetration Test</h1>
  <p class="meta"><b>{{.Report.TenantName}}</b></p>
  <p class="meta">Generated {{rfc .Report.GeneratedAt}}</p>
  <p class="meta">Assessed by {{.Report.Engine}} — continuous automated assessment</p>
  {{if .Report.Signer}}<p class="meta">Signed off by {{.Report.Signer}}{{if .Report.SHA256}} · sha256 <code>{{.Report.SHA256}}</code>{{end}}</p>{{end}}
  <div class="rating {{sevClass .RatingClass}}">Overall risk rating: {{.Report.Summary.RiskRating}}</div>
</div>

<h2>Executive summary</h2>
<ul class="kv">
  <li><b>{{.S.Total}} findings</b> — Critical {{.Sev.critical}} · High {{.Sev.high}} · Medium {{.Sev.medium}} · Low {{.Sev.low}} · Info {{.Sev.info}}</li>
  <li><b>{{.S.ExploitProven}} exploitation-proven</b> (strongest evidence tier — a benign proof-of-concept is captured for each)
      · <b>{{.S.Verified}} tool-confirmed</b> · <b>{{.S.Unconfirmed}} unconfirmed</b> (pattern-match — validate before action)
      · <b>{{.S.KEV}} actively exploited</b> (CISA KEV) · <b>{{.S.FixesReady}} with a fix already prepared</b></li>
  {{if .SCATotal}}<li><b>Dependency patchability:</b> {{.S.PatchAvailable}} of {{.SCATotal}} dependency findings have an upstream fix you can upgrade to now; {{.S.PatchUnavailable}} have no fix available yet (mitigate)</li>{{end}}
  {{if .S.Ransomware}}<li><b>{{.S.Ransomware}} ransomware-linked</b> — CISA marks the CVE used in ransomware campaigns, a stronger signal than KEV listing</li>{{end}}
  {{if .S.Automatable}}<li><b>{{.S.Automatable}} automatable</b> — CISA assesses an attacker can automate exploitation, so these scale across an estate rather than costing effort per target</li>{{end}}
  {{if .HasRetest}}<li><b>Fix verification:</b> {{.S.RetestConfirmed}} applied {{if eq .S.RetestConfirmed 1}}fix{{else}}fixes{{end}} re-tested and confirmed closed on re-scan; {{.S.RetestStillPresent}} still present after the fix</li>{{end}}
</ul>
<p>{{inline .Narrative}}</p>
{{if .IntelCaveat}}<div class="caveat">{{inline .IntelCaveat}}</div>{{end}}

<h2>Methodology &amp; confidence</h2>
<p>Assessment is performed by the TensorShield engine, which wraps best-in-class open-source scanners
across every asset class (web, API, code, containers, cloud, identity) and verifies exploitable findings
through an evidence-grounded agent. <b>Every finding below cites the tool and rule that proves it</b> — no
result is asserted that a tool did not demonstrate (anti-hallucination grounding). The assessment is
continuous, so this report reflects the current state, not a point-in-time snapshot.</p>
<ul>
  <li><b>Confirmed</b> — independently corroborated by ≥1 other tool, or actively re-verified. Treat as real.</li>
  <li><b>Unconfirmed</b> — a single-tool pattern match. A credible lead to validate, not a proven exploit — listed
      after the confirmed findings of the same severity and labelled inline, so a false positive can never
      masquerade as a confirmed result.</li>
</ul>
{{if .IntelLine}}<p>{{inline .IntelLine}}</p>{{end}}

<h2>Scope</h2>
{{if not .Report.Scope}}<p class="muted"><i>No assets in scope yet — connect a system to begin the assessment.</i></p>
{{else}}<ul>
{{range .Scope}}<li><code>{{.Target}}</code>{{if .Untested}} — <b>not assessed</b> (no scan has run against this target){{else if .Partial}} — <b>partially assessed</b> (the last scan lost one or more tools; what they would have found is not represented here){{end}}</li>
{{end}}</ul>{{end}}

{{if .Report.Roadmap}}
<h2>Remediation plan</h2>
<p>The findings below, grouped into the changes that fix them and ordered by what to do first.
Priority is set by evidence of real exploitability (a captured proof-of-concept, then CISA’s
actively-exploited catalogue) ahead of severity alone, so proven risk outranks theoretical worst
case. Unconfirmed leads are listed last — validate them before spending effort. <b>No effort or
time estimates are given: we cannot see your codebase, release process, or team, and an invented
estimate is the one number in this report that nothing would support.</b></p>
{{range .Report.Roadmap}}
<div class="finding step">
  <div class="fhead">
    <span class="stepno">{{.Order}}</span>
    <span class="pill {{sevClass .Severity}}">{{upper .Severity}}</span>
    <span class="ftitle">{{.Title}}</span>
  </div>
  <ul class="facts">
    <li><b>Closes:</b> {{.Closes}} {{if eq .Closes 1}}finding{{else}}findings{{end}}{{if .FixReady}} · <b>fix prepared, awaiting approval</b>{{end}}</li>
    {{if .Why}}<li><b>Why here:</b> {{join .Why}}</li>{{end}}
    {{if .Where}}<li><b>Where:</b> {{range .Where}}<code>{{.}}</code> {{end}}</li>{{end}}
    {{if .Action}}<li><b>Fix:</b> {{.Action}}</li>{{end}}
    <li class="muted"><b>Resolves:</b> {{join .Findings}}</li>
  </ul>
</div>
{{end}}
{{end}}

<h2>Findings ({{len .Report.Findings}})</h2>
{{if not .Report.Findings}}<p class="muted"><i>{{inline .EmptyNote}}</i></p>{{end}}
{{range .Report.Findings}}
<div class="finding{{if eq .Severity "critical"}} crit{{else if eq .Severity "high"}} hi{{end}}">
  <div class="fhead"><span class="pill {{sevClass .Severity}}">{{upper .Severity}}</span><span class="ftitle">{{.Title}}</span></div>
  <div>
    {{if .PoC}}<span class="flag flag-proven">✓ exploitation-proven</span>{{end}}
    {{if .Unconfirmed}}<span class="flag flag-warn">unconfirmed — validate before action</span>{{end}}
    {{if .KEV}}<span class="flag flag-danger">actively exploited (CISA KEV)</span>{{end}}
    {{if .Ransomware}}<span class="flag flag-danger">ransomware-linked (CISA)</span>{{end}}
    {{if .WeaponRank}}<span class="flag flag-warn">weaponized: {{.WeaponRank}} (Metasploit)</span>{{end}}
    {{if .PublicExploit}}<span class="flag flag-warn">public exploit available</span>{{end}}
    {{if .SSVCExploitation}}<span class="flag flag-danger">CISA SSVC exploitation: {{.SSVCExploitation}}</span>{{end}}
    {{/* Stated either way: the NO is what separates two otherwise identical findings. */}}
    {{if eq .SSVCAutomatable "yes"}}<span class="flag flag-warn">automatable (CISA SSVC)</span>
    {{else if .SSVCAutomatable}}<span class="flag">not automatable (CISA SSVC)</span>{{end}}
    {{if eq .SSVCImpact "total"}}<span class="flag">SSVC impact: total</span>{{end}}
    {{if .FixReady}}<span class="flag">fix prepared — awaiting approval</span>{{end}}
  </div>
  <ul class="facts">
    <li><b>Tool / rule:</b> <code>{{.Tool}}</code> · <code>{{.RuleID}}</code></li>
    {{if .Endpoint}}<li><b>Location:</b> <code>{{.Endpoint}}</code></li>{{end}}
    {{if .CWE}}<li><b>CWE:</b> {{join .CWE}}</li>{{end}}
    {{if .OWASP}}<li><b>OWASP Top 10:</b> {{join .OWASP}}</li>{{end}}
    {{if .MITRE}}<li><b>MITRE ATT&amp;CK:</b> {{join .MITRE}}</li>{{end}}
    {{if .CVSS}}<li><b>CVSS:</b> {{cvss .CVSS}}{{if .CVSSVector}} (<code>{{.CVSSVector}}</code>){{end}}{{if .CVSSVector}}{{$prose := vectorProse .CVSSVector}}{{if $prose}}<br><span class="muted">{{$prose}}</span>{{end}}{{end}}</li>{{end}}
    {{if .EPSS}}<li><b>EPSS:</b> {{pct1 .EPSS}} exploit probability (FIRST.org)</li>{{end}}
    {{if notZero .KEVDueDate}}<li><b>CISA remediation deadline (BOD 22-01):</b> {{date .KEVDueDate}}</li>{{end}}
    <li><b>Evidence strength:</b> {{if .Verification}}{{.Verification}}{{else}}detected{{end}}{{if .Confidence}} · confidence {{pct .Confidence}}{{end}}</li>
    {{if notZero .DiscoveredAt}}<li><b>First observed:</b> {{date .DiscoveredAt}}</li>{{end}}
  </ul>
  {{if .Description}}<p>{{inline .Description}}</p>{{end}}
  {{/* The PoC is EVIDENCE and stays verbatim in <pre> — never run through inline, which would
       eat backticks/asterisks that are part of the actual payload. */}}
  {{if .PoC}}<div><b>Reproducible proof of concept:</b><pre>{{.PoC}}</pre></div>{{end}}
  {{if .Remediation}}<div class="fix"><b>Recommended fix:</b> {{.Remediation}}</div>{{end}}
</div>
{{end}}

<div class="foot">
  {{.Report.TenantName}} · generated {{rfc .Report.GeneratedAt}} by {{.Report.Engine}}.
  Every finding is grounded in the scanner evidence cited against it.
</div>
</div></body></html>`

// vaptHTMLScopeRow is one scope line with its assessment state resolved for the template.
type vaptHTMLScopeRow struct {
	Target   string
	Untested bool
	Partial  bool
}

// vaptHTMLView is the template's data — a thin view-model so the template holds no logic that
// belongs in Go (and so the honesty rules stay in one place, shared with the Markdown renderer).
type vaptHTMLView struct {
	Report      *VAPTReport
	S           VAPTSummary
	Sev         map[string]int
	Scope       []vaptHTMLScopeRow
	SCATotal    int
	HasRetest   bool
	Narrative   string
	EmptyNote   string
	RatingClass string
	// IntelCaveat / IntelLine mirror the Markdown renderer's intel-provenance disclosure, so the
	// print deliverable cannot quietly drop the caveat the other medium carries.
	IntelCaveat string
	IntelLine   string
}

// RenderVAPTHTML renders the report as a self-contained, print-ready HTML document — the form a
// customer saves as PDF and forwards. Same grounded data and the same honesty rules as
// RenderVAPTMarkdown (untested scope named inline, unconfirmed findings labelled, no rating over
// an unassessed estate); a different medium, not different claims. Pure (no I/O).
func RenderVAPTHTML(r *VAPTReport) string {
	if r == nil {
		return ""
	}
	sev := map[string]int{}
	for _, k := range []string{"critical", "high", "medium", "low", "info"} {
		sev[k] = r.Summary.BySeverity[k]
	}
	untested := map[string]bool{}
	for _, t := range r.Untested {
		untested[t] = true
	}
	partial := map[string]bool{}
	for _, t := range r.PartiallyAssessed {
		partial[t] = true
	}
	rows := make([]vaptHTMLScopeRow, 0, len(r.Scope))
	for _, t := range r.Scope {
		rows = append(rows, vaptHTMLScopeRow{Target: t, Untested: untested[t], Partial: partial[t]})
	}
	v := vaptHTMLView{
		Report: r, S: r.Summary, Sev: sev, Scope: rows,
		SCATotal:    r.Summary.PatchAvailable + r.Summary.PatchUnavailable,
		HasRetest:   r.Summary.RetestConfirmed > 0 || r.Summary.RetestStillPresent > 0,
		Narrative:   narrativeSummary(r),
		RatingClass: ratingClass(r.Summary.RiskRating),
		IntelCaveat: r.Intel.IntelCaveat(),
		IntelLine:   RenderIntelProvenance(r.Intel),
	}
	if len(r.Findings) == 0 {
		v.EmptyNote = emptyFindingsNote(r)
	}
	var b strings.Builder
	if err := vaptHTMLTemplate.Execute(&b, v); err != nil {
		// A template failure must not hand the customer a half-written report.
		return ""
	}
	return b.String()
}

// ratingClass maps the risk rating to the severity palette. "Not assessed" deliberately takes the
// neutral info colour: it is the ABSENCE of a verdict, and colouring it green would restate the
// all-clear the rating exists to withhold.
func ratingClass(rating string) string {
	switch strings.ToLower(rating) {
	case "critical":
		return "critical"
	case "high":
		return "high"
	case "medium":
		return "medium"
	case "low":
		return "low"
	default: // Clear | Not assessed
		return "info"
	}
}

// emptyFindingsNote is the no-findings line, kept identical in wording to the Markdown renderer's
// so the two media cannot drift on the one sentence where a silence must not read as an all-clear.
func emptyFindingsNote(r *VAPTReport) string {
	switch {
	case len(r.Untested) == len(r.Scope) && len(r.Scope) > 0:
		return "Nothing has been assessed yet — this is an empty result, not a clean one."
	case len(r.Untested) > 0:
		return "No open vulnerabilities in the scanned targets. " + joinTargets(r.Untested) +
			" " + verbFor(len(r.Untested)) + " not been assessed."
	case len(r.PartiallyAssessed) > 0:
		return "No open vulnerabilities in what was assessed. " + joinTargets(r.PartiallyAssessed) +
			" " + verbFor(len(r.PartiallyAssessed)) + " only PARTIALLY assessed — the last scan lost one or " +
			"more tools, so this is not a clean bill of health for " + pronounFor(len(r.PartiallyAssessed)) + "."
	default:
		return "No open vulnerabilities — every monitored asset is currently clean."
	}
}

// inlineMarkup converts the ONLY two inline constructs our own generators emit — **bold** and
// `code` — into markup, for prose (narrativeSummary) shared with the Markdown renderer.
//
// It ESCAPES FIRST and converts second, so any HTML in the underlying data (a target name, a
// tenant name) is inert text by the time the delimiters are interpreted; the returned
// template.HTML therefore contains only the tags this function itself introduced. It is
// deliberately NOT a Markdown renderer: anything else passes through as escaped text.
//
// It is applied to finding DESCRIPTIONS too, which are scanner/target-derived. That is safe by
// construction rather than by trust: the only tags it can ever emit are the four hard-coded here,
// none of which takes an attribute, so the worst a hostile description achieves is bolding its own
// text. The alternative — rendering our own tools' `code` spans as literal backticks — makes the
// customer deliverable look unfinished. The captured PoC is deliberately NOT passed through it
// (see the template): there the delimiters are part of the payload.
func inlineMarkup(s string) template.HTML {
	esc := template.HTMLEscapeString(s)
	esc = wrapPairs(esc, "**", "<strong>", "</strong>")
	esc = wrapPairs(esc, "`", "<code>", "</code>")
	return template.HTML(esc) //nolint:gosec // escaped above; only our own tags are added
}

// wrapPairs replaces balanced PAIRS of delim with open/close tags. An unpaired trailing delimiter
// is left as literal text rather than being closed for the caller — inventing a tag boundary is
// how a converter starts emitting markup the input never asked for.
func wrapPairs(s, delim, open, close string) string {
	var b strings.Builder
	rest, inside := s, false
	for {
		i := strings.Index(rest, delim)
		if i < 0 {
			break
		}
		// Only open a span if a matching closer exists; otherwise stop and emit the remainder.
		if !inside && !strings.Contains(rest[i+len(delim):], delim) {
			break
		}
		b.WriteString(rest[:i])
		if inside {
			b.WriteString(close)
		} else {
			b.WriteString(open)
		}
		inside = !inside
		rest = rest[i+len(delim):]
	}
	b.WriteString(rest)
	return b.String()
}
