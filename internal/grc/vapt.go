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

// VAPTReport is the customer-facing Vulnerability Assessment & Penetration Test deliverable
// — the artifact an SMB hands an enterprise customer, insurer, or auditor in a security
// review ("do you have a recent pentest?"). It is built ENTIRELY from grounded scan findings
// (CLAUDE.md §10): every entry cites the tool + evidence that backs it, so nothing is
// asserted that a tool did not prove. This is the deterministic, evidence-grounded analogue
// of a manual pentest report — continuously regenerable, never stale.
type VAPTReport struct {
	TenantName  string    `json:"tenant_name"`
	GeneratedAt time.Time `json:"generated_at"`
	Engine      string    `json:"engine"`
	Scope       []string  `json:"scope"` // the monitored asset targets assessed
	// Untested names scope targets that NOTHING has assessed yet. Zero findings across a scope
	// nobody scanned is not a clean result, and this report is the document a customer hands an
	// auditor or a prospect — it is the last place a silence should read as an all-clear.
	Untested []string `json:"untested,omitempty"`
	// PartiallyAssessed names scope targets that WERE scanned but whose most recent scan lost a tool.
	// Distinct from Untested, and the distinction is the point: those targets were looked at, so they
	// are not "not assessed" — but a scan missing tools has not earned "clean" either, and this
	// report's closing line is the most quotable sentence in a document customers hand to prospects
	// and auditors.
	PartiallyAssessed []string      `json:"partially_assessed,omitempty"`
	Summary           VAPTSummary   `json:"summary"`
	Findings          []VAPTFinding `json:"findings"` // worst-severity first
	// Roadmap is the ordered remediation plan — the findings grouped into the changes that fix
	// them, worst-first by real exploitation evidence. A list of findings is not a plan; this is
	// the section that tells a team what to do on Monday. See vapt_roadmap.go.
	Roadmap []RemediationStep `json:"roadmap,omitempty"`
	// Intel is the pinned state of the threat-intel corpus this report's KEV / ransomware /
	// exploit-probability claims were evaluated against. Filled by the caller (which can read the
	// environment and the on-disk manifest); nil when unknown. See vapt_provenance.go.
	Intel *IntelProvenance `json:"intel,omitempty"`
	// Attestation, when the report is signed (same scheme as the evidence pack).
	Signer string `json:"signer,omitempty"`
	SHA256 string `json:"sha256,omitempty"`
}

// VAPTSummary is the executive-summary roll-up.
type VAPTSummary struct {
	Total         int            `json:"total"`
	BySeverity    map[string]int `json:"by_severity"`    // critical/high/medium/low/info
	Verified      int            `json:"verified"`       // exploitation/tool-confirmed (not pattern-only)
	ExploitProven int            `json:"exploit_proven"` // a benign PoC was captured (active-driver proof — the strongest tier)
	Unconfirmed   int            `json:"unconfirmed"`    // pattern-match only — leads to validate (FP-exposed)
	KEV           int            `json:"kev"`            // actively exploited in the wild (CISA KEV)
	// Ransomware counts KEV findings CISA marks as used in ransomware campaigns — a STRICTLY
	// STRONGER claim than KEV listing (exploited by crews who encrypt the estate, not merely
	// exploited in the wild). Kept separate from KEV so the urgent few are never diluted into
	// the many. The engine computes it (§7); the report was dropping it on the floor.
	Ransomware int `json:"ransomware,omitempty"`
	// Automatable counts findings CISA assesses an attacker can AUTOMATE (SSVC). It is the signal
	// none of the other feeds provides: KEV is binary and covers ~1,700 CVEs, EPSS is a probability,
	// and neither separates a vulnerability exploited by hand against one target from one that can
	// be driven across an estate.
	Automatable int `json:"automatable,omitempty"`
	FixesReady  int `json:"fixes_ready"` // findings with a remediation already prepared
	// RetestConfirmed / RetestStillPresent are the fix-verification roll-up — the "we don't just
	// fix it, we prove it closed" differentiator (State-of-AI-in-Pentesting KF#4). Confirmed = an
	// applied fix whose re-scan proved every claimed finding gone; StillPresent = a fix was applied
	// but the finding is STILL there. Both 0 when nothing has been re-tested (honest, not "clean").
	RetestConfirmed    int `json:"retest_confirmed,omitempty"`
	RetestStillPresent int `json:"retest_still_present,omitempty"`
	// RetestAwaitingProof counts fixes the re-scan found gone but which are NOT counted as confirmed,
	// because a clean re-scan for that class has been contradicted by a live exploit before (ADR 0025
	// F1). Reported separately and never folded into either other number: rolled into confirmed it
	// would overstate, rolled into still-present it would claim the fix failed, and omitted entirely
	// it would silently shrink the totals — the reader would see a smaller report and no reason why.
	RetestAwaitingProof int `json:"retest_awaiting_proof,omitempty"`
	// PatchAvailable / PatchUnavailable: of the dependency (SCA) findings, how many have an upstream
	// patched version the customer can upgrade to right now vs. none available yet — the competitor
	// "fixable vs no-fix" executive signal. Only SCA findings (grype/trivy/osv-scanner) carry it.
	PatchAvailable   int    `json:"patch_available"`
	PatchUnavailable int    `json:"patch_unavailable"`
	RiskRating       string `json:"risk_rating"` // Critical | High | Medium | Low | Clear
}

// VAPTFinding is one assessed vulnerability, grounded in its scanner evidence.
type VAPTFinding struct {
	ID            string   `json:"id"`
	Title         string   `json:"title"`
	Severity      string   `json:"severity"`
	CVSS          float64  `json:"cvss,omitempty"`
	CVSSVector    string   `json:"cvss_vector,omitempty"`    // CVSS base vector (NVD) — attack-vector detail beyond the score
	EPSS          float64  `json:"epss,omitempty"`           // FIRST.org exploit-prediction probability (0–1)
	PublicExploit bool     `json:"public_exploit,omitempty"` // a public exploit/PoC exists (ExploitDB/Metasploit)
	Tool          string   `json:"tool"`                     // the scanner that found it (evidence)
	RuleID        string   `json:"rule_id"`                  // the specific check
	Endpoint      string   `json:"endpoint,omitempty"`
	CWE           []string `json:"cwe,omitempty"`
	MITRE         []string `json:"mitre,omitempty"`
	Description   string   `json:"description,omitempty"`
	PoC           string   `json:"poc,omitempty"`          // captured exploitation proof (active-driver PoC), if any
	OWASP         []string `json:"owasp,omitempty"`        // OWASP Top 10 (2021) category mapping
	Remediation   string   `json:"remediation,omitempty"`  // the recommended fix (CWE-class standard)
	Verification  string   `json:"verification,omitempty"` // verified | corroborated | pattern_match
	// Rung is HOW this was established — exploited | provider_confirmed | reachability_confirmed |
	// corroborated | scanner_reported (ADR 0029 D2d).
	//
	// It exists because Verification could not tell two very different claims apart: a web finding the
	// agent EXPLOITED and a cloud path the provider's policy simulator merely AUTHORIZED both arrive
	// here as the word "verified", and this document is the one a customer forwards to an auditor.
	Rung        string  `json:"rung,omitempty"`
	Confidence  float64 `json:"confidence,omitempty"`  // 0–1 grounded confidence (per-tool base + corroboration)
	Unconfirmed bool    `json:"unconfirmed,omitempty"` // pattern-match only — a lead to validate, not a confirmed exploit
	KEV         bool    `json:"kev,omitempty"`         // actively exploited
	// Ransomware: CISA marks this CVE used in ransomware campaigns (stronger than KEV). WeaponRank:
	// Metasploit's own reliability name for the best module targeting it ("excellent"…"manual") —
	// "an operator can run it tonight". KEVDueDate: CISA's own BOD 22-01 remediation deadline.
	// All three are computed by the engine (§7) and were being dropped from this deliverable.
	Ransomware bool   `json:"ransomware,omitempty"`
	WeaponRank string `json:"weapon_rank,omitempty"`
	// CISA's SSVC decision points (Vulnrichment/ADP), recorded VERBATIM — we never compute an SSVC
	// decision from them, which would need the defender's own mission and deployment context.
	// Automatable is carried even when the answer is NO: between two findings with identical CVSS
	// and neither on KEV, that negative is exactly what separates them.
	SSVCExploitation string    `json:"ssvc_exploitation,omitempty"`
	SSVCAutomatable  string    `json:"ssvc_automatable,omitempty"`
	SSVCImpact       string    `json:"ssvc_impact,omitempty"`
	KEVDueDate       time.Time `json:"kev_due_date,omitzero"`
	// DiscoveredAt is when a tool actually observed this. An auditor asking "how long has this been
	// open?" is asking a question the report otherwise cannot answer, and a continuously-regenerated
	// document with no per-finding date reads as though everything was found today.
	DiscoveredAt time.Time `json:"discovered_at,omitzero"`
	FixReady     bool      `json:"fix_ready,omitempty"` // a remediation is prepared/queued
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

	name := tenantID
	if t, terr := g.Store.GetTenant(ctx, tenantID); terr == nil && t.Name != "" {
		name = t.Name
	}
	var scope []string
	for _, a := range assets {
		if a.Target != "" {
			scope = append(scope, a.Target)
		}
	}
	rep := ReportFromFindings(findings, scope, name, g.now(), fixReady)

	// Fix-verification roll-up (best-effort): the retest differentiator — a fix this product
	// APPLIED and then re-tested, so the report can say "confirmed closed on re-scan" rather than
	// "we filed a fix and hoped". Computed here (not in the pure core) because it needs the action
	// store; a per-engagement report has no such history and simply carries zeros. Grounded (§10):
	// counts come only from a real FixVerification the retester wrote, never inferred.
	if actions, aerr := g.Store.ListActions(ctx, tenantID); aerr == nil {
		for _, a := range actions {
			if a.Verification == nil {
				continue
			}
			switch a.Verification.Status {
			case platform.FixStatusFixed:
				rep.Summary.RetestConfirmed++
			case platform.FixStatusStillPresent:
				rep.Summary.RetestStillPresent++
			case platform.FixStatusRescanUnconfirmed:
				rep.Summary.RetestAwaitingProof++
			}
		}
	}
	return rep, nil
}

// ReportFromFindings builds a VAPT report from an explicit findings set + scope —
// the pure core shared by the tenant-wide VAPTReport and the per-pentest-engagement
// report (which passes the engagement's scoped findings + Rules-of-Engagement scope).
// fixReady marks findings with a prepared remediation (may be nil). Pure (no I/O).
func ReportFromFindings(findings []types.Finding, scope []string, name string, now time.Time, fixReady map[string]bool) *VAPTReport {
	if fixReady == nil {
		fixReady = map[string]bool{}
	}
	r := &VAPTReport{
		TenantName: name, GeneratedAt: now, Engine: "tsengine (TensorShield)", Scope: scope,
		Summary: VAPTSummary{BySeverity: map[string]int{}},
	}
	for _, f := range findings {
		sev := string(f.Severity)
		r.Summary.Total++
		r.Summary.BySeverity[sev]++
		confirmed := isVerified(f)
		if confirmed {
			r.Summary.Verified++
		} else {
			r.Summary.Unconfirmed++
		}
		kev := f.ThreatIntel != nil && f.ThreatIntel.KEV != nil
		if kev {
			r.Summary.KEV++
		}
		if fixReady[f.ID] {
			r.Summary.FixesReady++
		}
		// Upstream patch availability (SCA fixable signal, §competitor-parity). Only dependency
		// scanners set this key, so the counts naturally scope to SCA findings.
		switch f.ToolArgs["fixable"] {
		case "true":
			r.Summary.PatchAvailable++
		case "false":
			r.Summary.PatchUnavailable++
		}
		// Pull the active-driver exploitation proof out of the description so the report can
		// render it as distinguished, reproducible evidence (the exploitation-proven tier) rather
		// than burying it in prose — the XBOW "we proved it" differentiator.
		poc, descBody := extractPoC(f.Description)
		if poc != "" {
			r.Summary.ExploitProven++
		}
		vf := VAPTFinding{
			ID: f.ID, Title: f.Title, Severity: sev, Tool: f.Tool, RuleID: f.RuleID,
			Endpoint: f.Endpoint, CWE: f.CWE, MITRE: f.MITRETechniques, Description: descBody, PoC: poc,
			OWASP: owaspFor(f.CWE, f.Tool), Remediation: remediationFor(f.CWE, f.Tool),
			Verification: string(f.VerificationStatus), Rung: string(f.DeriveRung()), Confidence: f.Confidence, DiscoveredAt: f.DiscoveredAt,
			Unconfirmed: !confirmed, KEV: kev, FixReady: fixReady[f.ID],
		}
		if f.ThreatIntel != nil {
			vf.CVSS = f.ThreatIntel.CVSS
			vf.CVSSVector = f.ThreatIntel.CVSSVector
			if f.ThreatIntel.EPSS != nil {
				vf.EPSS = f.ThreatIntel.EPSS.Score
			}
			vf.PublicExploit = len(f.ThreatIntel.Exploits) > 0
			vf.WeaponRank = f.ThreatIntel.WeaponRank
			if sv := f.ThreatIntel.SSVC; sv != nil {
				// "none" is the absence of a signal, not a finding about it — recording it would put
				// a reassuring word on every unassessed CVE.
				if sv.Exploitation != "" && sv.Exploitation != "none" {
					vf.SSVCExploitation = sv.Exploitation
				}
				vf.SSVCAutomatable = sv.Automatable
				vf.SSVCImpact = sv.TechnicalImpact
				if sv.Automatable == "yes" {
					r.Summary.Automatable++
				}
			}
			if k := f.ThreatIntel.KEV; k != nil {
				vf.Ransomware = k.Ransomware
				vf.KEVDueDate = k.DueDate
				if k.Ransomware {
					r.Summary.Ransomware++
				}
			}
		}
		r.Findings = append(r.Findings, vf)
	}
	sort.SliceStable(r.Findings, func(i, j int) bool {
		ri, rj := types.Severity(r.Findings[i].Severity).Rank(), types.Severity(r.Findings[j].Severity).Rank()
		if ri != rj {
			return ri > rj // higher rank = worse severity → worst first
		}
		// Within a severity, confirmed (verified/corroborated) leads unconfirmed
		// (pattern-match) — the report fronts what's proven, not the FP-exposed leads.
		if r.Findings[i].Unconfirmed != r.Findings[j].Unconfirmed {
			return !r.Findings[i].Unconfirmed
		}
		if r.Findings[i].Confidence != r.Findings[j].Confidence {
			return r.Findings[i].Confidence > r.Findings[j].Confidence
		}
		return r.Findings[i].ID < r.Findings[j].ID
	})
	r.Roadmap = BuildRoadmap(findings, fixReady)
	r.Summary.RiskRating = vaptRisk(r.Summary.BySeverity)
	// A scope nothing has assessed cannot be rated. "Clear" is a verdict; with no assessment behind it
	// there is no verdict to give, and the word would be doing all the work in a document that gets
	// forwarded to auditors.
	if len(r.Untested) > 0 && len(r.Untested) == len(r.Scope) && r.Summary.Total == 0 {
		r.Summary.RiskRating = "Not assessed"
	}
	return r
}

func isVerified(f types.Finding) bool {
	return f.VerificationStatus == "verified" || f.VerificationStatus == "corroborated"
}

// extractPoC splits the active-driver "[Exploitation PoC ...]" proof line out of a finding's
// description (the active driver appends it on a proven exploit). Returns (poc, descriptionBody);
// poc is "" when the description carries no captured proof. Mirrors the dashboard UI's pocOf.
func extractPoC(desc string) (poc, body string) {
	i := strings.Index(desc, "[Exploitation PoC")
	if i < 0 {
		return "", desc
	}
	return strings.TrimSpace(desc[i:]), strings.TrimSpace(desc[:i])
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

// writeSignalLines appends executive-summary lines for signals that are only present when the
// engine actually computed them — ransomware linkage and fix-verification. Conditional (never
// "0 ...") so a clean report doesn't carry alarming-looking zeros; shared by the full + exec
// renderers so the two never drift.
func writeSignalLines(b *strings.Builder, s VAPTSummary) {
	if s.Ransomware > 0 {
		fmt.Fprintf(b, "- **%d ransomware-linked** — CISA marks the CVE used in ransomware campaigns, a stronger signal than KEV listing\n", s.Ransomware)
	}
	if s.Automatable > 0 {
		fmt.Fprintf(b, "- **%d automatable** — CISA assesses an attacker can automate exploitation, so these scale across an estate rather than costing effort per target\n", s.Automatable)
	}
	if s.RetestAwaitingProof > 0 {
		b.WriteString(fmt.Sprintf(" %s found gone on re-scan but not counted as confirmed: a clean "+
			"re-scan for that class has been contradicted by a live exploit before, so it awaits re-attack.",
			countNoun(s.RetestAwaitingProof, "applied fix was", "applied fixes were")))
	}
	if s.RetestConfirmed > 0 || s.RetestStillPresent > 0 {
		fmt.Fprintf(b, "- **Fix verification:** %s re-tested and confirmed closed on re-scan; %d still present after the fix\n",
			countNoun(s.RetestConfirmed, "applied fix", "applied fixes"), s.RetestStillPresent)
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
		if r.SHA256 != "" {
			fmt.Fprintf(&b, "- **Signed:** `%s` · sha256 `%s`\n", r.Signer, r.SHA256)
		} else {
			// A signer without a hash is a named sign-off, not an attestation — don't render an
			// empty `sha256 ` code span next to their name on a document the customer forwards.
			fmt.Fprintf(&b, "- **Signed off by:** %s\n", r.Signer)
		}
	}
	b.WriteString("\n## Executive summary\n\n")
	s := r.Summary
	fmt.Fprintf(&b, "- **Overall risk rating: %s**\n", s.RiskRating)
	fmt.Fprintf(&b, "- **%d findings** — Critical %d · High %d · Medium %d · Low %d · Info %d\n",
		s.Total, s.BySeverity["critical"], s.BySeverity["high"], s.BySeverity["medium"], s.BySeverity["low"], s.BySeverity["info"])
	fmt.Fprintf(&b, "- **%d exploitation-proven** (strongest evidence tier — a benign proof-of-concept is captured for each) · **%d tool-confirmed** (verified/corroborated) · **%d unconfirmed** (pattern-match — validate before action) · **%d actively exploited** (CISA KEV) · **%d with a fix already prepared**\n",
		s.ExploitProven, s.Verified, s.Unconfirmed, s.KEV, s.FixesReady)
	if sca := s.PatchAvailable + s.PatchUnavailable; sca > 0 {
		fmt.Fprintf(&b, "- **Dependency patchability:** %d of %d dependency findings have an upstream fix you can upgrade to now; %d have no fix available yet (mitigate)\n",
			s.PatchAvailable, sca, s.PatchUnavailable)
	}
	writeSignalLines(&b, s)
	b.WriteString("\n" + narrativeSummary(r) + "\n")
	// The caveat belongs HERE, immediately under the exploitation counts it qualifies — not in a
	// methodology note further down that a reader quoting "0 actively exploited" never reaches.
	if c := r.Intel.IntelCaveat(); c != "" {
		b.WriteString("\n" + c + "\n")
	}
	b.WriteString("\n## Methodology & confidence\n\n")
	b.WriteString("Assessment is performed by the TensorShield engine, which wraps best-in-class open-source " +
		"scanners across every asset class (web, API, code, containers, cloud, identity) and verifies exploitable " +
		"findings through an evidence-grounded agent. **Every finding below cites the tool and rule that proves it** — " +
		"no result is asserted that a tool did not demonstrate (anti-hallucination grounding). The assessment is " +
		"continuous, so this report reflects the current state, not a point-in-time snapshot.\n\n")
	b.WriteString("Each finding carries a **confidence tier** so you can triage accurately:\n\n" +
		"- **Confirmed** — independently corroborated by ≥1 other tool, or actively re-verified. Treat as real.\n" +
		"- **Unconfirmed** — a single-tool pattern match. A credible lead to validate, not a proven exploit — listed after the confirmed findings of the same severity and labelled inline, so a false positive can never masquerade as a confirmed result.\n\n")
	if p := RenderIntelProvenance(r.Intel); p != "" {
		b.WriteString(p + "\n\n")
	}

	b.WriteString("## Scope\n\n")
	if len(r.Scope) == 0 {
		b.WriteString("_No assets in scope yet — connect a system to begin the assessment._\n\n")
	} else {
		// Mark what was never assessed inline. A reader scanning the scope list should not have to
		// cross-reference the summary to learn that half of it was never touched.
		untested := map[string]bool{}
		for _, t := range r.Untested {
			untested[t] = true
		}
		partial := map[string]bool{}
		for _, t := range r.PartiallyAssessed {
			partial[t] = true
		}
		for _, t := range r.Scope {
			switch {
			case untested[t]:
				fmt.Fprintf(&b, "- `%s` — **not assessed** (no scan has run against this target)\n", t)
			case partial[t]:
				fmt.Fprintf(&b, "- `%s` — **partially assessed** (the last scan lost one or more tools; "+
					"what they would have found is not represented here)\n", t)
			default:
				fmt.Fprintf(&b, "- `%s`\n", t)
			}
		}
		b.WriteString("\n")
	}

	fmt.Fprintf(&b, "## Findings (%d)\n\n", len(r.Findings))
	if len(r.Findings) == 0 {
		if len(r.Untested) == len(r.Scope) && len(r.Scope) > 0 {
			b.WriteString("_Nothing has been assessed yet — this is an empty result, not a clean one._\n")
		} else if len(r.Untested) > 0 {
			b.WriteString("_No open vulnerabilities in the scanned targets. " + joinTargets(r.Untested) +
				" " + verbFor(len(r.Untested)) + " not been assessed._\n")
		} else if len(r.PartiallyAssessed) > 0 {
			// Scanned, but not completely. "Clean" is a claim about what was looked for, and a scan
			// that lost its tools looked for less than it reports.
			b.WriteString("_No open vulnerabilities in what was assessed. " + joinTargets(r.PartiallyAssessed) +
				" " + verbFor(len(r.PartiallyAssessed)) + " only PARTIALLY assessed — the last scan lost " +
				"one or more tools, so this is not a clean bill of health for " +
				pronounFor(len(r.PartiallyAssessed)) + "._\n")
		} else {
			b.WriteString("_No open vulnerabilities — every monitored asset is currently clean._\n")
		}
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
			if f.CVSSVector != "" {
				fmt.Fprintf(&b, "- **CVSS:** %.1f (`%s`)\n", f.CVSS, f.CVSSVector)
				// The vector carries the actionable half — decode it, keeping the raw form above
				// because that is what an auditor cross-checks.
				if prose := cvssVectorProse(f.CVSSVector); prose != "" {
					fmt.Fprintf(&b, "  - %s\n", prose)
				}
			} else {
				fmt.Fprintf(&b, "- **CVSS:** %.1f\n", f.CVSS)
			}
		}
		if f.EPSS > 0 {
			fmt.Fprintf(&b, "- **EPSS:** %.1f%% exploit probability (FIRST.org)\n", f.EPSS*100)
		}
		if f.PublicExploit {
			fmt.Fprintf(&b, "- **Public exploit available** (a working PoC is published — ExploitDB/Metasploit)\n")
		}
		if !f.KEVDueDate.IsZero() {
			fmt.Fprintf(&b, "- **CISA remediation deadline (BOD 22-01):** %s\n", f.KEVDueDate.UTC().Format("2006-01-02"))
		}
		// The rung leads, because it is the sentence that survives being read quickly. The raw
		// verification state used to be printed here on its own, so "verified" covered both an exploit
		// we ran and a policy the provider merely allowed.
		status := f.Rung
		if status != "" {
			status = types.EvidenceRung(status).Label()
		} else if status = f.Verification; status == "" {
			status = "detected"
		}
		if f.Confidence > 0 {
			status += fmt.Sprintf(" · confidence %.0f%%", f.Confidence*100)
		}
		if f.Unconfirmed {
			status += " · **unconfirmed (pattern match — validate before action)**"
		}
		if f.KEV {
			status += " · **actively exploited (CISA KEV)**"
		}
		if f.Ransomware {
			status += " · **ransomware-linked (CISA)**"
		}
		if f.WeaponRank != "" {
			status += fmt.Sprintf(" · weaponized: %s (Metasploit)", f.WeaponRank)
		}
		if f.SSVCExploitation != "" {
			status += fmt.Sprintf(" · **CISA SSVC exploitation: %s**", f.SSVCExploitation)
		}
		if f.SSVCAutomatable != "" {
			// Stated either way — the NO is the half that discriminates between two otherwise
			// identical findings, and dropping it would leave only the alarming case visible.
			if f.SSVCAutomatable == "yes" {
				status += " · **automatable (CISA SSVC)**"
			} else {
				status += " · not automatable (CISA SSVC)"
			}
		}
		if f.SSVCImpact == "total" {
			status += " · SSVC technical impact: total"
		}
		if f.PoC != "" && f.Rung != string(types.RungExploited) {
			// Belt and braces: a captured proof with anything other than the exploited rung is a
			// contradiction worth showing rather than smoothing over.
			status = "**exploitation-proven** · " + status
		}
		fmt.Fprintf(&b, "- **Evidence strength:** %s\n", status)
		if !f.DiscoveredAt.IsZero() {
			fmt.Fprintf(&b, "- **First observed:** %s\n", f.DiscoveredAt.UTC().Format("2006-01-02"))
		}
		if f.Description != "" {
			fmt.Fprintf(&b, "\n%s\n", f.Description)
		}
		if f.PoC != "" {
			b.WriteString("\n**✓ Exploitation-proven — reproducible proof of concept:**\n\n")
			fmt.Fprintf(&b, "```\n%s\n```\n", f.PoC)
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
	b.WriteString(RenderRoadmapMarkdown(r.Roadmap))
	return b.String()
}

// RenderVAPTExecMarkdown renders the concise EXECUTIVE / trust summary of the same report — the
// shareable one-pager for a customer, auditor, or exec who asks "did you get pentested, and what's
// the posture?" It carries the risk rating, exploitation-proven counts, severity breakdown, the
// top findings by title/severity only (NO per-finding technical detail / PoC / payloads), and the
// named sign-off. The full technical VAPT (RenderVAPTMarkdown) stays the developer/remediation
// deliverable. Same grounded data — a different altitude, not different claims.
func RenderVAPTExecMarkdown(r *VAPTReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "# Penetration Test — Executive Summary — %s\n\n", r.TenantName)
	fmt.Fprintf(&b, "- **Generated:** %s\n", r.GeneratedAt.UTC().Format(time.RFC3339))
	fmt.Fprintf(&b, "- **Assessed by:** %s\n", r.Engine)
	if len(r.Scope) > 0 {
		fmt.Fprintf(&b, "- **Scope:** %s\n", strings.Join(r.Scope, ", "))
	}
	if r.Signer != "" {
		fmt.Fprintf(&b, "- **Signed off by:** %s\n", r.Signer)
	}
	s := r.Summary
	fmt.Fprintf(&b, "\n## Overall risk rating: %s\n\n", s.RiskRating)
	fmt.Fprintf(&b, "- **%d findings** — Critical %d · High %d · Medium %d · Low %d · Info %d\n",
		s.Total, s.BySeverity["critical"], s.BySeverity["high"], s.BySeverity["medium"], s.BySeverity["low"], s.BySeverity["info"])
	fmt.Fprintf(&b, "- **%d exploitation-proven** (strongest evidence tier — a benign proof-of-concept is captured for each) · **%d actively exploited in the wild** (CISA KEV) · **%d with a fix already prepared**\n",
		s.ExploitProven, s.KEV, s.FixesReady)
	if sca := s.PatchAvailable + s.PatchUnavailable; sca > 0 {
		fmt.Fprintf(&b, "- **%d of %d dependency findings have an upstream fix available now**\n", s.PatchAvailable, sca)
	}
	writeSignalLines(&b, s)
	b.WriteString("\n" + narrativeSummary(r) + "\n")
	// The exec one-pager is the MOST forwarded artifact and the most quoted; if the KEV figure on it
	// rests on stale intel, this is the page that has to say so.
	if c := r.Intel.IntelCaveat(); c != "" {
		b.WriteString("\n" + c + "\n")
	}

	// Top findings — title + severity + confidence tier only (the "what", not the "how"). Cap at 10
	// so the exec page stays a page; the full technical report carries the rest.
	if len(r.Findings) > 0 {
		b.WriteString("\n## Most significant findings\n\n")
		n := len(r.Findings)
		if n > 10 {
			n = 10
		}
		for _, f := range r.Findings[:n] {
			tier := "confirmed"
			if f.Unconfirmed {
				tier = "unconfirmed lead"
			} else if f.PoC != "" {
				tier = "exploitation-proven"
			}
			fmt.Fprintf(&b, "- **[%s]** %s — _%s_\n", strings.ToUpper(f.Severity), f.Title, tier)
		}
		if len(r.Findings) > n {
			fmt.Fprintf(&b, "\n_+ %d more — see the full technical report for every finding, evidence, and remediation._\n", len(r.Findings)-n)
		}
	} else {
		b.WriteString("\nNo findings were identified in scope for this assessment.\n")
	}
	b.WriteString("\n---\n_This is the executive summary. The full technical report includes every finding with its evidence, request/response proof, CWE/OWASP mapping, and developer-ready remediation._\n")
	return b.String()
}

// Reassess re-derives the parts of a report that depend on Untested, which callers fill in after
// ReportFromFindings has run (only the platform layer knows what has actually been scanned).
//
// It exists because the alternative — threading an untested list through the pure constructor — would
// push a store-shaped concern into a function whose whole value is being pure and testable. Calling
// this is required for the rating to be honest; ReportFromFindings alone cannot know.
func Reassess(r *VAPTReport) {
	if r == nil {
		return
	}
	r.Summary.RiskRating = vaptRisk(r.Summary.BySeverity)
	if len(r.Untested) > 0 && len(r.Untested) == len(r.Scope) && r.Summary.Total == 0 {
		r.Summary.RiskRating = "Not assessed"
	}
}
