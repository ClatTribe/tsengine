package l2

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// minSystemPromptBytes is the render guard floor. strix once shipped an
// EMPTY system prompt (a template-render bug) and the model hallucinated an
// entire scan from training data (prompt_tokens=145 instead of ~80K). The
// agent asserts the built prompt clears this floor before the loop starts —
// an empty/tiny prompt is a build error, never silently sent.
const minSystemPromptBytes = 400

// BuildSystemPrompt assembles the Lead's system prompt: its role, the
// load-bearing rules, and a COMPACT digest of the L1 findings it's
// translating. Deliberately short + evidence-only (strix's verbose
// 7-rule prompt made the model hallucinate findings as prose), and it
// never shows tool-call syntax (so the model can't mimic it as fake calls).
// IssueDigest is one deduplicated, cross-tool UNIFIED issue — the L1.7 estate view the platform feeds
// the Lead so it triages over CORROBORATED issues ("one issue, many signals") instead of raw
// per-scanner findings. Neutral data: the platform computes it (crossdetect.UnifiedIssues) and maps it
// in; l2 stays engine-pure (imports only pkg/types, never the platform layer).
type IssueDigest struct {
	Title     string
	Severity  string
	Sources   []string // distinct scanners that reported it (the corroboration)
	Confirmed bool     // ≥2 independent tools agree
	Count     int      // raw findings collapsed in
	Endpoint  string
	CVE       string
	Attacked  bool // observed under attack in production (the strongest exploitability signal)
}

// EstateContext is the deterministic L1.7 correlation the AI security engineer reasons OVER: the
// unified cross-surface issues + the attack-path chains. The zero value renders nothing, so the
// prompt is byte-identical to the pre-estate behaviour when no correlation is supplied.
type EstateContext struct {
	Issues      []IssueDigest
	AttackPaths []string // pre-rendered chain summaries, highest-severity first
}

// BuildSystemPrompt is the estate-free prompt (back-compat for callers/tests with no correlation).
func BuildSystemPrompt(target types.Asset, l1 []types.Finding) string {
	return BuildSystemPromptWithEstate(target, l1, EstateContext{})
}

// BuildSystemPromptWithEstate assembles the Lead's system prompt with the L1.7 estate view up front —
// the engineer triages over the unified, corroborated, cross-surface issues + attack paths first, and
// drills into the raw findings only for detail. This is what makes it a whole-estate security engineer
// rather than a flat-finding explainer.
func BuildSystemPromptWithEstate(target types.Asset, l1 []types.Finding, estate EstateContext) string {
	var b strings.Builder
	fmt.Fprintf(&b, `You are the Lead — tsengine's AI security & compliance engineer.

Deterministic L1 scanners already ran and found everything an OSS tool can,
and a deterministic correlation layer has unified + cross-linked them.
Your job is NOT to detect — it is to TRANSLATE those findings for a
developer/PM audience: prioritize them, link related ones into attack
chains, verify the high-severity ones, and explain each in plain English
with a concrete remediation.

Rules:
- Do not re-run detection or recon — L1 already did. Read the issues/findings below.
- Every report you emit must rest on evidence from a tool call YOU ran this
  scan. Never invent findings, CVEs, or endpoints.
- Emit each finding as soon as you've reasoned about it — an unreported
  conclusion is lost.
- Work the phases in order (triage → investigate → chain → report). Advance
  when a phase's work is done; only the report phase can finish the scan.

Target: %s (%s)
`, target.Target, target.Type)

	if len(estate.Issues) > 0 {
		b.WriteString("\nUNIFIED ISSUES — your PRIMARY triage surface (deduped + corroborated across every tool and surface; reason over THESE, drill into the raw findings only for detail):\n")
		for _, line := range digestIssues(estate.Issues) {
			b.WriteString(line)
			b.WriteByte('\n')
		}
	}
	if len(estate.AttackPaths) > 0 {
		b.WriteString("\nCROSS-SURFACE ATTACK PATHS — a finding on one surface bridges, via a shared entity, to a crown jewel on another. Prioritize the assets these traverse:\n")
		for _, p := range estate.AttackPaths {
			b.WriteString("- ")
			b.WriteString(p)
			b.WriteByte('\n')
		}
	}

	fmt.Fprintf(&b, `
L1 findings (%d) — the raw detail behind the issues above. Each line carries the L1.5 enrichment in [brackets]:
KEV = on CISA's actively-exploited list (treat as urgent); EPSS = exploit probability 0–1;
exploit:/surface: = L1.5 exploitability + surface-priority (0–10, higher = more reachable/impactful);
corrob: = independent tools that agree; corroborated/verified = cross-confirmed or PoC-proven.
Triage by these, not severity alone — a KEV or high-exploit finding outranks a plain one of equal severity.
`, len(l1))

	for _, line := range digestFindings(l1) {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if len(l1) == 0 {
		b.WriteString("(none — L1 surfaced nothing; confirm and finish.)\n")
	}
	return b.String()
}

// digestIssues renders the unified-issue estate view: severity-sorted, corroboration-tagged, capped.
func digestIssues(issues []IssueDigest) []string {
	sorted := append([]IssueDigest(nil), issues...)
	sort.Slice(sorted, func(i, j int) bool {
		if ri, rj := sevRank(sorted[i].Severity), sevRank(sorted[j].Severity); ri != rj {
			return ri > rj
		}
		return sorted[i].Count > sorted[j].Count
	})
	const cap = 100
	out := make([]string, 0, len(sorted))
	for i, is := range sorted {
		if i >= cap {
			out = append(out, fmt.Sprintf("… (+%d more issues)", len(sorted)-cap))
			break
		}
		line := fmt.Sprintf("- [%s] %s %s", is.Severity, is.Title, is.Endpoint)
		var tags []string
		if is.Confirmed {
			tags = append(tags, fmt.Sprintf("CONFIRMED by %d tools", len(is.Sources)))
		} else if len(is.Sources) > 0 {
			tags = append(tags, "src:"+strings.Join(is.Sources, "+"))
		}
		if is.Count > 1 {
			tags = append(tags, fmt.Sprintf("%d findings", is.Count))
		}
		if is.CVE != "" {
			tags = append(tags, is.CVE)
		}
		if is.Attacked {
			tags = append(tags, "UNDER ATTACK in prod")
		}
		if len(tags) > 0 {
			line += "  [" + strings.Join(tags, " · ") + "]"
		}
		out = append(out, line)
	}
	return out
}

// sevRank maps a severity string to a rank (critical highest) for the issue digest sort.
func sevRank(s string) int {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info", "informational":
		return 1
	}
	return 0
}

// digestFindings renders a compact, deterministic one-line-per-finding
// digest (sorted for stable prompt prefix → cache-friendly). Capped so a
// huge finding set can't blow the prompt.
//
// The line carries the L1.5 enrichment INLINE (KEV/EPSS/exploitability/
// surface-priority/corroboration/verification) so the Lead triages WITH the
// enrichment at a glance — not despite it. Severity stays the primary sort
// (the security-engineer expectation + the bench test), but the L1.5 signals
// break ties WITHIN a band, so a KEV-listed / highly-exploitable finding
// rises above a plain one of the same severity. Full detail is still one
// get_finding(id) away; this just stops the digest from throwing L1.5 away.
func digestFindings(l1 []types.Finding) []string {
	const cap = 200
	sorted := append([]types.Finding(nil), l1...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Severity.Rank() != sorted[j].Severity.Rank() {
			return sorted[i].Severity.Rank() > sorted[j].Severity.Rank() // critical (Rank 5) first
		}
		if bi, bj := l15Boost(sorted[i]), l15Boost(sorted[j]); bi != bj {
			return bi > bj // within a severity band, the L1.5-hotter finding first
		}
		return sorted[i].ID < sorted[j].ID
	})
	out := make([]string, 0, len(sorted))
	for i, f := range sorted {
		if i >= cap {
			out = append(out, fmt.Sprintf("… (+%d more)", len(sorted)-cap))
			break
		}
		line := fmt.Sprintf("- [%s] %s %s %s — %s",
			f.ID, f.Severity, f.RuleID, f.Endpoint, f.Title)
		if tags := l15Tags(f); tags != "" {
			line += "  [" + tags + "]"
		}
		out = append(out, line)
	}
	return out
}

// l15Boost is the within-severity-band triage weight from the L1.5 signals:
// KEV (actively exploited) dominates, then EPSS exploit-probability, then the
// exploitability + surface-priority hooks, then cross-tool corroboration.
func l15Boost(f types.Finding) int {
	boost := 0
	if ti := f.ThreatIntel; ti != nil {
		if ti.KEV != nil && ti.KEV.Listed {
			boost += 1000 // CISA KEV: actively exploited in the wild — always rises
		}
		if ti.EPSS != nil {
			boost += int(ti.EPSS.Score * 100) // 0..100
		}
	}
	if f.Exploitability != nil {
		boost += f.Exploitability.Score * 10
	}
	if f.SurfacePriority != nil {
		boost += f.SurfacePriority.Score
	}
	boost += len(f.CorroboratedBy) * 2
	return boost
}

// l15Tags is the compact inline view of a finding's L1.5 enrichment for the
// digest line, delegating to the canonical renderer (types.Finding.L15Summary)
// so the Lead and the cloud/web investigate agents present L1.5 identically.
func l15Tags(f types.Finding) string {
	return f.L15Summary()
}
