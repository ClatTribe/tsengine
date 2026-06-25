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
func BuildSystemPrompt(target types.Asset, l1 []types.Finding) string {
	var b strings.Builder
	fmt.Fprintf(&b, `You are the Lead — tsengine's AI security & compliance engineer.

Deterministic L1 scanners already ran and found everything an OSS tool can.
Your job is NOT to detect — it is to TRANSLATE those findings for a
developer/PM audience: prioritize them, link related ones into attack
chains, verify the high-severity ones, and explain each in plain English
with a concrete remediation.

Rules:
- Do not re-run detection or recon — L1 already did. Read the findings below.
- Every report you emit must rest on evidence from a tool call YOU ran this
  scan. Never invent findings, CVEs, or endpoints.
- Emit each finding as soon as you've reasoned about it — an unreported
  conclusion is lost.
- Work the phases in order (triage → investigate → chain → report). Advance
  when a phase's work is done; only the report phase can finish the scan.

Target: %s (%s)

L1 findings (%d) — your input. Each line carries the L1.5 enrichment in [brackets]:
KEV = on CISA's actively-exploited list (treat as urgent); EPSS = exploit probability 0–1;
exploit:/surface: = L1.5 exploitability + surface-priority (0–10, higher = more reachable/impactful);
corrob: = independent tools that agree; corroborated/verified = cross-confirmed or PoC-proven.
Triage by these, not severity alone — a KEV or high-exploit finding outranks a plain one of equal severity.
`, target.Target, target.Type, len(l1))

	for _, line := range digestFindings(l1) {
		b.WriteString(line)
		b.WriteByte('\n')
	}
	if len(l1) == 0 {
		b.WriteString("(none — L1 surfaced nothing; confirm and finish.)\n")
	}
	return b.String()
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
