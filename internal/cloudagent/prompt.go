package cloudagent

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// buildPrompt assembles the system instruction + account summary + tool catalog +
// the running transcript. The agent loop calls the LLM once per turn with this.
func buildPrompt(cc *Context, transcript []string) string {
	var b strings.Builder
	b.WriteString(`You are an autonomous AI Cloud Security Engineer. You investigate a cloud account by
CALLING TOOLS — you do not have the data memorised, so query it. Your goal: find the
attack paths an external attacker could actually use to reach a crown jewel (sensitive
data or a privileged/admin identity), tell the real ones apart from the config-bad-but-
inert noise, record the real ones, and propose a verified fix for each.

RULES
- Reply with EXACTLY ONE JSON action and nothing else: {"thought":"...","tool":"NAME","args":{...}}.
- Ground every claim in a tool result. Do NOT record an issue from memory — record_issue
  REJECTS any path that doesn't actually exist in the graph or doesn't reach a crown jewel.
- prowler findings are config-bad, mostly NOT exploitable. Use resolve_access / find_paths /
  blast_radius to decide which are real.
- A good flow: enumerate_attack_paths to seed, then verify each candidate with find_paths /
  blast_radius, record_issue the confirmed ones, propose_fix each, then finish.
- When done, call finish(summary) with a short executive summary.

`)
	fmt.Fprintf(&b, "ACCOUNT: %s (%s) — %d resources, %d prowler findings.\n",
		cc.Snap.AccountID, cc.Snap.Provider, len(cc.Snap.Nodes), len(cc.Prowler))
	fmt.Fprintf(&b, "Crown jewels (sensitive data / privileged identities): %s\n\n", crownJewels(cc.Snap))

	// Cross-surface entry points (G2): footholds correlation already proved on OTHER surfaces (a code
	// repo, a web app) that bridge INTO this account. An attacker who owns that foothold starts INSIDE —
	// so verify paths FROM the named principal/resource first. Grounded by a real chain; still confirm
	// every issue in the graph (a bridge widens where you look, it does not authorise an ungrounded issue).
	if len(cc.Bridges) > 0 {
		b.WriteString("CROSS-SURFACE ENTRY POINTS (from code/other surfaces — grounded by correlation). An external\nattacker already holds these footholds; treat the cloud principal/resource each names as attacker-\ncontrolled and verify paths FROM it to a crown jewel FIRST:\n")
		for _, br := range cc.Bridges {
			b.WriteString("- " + br + "\n")
		}
		b.WriteByte('\n')
	}

	// Surface the prowler findings WITH their L1.5 enrichment so the agent triages from the
	// engine's signals (KEV/EPSS/exploitability + compliance), not a bare count. It still must
	// VERIFY each via the graph tools (config-bad ≠ exploitable), but now it knows where to look first.
	if d := digestProwler(cc.Prowler); len(d) > 0 {
		b.WriteString("PROWLER FINDINGS (L1) — config evidence to triage. [brackets] carry the L1.5 enrichment:\n")
		b.WriteString("KEV=actively exploited, EPSS=exploit prob 0-1, exploit/surface=L1.5 priority 0-10, then the compliance frameworks the finding maps to. Verify the high-priority ones FIRST via find_paths/blast_radius:\n")
		for _, line := range d {
			b.WriteString(line + "\n")
		}
		b.WriteByte('\n')
	}

	b.WriteString("TOOLS:\n")
	for _, t := range tools() {
		fmt.Fprintf(&b, "- %s\n", t.help)
	}

	if len(transcript) > 0 {
		b.WriteString("\nTRANSCRIPT (most recent last):\n")
		b.WriteString(strings.Join(transcript, "\n---\n"))
	}
	if len(cc.Issues) > 0 {
		fmt.Fprintf(&b, "\n\nRecorded so far: %d issue(s).", len(cc.Issues))
	}
	b.WriteString("\n\nYour next action (one JSON object):")
	return b.String()
}

// digestProwler renders the prowler findings as a compact, severity-sorted, L1.5-enriched digest
// (capped so a noisy account can't blow the prompt). The [bracket] suffix is the canonical L1.5 view
// (types.Finding.L15Tag) shared with the L2 Lead + the web agent.
func digestProwler(fs []types.Finding) []string {
	const cap = 40
	sorted := append([]types.Finding(nil), fs...)
	sort.Slice(sorted, func(i, j int) bool {
		if sorted[i].Severity.Rank() != sorted[j].Severity.Rank() {
			return sorted[i].Severity.Rank() > sorted[j].Severity.Rank()
		}
		return sorted[i].ID < sorted[j].ID
	})
	out := make([]string, 0, len(sorted))
	for i, f := range sorted {
		if i >= cap {
			out = append(out, fmt.Sprintf("  … (+%d more)", len(sorted)-cap))
			break
		}
		res := f.Endpoint
		if res == "" {
			res = f.RuleID
		}
		out = append(out, fmt.Sprintf("  - [%s] %s %s — %s%s", f.Severity, f.RuleID, res, f.Title, f.L15Tag()))
	}
	return out
}

func crownJewels(snap *cloudgraph.Snapshot) string {
	var j []string
	for _, id := range sortedNodeIDs(snap) {
		n := snap.Nodes[id]
		if cloudgraph.SensitiveData(n) || cloudgraph.PrivilegedIdentity(n) {
			j = append(j, id)
		}
		if len(j) >= 20 {
			j = append(j, "…")
			break
		}
	}
	if len(j) == 0 {
		return "(none labelled)"
	}
	return strings.Join(j, ", ")
}
