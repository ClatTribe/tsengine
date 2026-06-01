package cloudagent

import (
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/cloudgraph"
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
