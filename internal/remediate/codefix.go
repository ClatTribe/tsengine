package remediate

import (
	"fmt"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// codefix.go carries an APPLICABLE patch into the remediation action — the last link that turns "the
// AI Security Engineer wrote a fix" into a pull request the customer can merge (competitor parity:
// Aikido/Snyk ship fix PRs; we shipped prose).
//
// Propose() alone emits an ActOpenPR whose payload is a BODY — advice a human retypes. ProposeWithPatch
// attaches the real files (path→new content) so connector.Apply commits them to the fix branch and the
// PR carries a diff. Everything else is unchanged: same tier, same HITL gate (§18.2 inv. 3) — a PR is
// a proposal a human reviews, never a write to the default branch.
//
// Honest by construction: no files → we fall back to the prose PR rather than open a PR that claims a
// fix it doesn't contain.

// ProposeWithPatch is Propose for a repository finding the engineer actually patched. files is
// path→complete new content. Returns (action, true) only when the base Propose would.
func ProposeWithPatch(f types.Finding, asset platform.Asset, files map[string]string, idgen func() string) (platform.Action, bool) {
	act, ok := Propose(f, asset, idgen)
	if !ok || len(files) == 0 || act.Kind != platform.ActOpenPR {
		return act, ok // no patch (or not a PR-shaped fix) → unchanged prose behaviour
	}
	// map[string]any so it survives the store's JSON round-trip identically to the rest of the payload.
	fl := make(map[string]any, len(files))
	for k, v := range files {
		fl[k] = v
	}
	act.Payload["files"] = fl
	act.Payload["body"] = patchPRBody(f, files)
	act.Title = "Fix: " + f.Title
	return act, true
}

// patchPRBody is the PR description for a real patch: what was wrong, what changed, and the explicit
// reminder that a human owns the merge. It lists only files we actually rewrote (grounded, §10).
func patchPRBody(f types.Finding, files map[string]string) string {
	var b strings.Builder
	b.WriteString("## Security fix\n\n")
	if f.Title != "" {
		fmt.Fprintf(&b, "**%s**\n\n", f.Title)
	}
	if len(f.CWE) > 0 {
		fmt.Fprintf(&b, "- Weakness: %s\n", strings.Join(f.CWE, ", "))
	}
	if f.Severity != "" {
		fmt.Fprintf(&b, "- Severity: %s\n", f.Severity)
	}
	if f.Endpoint != "" {
		fmt.Fprintf(&b, "- Location: `%s`\n", f.Endpoint)
	}
	if f.RuleID != "" {
		fmt.Fprintf(&b, "- Detected by: `%s`", f.RuleID)
		if f.Tool != "" {
			fmt.Fprintf(&b, " (%s)", f.Tool)
		}
		b.WriteString("\n")
	}
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)
	b.WriteString("\n### Files changed\n")
	for _, p := range paths {
		fmt.Fprintf(&b, "- `%s`\n", p)
	}
	b.WriteString("\n---\nProposed by your AI Security Engineer. Review the diff before merging — ")
	b.WriteString("nothing is applied to your default branch without you.\n")
	return b.String()
}
