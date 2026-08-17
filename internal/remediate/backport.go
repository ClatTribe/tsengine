package remediate

import (
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/backport"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// BranchFile is one release branch's copy of the file a security fix touched.
// Supplied by the caller (the GitHub/GitLab connector lists branches and fetches
// the blob) so this planner stays pure and testable.
type BranchFile struct {
	Branch string   // e.g. "release/2.3"
	Path   string   // repo-relative path
	Lines  []string // the file's current content on that branch
}

// BackportPlan is the per-branch outcome of porting one fix.
type BackportPlan struct {
	Branch  string
	Verdict backport.Verdict
	AtLine  int
	Reason  string
	// Action is the gated remediation to open on this branch. Nil when no action
	// is warranted (already fixed, or the branch never had the vulnerable code).
	Action *platform.Action
}

// PlanBackports answers the question a security engineer faces the moment a fix
// merges: "which OTHER branches that customers actually run still have this
// bug, and can the same patch land there?"
//
// It relocates the fix into each supplied branch via internal/backport and turns
// the result into gated remediation actions:
//
//   - clean / offset      → an ActOpenPR the human reviews (the patch applies
//     mechanically; a PR is reversible, so tier 1 like any code-fix PR).
//   - needs_adaptation    → an ActFileTicket naming the branch + why the patch
//     does not apply cleanly, so a human (or the code agent) adapts it. We do
//     NOT open a PR with a patch we could not place (§10 — never guess).
//   - already_applied     → NO action. The branch is fixed; re-applying a
//     security patch is a real, damaging failure mode.
//   - not_applicable      → NO action. The branch never had the vulnerable code.
//
// Grounding (§10): every plan cites the originating finding, and the verdict is
// computed from the branch's REAL file content — never from an assumption that
// "the fix probably applies everywhere".
func PlanBackports(f platform.Action, hunk backport.Hunk, branches []BranchFile, idgen func() string) []BackportPlan {
	var out []BackportPlan
	for _, b := range branches {
		r := backport.Locate(b.Lines, hunk)
		p := BackportPlan{Branch: b.Branch, Verdict: r.Verdict, AtLine: r.At, Reason: r.Reason}

		switch r.Verdict {
		case backport.VerdictClean, backport.VerdictOffset:
			patched, ok := backport.Apply(b.Lines, hunk, r)
			if !ok { // defensive: Apply is the authority, not the verdict name
				p.Verdict = backport.VerdictNeedsAdaptation
				p.Reason = "relocation succeeded but the patch would not apply cleanly"
				p.Action = backportTicket(f, b, p.Reason, idgen)
				break
			}
			p.Action = &platform.Action{
				ID:           idgen(),
				TenantID:     f.TenantID,
				FindingID:    f.FindingID,
				FindingIDs:   f.FindingIDs,
				FindingKeys:  f.FindingKeys,
				ConnectionID: f.ConnectionID,
				Kind:         platform.ActOpenPR,
				Tier:         tierOpenPR,
				Status:       platform.ActProposed,
				Title:        fmt.Sprintf("Backport security fix to %s (%s)", b.Branch, b.Path),
				Payload: map[string]any{
					"remediation_type": "backport",
					"branch":           b.Branch,
					"path":             b.Path,
					"backport_verdict": string(r.Verdict),
					"at_line":          r.At,
					"reason":           r.Reason,
					"content":          strings.Join(patched, "\n"),
				},
			}
		case backport.VerdictNeedsAdaptation:
			p.Action = backportTicket(f, b, r.Reason, idgen)
		case backport.VerdictAlreadyApplied, backport.VerdictNotApplicable:
			// Deliberately no action — see the doc comment.
		}
		out = append(out, p)
	}
	return out
}

// backportTicket is the honest fallback: the branch is affected but the patch
// cannot be placed mechanically, so a human/agent is asked to adapt it. A
// ticket is informational + reversible → tier 1, like the other runbook tickets.
func backportTicket(f platform.Action, b BranchFile, reason string, idgen func() string) *platform.Action {
	return &platform.Action{
		ID:           idgen(),
		TenantID:     f.TenantID,
		FindingID:    f.FindingID,
		FindingIDs:   f.FindingIDs,
		FindingKeys:  f.FindingKeys,
		ConnectionID: f.ConnectionID,
		Kind:         platform.ActFileTicket,
		Tier:         1,
		Status:       platform.ActProposed,
		Title:        fmt.Sprintf("Adapt security fix for %s (%s)", b.Branch, b.Path),
		Payload: map[string]any{
			"remediation_type": "backport_adapt",
			"branch":           b.Branch,
			"path":             b.Path,
			"reason":           reason,
			"runbook": fmt.Sprintf(
				"The security fix merged on the primary branch does not apply cleanly to %s (%s): %s. "+
					"Adapt the patch to this branch's code and re-run the fix verification.",
				b.Branch, b.Path, reason),
		},
	}
}
