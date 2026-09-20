package remediate

import (
	"context"
	"log/slog"
	"strings"

	"github.com/ClatTribe/tsengine/internal/backport"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// backport_wire.go is the CALLER PlanBackports never had.
//
// THE DEFECT THIS CLOSES. `PlanBackports` was complete, tested and had ZERO non-test callers: it
// appeared only in its own file and its own test. So a security fix shipped to the default branch and
// the release branches customers actually run kept the bug, silently — the product knew how to answer
// "which other branches are still vulnerable?" and never asked. The built-but-unwired shape this
// codebase keeps finding, on the one path where the cost is a live vulnerability left in place.
//
// WHEN IT RUNS, stated honestly: at DELIVERY of the fix PR, not at merge. The engine opens the PR; it
// does not control when a human merges it, and waiting for a merge webhook would leave the capability
// dormant for an event we do not reliably receive. Planning at delivery means the reviewer gets the
// default-branch fix and its per-branch companions together, which is also the cheaper review. The
// branch copies are read at this moment, so a branch is judged on the content it has NOW — and if the
// fix PR is never merged, the backport actions are simply approved or rejected on their own merits.
//
// Every produced action is a PROPOSAL routed through the same HITL desk as any other remediation
// (§18.2 inv. 3) — this opens nothing by itself.

// Backporter supplies the two inputs PlanBackports needs for one delivered code fix: the hunk the fix
// applied, and each maintained branch's copy of the file it touched. It is the seam between this
// package (which must not learn how to talk to a forge) and the connector-backed implementation wired
// from platformapi — the same shape as Patcher, for the same reason.
//
// Returning an empty branch list is the normal, honest outcome for a repository with one branch.
type Backporter interface {
	BackportInputs(ctx context.Context, a platform.Action, c platform.Connection, token string) (backport.Hunk, []BranchFile, error)
}

// BackportFunc adapts a function to Backporter.
type BackportFunc func(ctx context.Context, a platform.Action, c platform.Connection, token string) (backport.Hunk, []BranchFile, error)

func (f BackportFunc) BackportInputs(ctx context.Context, a platform.Action, c platform.Connection, token string) (backport.Hunk, []BranchFile, error) {
	return f(ctx, a, c, token)
}

// Submitter queues a freshly proposed action at the human desk (hitl.Desk.Submit). An interface rather
// than the concrete desk on purpose: the desk already imports this package as its Applier, so a
// dependency the other way would be an import cycle.
type Submitter interface {
	Submit(ctx context.Context, a platform.Action) (platform.Action, error)
}

// planBackports runs the planner for a delivered repository fix and queues what it produces.
//
// BEST-EFFORT BY CONSTRUCTION: it is called AFTER the fix PR has been opened, so nothing here may fail
// the delivery — the fix is already shipped, and losing it because a branch listing 403'd would be a
// strictly worse outcome than not backporting. Every early return is a no-op, and each is logged with
// its reason rather than swallowed, because "no backports were proposed" and "we could not look" are
// different facts (§10).
func (d *Deliverer) planBackports(ctx context.Context, a platform.Action, c platform.Connection, token string) {
	if d.Backporter == nil || d.Submit == nil {
		return // not wired on this deployment → exactly today's behaviour
	}
	if a.Kind != platform.ActOpenPR {
		return
	}
	// A backport of a backport is not a thing: the per-branch actions this produces are themselves
	// ActOpenPR, and without this guard delivering one would plan backports of it.
	if rt, _ := a.Payload["remediation_type"].(string); rt == backportRemediationType {
		return
	}
	hunk, branches, err := d.Backporter.BackportInputs(ctx, a, c, token)
	if err != nil {
		slog.Warn("[remediate] backport inputs unavailable — other branches were NOT assessed for this fix",
			"action", a.ID, "tenant", a.TenantID, "err", err.Error())
		return
	}
	if len(branches) == 0 {
		return // one-branch repository, or nothing maintained besides the base: nothing to port
	}
	plans := PlanBackports(a, hunk, branches, d.newID)
	queued, skipped := 0, 0
	for _, p := range plans {
		if p.Action == nil {
			skipped++ // already_applied / not_applicable — deliberately no action
			continue
		}
		if _, serr := d.Submit.Submit(ctx, *p.Action); serr != nil {
			slog.Warn("[remediate] a backport action could not be queued",
				"action", a.ID, "branch", p.Branch, "err", serr.Error())
			continue
		}
		queued++
	}
	slog.Info("[remediate] backports planned for a delivered fix",
		"action", a.ID, "tenant", a.TenantID, "branches", len(branches),
		"queued", queued, "no_action_needed", skipped)
}

// newID generates ids for the planned actions. The Deliverer has no id generator of its own, so it
// derives them from the originating action — deterministic, collision-free per branch, and traceable
// back to the fix that produced them.
func (d *Deliverer) newID() string {
	d.backportSeq++
	return "bp-" + strings.TrimPrefix(itoa(d.backportSeq), "+")
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// backportRemediationType is the payload marker PlanBackports stamps on the actions it produces.
const backportRemediationType = "backport"

// MaintainedBranches filters a repository's branches to the ones worth porting a security fix to.
//
// It is deliberately CONSERVATIVE and deliberately a HEURISTIC, and both matter. A repository's branch
// list is mostly dead feature branches; porting to all of them would open dozens of PRs nobody wants
// and teach the team to ignore the bot. So this matches the conventional release-line shapes only
// (release/*, support/*, maintenance/*, stable, a bare vN / vN.N) and drops everything else, including
// the base branch — which already has the fix.
//
// The cost of the two error directions is asymmetric and chosen: MISSING a branch leaves a known bug
// unported and visible in the next scan of that branch; INVENTING one spams the customer's repository.
// A team whose release lines are named unconventionally gets no backports rather than wrong ones.
func MaintainedBranches(all []string, base string) []string {
	var out []string
	for _, b := range all {
		n := strings.TrimSpace(b)
		if n == "" || strings.EqualFold(n, base) {
			continue
		}
		if maintainedBranch(n) {
			out = append(out, n)
		}
	}
	return out
}

func maintainedBranch(n string) bool {
	l := strings.ToLower(n)
	for _, p := range []string{"release/", "release-", "support/", "maintenance/", "stable/"} {
		if strings.HasPrefix(l, p) {
			return true
		}
	}
	if l == "stable" || l == "main" || l == "master" {
		return true
	}
	// A bare version line: v1, v2.3, 1.x — the other common release-branch convention.
	return versionBranch(l)
}

func versionBranch(l string) bool {
	s := strings.TrimPrefix(l, "v")
	if s == "" || s == l && !isDigit(s[0]) {
		return false
	}
	if !isDigit(s[0]) {
		return false
	}
	for i := 0; i < len(s); i++ {
		if !isDigit(s[i]) && s[i] != '.' && s[i] != 'x' {
			return false
		}
	}
	return true
}

func isDigit(b byte) bool { return b >= '0' && b <= '9' }
