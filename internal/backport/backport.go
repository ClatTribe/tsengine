// Package backport ports a security fix from the version it was written for to
// another version of the same code — the "backport" task (task 8 in
// docs/security-engineer-tasks-benchmarks.md), measured externally by
// BackportBench.
//
// # WHY THIS EXISTS
//
// A real security engineer rarely gets to ship one patch: the fix lands on main
// and then has to reach the release branches customers actually run, where the
// surrounding code has DIVERGED (lines moved, the function was refactored, the
// call was renamed). That is the whole difficulty — "apply this diff" is easy,
// "apply this diff to code that no longer looks like the diff's context" is not.
//
// THE PROPOSE / DISPOSE SPLIT (§10)
//
// This package is the DISPOSE half, and it is deterministic:
//
//   - It LOCATES the hunk's site in the target version by matching real context
//     lines (exact → offset → whitespace-normalized), never by guessing a line
//     number.
//   - It CLASSIFIES the outcome honestly: clean / offset / already-applied /
//     not-applicable / needs-adaptation. "needs-adaptation" is a refusal to
//     guess, and it is the ONLY case where an LLM should be asked to rewrite the
//     patch — whose output then comes back through Apply + the caller's build
//     and test gates before anything is shipped.
//   - ALREADY-APPLIED detection comes first, because double-applying a security
//     patch is a real and damaging failure mode (it can silently corrupt the
//     fix). A backport that is already present is reported, never re-applied.
//
// So the LLM may PROPOSE an adapted patch; it can never decide that a patch
// applied. That decision is this package's, from the actual file content.
package backport

import (
	"strings"
)

// Verdict is the outcome of locating one hunk in a target version.
type Verdict string

const (
	// VerdictClean — the hunk's context was found exactly where the patch says.
	VerdictClean Verdict = "clean"
	// VerdictOffset — found, but at a different line (code above it moved). Still
	// a mechanical, safe application.
	VerdictOffset Verdict = "offset"
	// VerdictAlreadyApplied — the fix is already present in the target. Must NOT
	// be applied again.
	VerdictAlreadyApplied Verdict = "already_applied"
	// VerdictNeedsAdaptation — the context is recognisable but not an exact
	// match (whitespace/formatting drift, or partial context). A human or an LLM
	// must adapt it; this package refuses to guess.
	VerdictNeedsAdaptation Verdict = "needs_adaptation"
	// VerdictNotApplicable — the code the patch removes is not in this version at
	// all (different code path, or the file was rewritten). Backporting is not
	// meaningful here.
	VerdictNotApplicable Verdict = "not_applicable"
)

// Hunk is one contiguous change from a unified diff, reduced to what relocation
// actually needs: the lines it deletes, the lines it adds, and the surrounding
// context that identifies the site.
type Hunk struct {
	File string
	// StartLine is the 1-based line the hunk applied at in the ORIGINAL version
	// (the diff's own claim — used only as a search hint, never trusted).
	StartLine int
	Before    []string // context lines preceding the change (unchanged)
	Removed   []string // lines the patch deletes
	Added     []string // lines the patch inserts
	After     []string // context lines following the change (unchanged)
}

// Result is the located site + how confident the location is.
type Result struct {
	Verdict Verdict
	// At is the 1-based line in the target where Removed begins (0 when the
	// verdict gives no site).
	At int
	// Offset is At minus the hunk's claimed StartLine (0 for a clean match).
	Offset int
	// Reason is a short human-readable justification — the audit trail for why
	// a backport was applied, skipped, or escalated to adaptation.
	Reason string
}

// Locate finds where a hunk belongs in target (the file's lines, in order) and
// classifies the outcome. It never mutates target.
//
// Order matters: already-applied is checked BEFORE searching for the removed
// lines, because a correctly-backported file no longer contains them and would
// otherwise be misreported as not-applicable.
func Locate(target []string, h Hunk) Result {
	// An empty hunk changes nothing.
	if len(h.Removed) == 0 && len(h.Added) == 0 {
		return Result{Verdict: VerdictNotApplicable, Reason: "hunk has no changes"}
	}

	// 1. Already applied? The added lines are present AND the removed lines are
	// gone. Both halves are required: added-present alone can be coincidence in
	// a file that also still has the vulnerable lines.
	if len(h.Added) > 0 && indexOf(target, h.Added, 0) >= 0 {
		if len(h.Removed) == 0 || indexOf(target, h.Removed, 0) < 0 {
			return Result{
				Verdict: VerdictAlreadyApplied,
				At:      indexOf(target, h.Added, 0) + 1,
				Reason:  "the fix is already present and the vulnerable lines are gone",
			}
		}
	}

	// 2. A pure insertion (no removed lines) anchors on its context.
	if len(h.Removed) == 0 {
		if at := indexOf(target, h.Before, 0); at >= 0 && len(h.Before) > 0 {
			line := at + len(h.Before) + 1
			return Result{Verdict: verdictFor(line, h.StartLine), At: line,
				Offset: line - h.StartLine, Reason: "insertion anchored on preceding context"}
		}
		return Result{Verdict: VerdictNeedsAdaptation, Reason: "insertion context not found; a human/LLM must place it"}
	}

	// 3. Exact match on the removed lines. EVERY candidate site is considered —
	// checking only the first would reject a patch whose context points at a
	// later occurrence — and the context is what disambiguates. A site is only
	// applied when exactly ONE candidate is identified; anything else escalates
	// to adaptation rather than coin-flipping a security patch into one of
	// several plausible places.
	if cands := allIndexes(target, h.Removed); len(cands) > 0 {
		hasCtx := len(h.Before) > 0 || len(h.After) > 0
		var agreeing []int
		if hasCtx {
			for _, at := range cands {
				if contextAgrees(target, h, at) {
					agreeing = append(agreeing, at)
				}
			}
		}
		switch {
		case len(agreeing) == 1:
			line := agreeing[0] + 1
			return Result{Verdict: verdictFor(line, h.StartLine), At: line,
				Offset: line - h.StartLine, Reason: "the removed lines and their surrounding context both match here"}
		case len(agreeing) > 1:
			return Result{Verdict: VerdictNeedsAdaptation, At: agreeing[0] + 1,
				Reason: "several sites match the patch AND its context; a human/LLM must choose"}
		case len(cands) == 1 && !hasCtx:
			// One site and no context to check — nothing to disambiguate.
			line := cands[0] + 1
			return Result{Verdict: verdictFor(line, h.StartLine), At: line,
				Offset: line - h.StartLine, Reason: "exact match on the lines the patch removes (single site)"}
		case len(cands) == 1:
			// The vulnerable lines are here, but the surroundings differ — the
			// function moved or was refactored around them. Recognisable, not
			// mechanically safe.
			return Result{Verdict: VerdictNeedsAdaptation, At: cands[0] + 1,
				Reason: "the removed lines match but the surrounding context does not (code was refactored around them)"}
		default:
			return Result{Verdict: VerdictNeedsAdaptation, At: cands[0] + 1,
				Reason: "the removed lines appear multiple times and the context does not disambiguate"}
		}
	}

	// 4. Whitespace/formatting drift — recognisable but not identical. Report it
	// as needing adaptation rather than applying a patch to reformatted code.
	if at := indexOfNormalized(target, h.Removed); at >= 0 {
		return Result{Verdict: VerdictNeedsAdaptation, At: at + 1,
			Reason: "the code matches only after whitespace normalization (formatting drift)"}
	}

	// 5. Nothing to remove: this version does not contain the vulnerable code.
	return Result{Verdict: VerdictNotApplicable,
		Reason: "the lines the patch removes are not present in this version"}
}

// Apply performs the hunk at the located site, returning the new file lines. It
// REFUSES any verdict that is not mechanically safe — so an already-applied fix
// can't be double-applied and an unadapted patch can't be forced in. ok=false
// leaves target untouched.
func Apply(target []string, h Hunk, r Result) (out []string, ok bool) {
	if r.Verdict != VerdictClean && r.Verdict != VerdictOffset {
		return target, false
	}
	if r.At < 1 || r.At-1+len(h.Removed) > len(target) {
		return target, false
	}
	i := r.At - 1
	out = make([]string, 0, len(target)-len(h.Removed)+len(h.Added))
	out = append(out, target[:i]...)
	out = append(out, h.Added...)
	out = append(out, target[i+len(h.Removed):]...)
	return out, true
}

// verdictFor distinguishes a clean application from a shifted one.
func verdictFor(line, claimed int) Verdict {
	if claimed <= 0 || line == claimed {
		return VerdictClean
	}
	return VerdictOffset
}

// contextAgrees checks the patch's Before/After context around a candidate site.
func contextAgrees(target []string, h Hunk, at int) bool {
	if len(h.Before) > 0 {
		start := at - len(h.Before)
		if start < 0 || !equalAt(target, h.Before, start) {
			return false
		}
	}
	if len(h.After) > 0 {
		start := at + len(h.Removed)
		if start+len(h.After) > len(target) || !equalAt(target, h.After, start) {
			return false
		}
	}
	return true
}

// indexOf returns the first index ≥ from where want appears in hay, else -1.
func indexOf(hay, want []string, from int) int {
	if len(want) == 0 || len(want) > len(hay) {
		return -1
	}
	for i := from; i+len(want) <= len(hay); i++ {
		if equalAt(hay, want, i) {
			return i
		}
	}
	return -1
}

// allIndexes returns every index where want appears in hay.
func allIndexes(hay, want []string) []int {
	var out []int
	for i := 0; ; {
		at := indexOf(hay, want, i)
		if at < 0 {
			return out
		}
		out = append(out, at)
		i = at + 1
	}
}

// indexOfNormalized matches ignoring leading/trailing whitespace and internal
// run-length — i.e. reformatted but semantically identical lines.
func indexOfNormalized(hay, want []string) int {
	nh := make([]string, len(hay))
	for i, s := range hay {
		nh[i] = normalizeLine(s)
	}
	nw := make([]string, len(want))
	for i, s := range want {
		nw[i] = normalizeLine(s)
	}
	return indexOf(nh, nw, 0)
}

// normalizeLine strips ALL whitespace so reformatted-but-identical code matches
// (`exec.Command( "sh" , x )` vs `exec.Command("sh", x)`) — collapsing runs is
// not enough, since formatters also add/remove spaces around punctuation.
//
// This is deliberately aggressive, and it is SAFE because it is used only for
// RECOGNITION: the verdict it produces is needs_adaptation, which never
// auto-applies. Over-recognising escalates to a human/LLM; it can't mis-patch.
// (That also keeps it honest for whitespace-significant languages like Python,
// where indentation differences must never be silently applied.)
func normalizeLine(s string) string { return strings.Join(strings.Fields(s), "") }

func equalAt(hay, want []string, at int) bool {
	for j, w := range want {
		if hay[at+j] != w {
			return false
		}
	}
	return true
}
