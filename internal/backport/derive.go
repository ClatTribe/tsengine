package backport

// derive.go builds a Hunk from the two file versions a fix produced — the piece that was missing
// between the planner and any real caller.
//
// WHY THIS EXISTS. PlanBackports takes a Hunk and had no production caller, and the reason is visible
// here: the product never holds a DIFF. The remediation pipeline carries WHOLE-FILE content (the AI
// engineer proposes replacements; connector.GitHub.CommitFiles commits whole files), so nothing in the
// tree could produce the one input the planner needs. The planner was pure, tested, and unreachable —
// not for want of wiring, but for want of this function.
//
// It computes ONE hunk spanning the whole changed region rather than a minimal per-run diff. That is
// deliberate: Locate re-finds the site by matching Removed plus surrounding context, so a single
// well-anchored hunk relocates more reliably than several small ones, and a security fix that touches
// two nearby lines should move as one unit or not at all. A file with edits in genuinely separate
// regions yields one hunk spanning both, which Locate will usually refuse to place — the honest
// outcome (needs_adaptation), not a patch guessed into two places.

// ContextLines is how many unchanged lines are captured either side of the change. Three is the
// unified-diff convention, and it is what gives Locate enough to disambiguate between several
// identical candidate sites without over-constraining a branch that has drifted.
const ContextLines = 3

// HunkBetween derives the hunk that turns `before` into `after` for one file.
//
// ok is false when the two versions are identical (nothing to port) — the caller must not
// manufacture a hunk from a no-op change, because Locate would then report "hunk has no changes"
// and every branch would land as not_applicable, which reads exactly like "no branch is affected".
func HunkBetween(file string, before, after []string) (Hunk, bool) {
	// Common prefix.
	start := 0
	for start < len(before) && start < len(after) && before[start] == after[start] {
		start++
	}
	// Common suffix, never crossing the prefix in either version.
	endB, endA := len(before), len(after)
	for endB > start && endA > start && before[endB-1] == after[endA-1] {
		endB--
		endA--
	}
	if start == endB && start == endA {
		return Hunk{}, false // identical
	}

	ctxStart := start - ContextLines
	if ctxStart < 0 {
		ctxStart = 0
	}
	ctxEnd := endB + ContextLines
	if ctxEnd > len(before) {
		ctxEnd = len(before)
	}

	return Hunk{
		File: file,
		// StartLine is the 1-based line the change begins at in the ORIGINAL. Locate treats it as a
		// hint only (it reports an offset when the branch has drifted), never as the truth.
		StartLine: start + 1,
		Before:    append([]string(nil), before[ctxStart:start]...),
		Removed:   append([]string(nil), before[start:endB]...),
		Added:     append([]string(nil), after[start:endA]...),
		After:     append([]string(nil), before[endB:ctxEnd]...),
	}, true
}
