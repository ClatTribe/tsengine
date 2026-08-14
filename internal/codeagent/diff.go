package codeagent

import (
	"fmt"
	"strings"
)

// diff.go renders a Patch as a unified diff a human can READ before approving it.
//
// WHY IT EXISTS. A Patch is whole-file replacements — the right representation for APPLYING a fix
// (robust to whitespace and line-ending drift, trivial to verify). It is the wrong representation for
// REVIEWING one: handing a reviewer the full new contents of a 400-line file and asking "approve?"
// is not a review, it is a signature. The reviewer needs the handful of lines that changed.
//
// This is presentation only. The diff never feeds the apply path — Patch.Files remains what gets
// written — so a rendering bug can produce a confusing review but can never change what executes.
//
// The algorithm is a plain LCS over lines. No dependency, and at the size of a security fix (a few
// files, hundreds of lines) the quadratic table is irrelevant. Bounded by maxDiffLines so a
// pathological rewrite cannot produce an unreadable wall of text in the desk UI.

const (
	// contextLines is how many unchanged lines to show around each change — 3 is the git default and
	// what every reviewer's eye is trained on.
	contextLines = 3
	// maxDiffLines caps the rendered output. A fix that rewrites more than this is not reviewable as a
	// diff anyway, and the truncation says so explicitly rather than silently dropping changes.
	maxDiffLines = 400
)

// UnifiedDiff renders the patch against the file contents it will replace.
//
// before maps path → current content. A path absent from before is treated as a NEW file (all lines
// added), which is the honest rendering: we genuinely do not know a prior version.
func (p Patch) UnifiedDiff(before map[string]string) string {
	var b strings.Builder
	total := 0
	for _, f := range p.Files {
		old := before[f.Path]
		if old == f.Content {
			continue // unchanged — showing it would pad the review with noise
		}
		hunks := diffLines(splitLines(old), splitLines(f.Content))
		if len(hunks) == 0 {
			continue
		}
		fmt.Fprintf(&b, "--- a/%s\n+++ b/%s\n", f.Path, f.Path)
		for _, h := range hunks {
			n := strings.Count(h, "\n")
			// The cap has to apply WITHIN a hunk too, not just between them: a whole-file rewrite is a
			// single enormous hunk, so a between-hunks check alone lets it through untruncated.
			if total+n > maxDiffLines {
				if room := maxDiffLines - total; room > 0 {
					lines := strings.SplitAfter(h, "\n")
					if room < len(lines) {
						lines = lines[:room]
					}
					b.WriteString(strings.Join(lines, ""))
				}
				fmt.Fprintf(&b, "@@ … diff truncated at %d lines — review the full file before approving @@\n", maxDiffLines)
				return b.String()
			}
			b.WriteString(h)
			total += n
		}
	}
	return b.String()
}

func splitLines(s string) []string {
	if s == "" {
		return nil
	}
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}

// diffLines produces unified-diff hunks for one file.
func diffLines(a, b []string) []string {
	ops := lcsOps(a, b)
	if len(ops) == 0 {
		return nil
	}
	// Group consecutive edits (with contextLines of surrounding context) into hunks.
	var hunks []string
	i := 0
	for i < len(ops) {
		if ops[i].kind == opEqual {
			i++
			continue
		}
		// Walk back for leading context, forward to the end of this change cluster.
		start := i
		for start > 0 && ops[start-1].kind == opEqual && i-start < contextLines {
			start--
		}
		end := i
		gap := 0
		for end < len(ops) && (ops[end].kind != opEqual || gap < contextLines*2) {
			if ops[end].kind == opEqual {
				gap++
			} else {
				gap = 0
			}
			end++
		}
		// Trim trailing context to contextLines.
		trail := 0
		for end > i && ops[end-1].kind == opEqual && trail < contextLines {
			trail++
			end--
		}
		end += trail

		var h strings.Builder
		aStart, bStart, aCount, bCount := 0, 0, 0, 0
		for j := start; j < end && j < len(ops); j++ {
			o := ops[j]
			if aCount == 0 && bCount == 0 {
				aStart, bStart = o.aLine+1, o.bLine+1
			}
			switch o.kind {
			case opEqual:
				aCount, bCount = aCount+1, bCount+1
			case opDel:
				aCount++
			case opAdd:
				bCount++
			}
		}
		fmt.Fprintf(&h, "@@ -%d,%d +%d,%d @@\n", aStart, aCount, bStart, bCount)
		for j := start; j < end && j < len(ops); j++ {
			o := ops[j]
			switch o.kind {
			case opEqual:
				h.WriteString(" " + o.text + "\n")
			case opDel:
				h.WriteString("-" + o.text + "\n")
			case opAdd:
				h.WriteString("+" + o.text + "\n")
			}
		}
		hunks = append(hunks, h.String())
		i = end
	}
	return hunks
}

type opKind int

const (
	opEqual opKind = iota
	opDel
	opAdd
)

type op struct {
	kind         opKind
	text         string
	aLine, bLine int
}

// lcsOps computes a line-level longest-common-subsequence edit script.
func lcsOps(a, b []string) []op {
	n, m := len(a), len(b)
	// Guard the quadratic table: a huge rewrite is not reviewable as a diff, so fall back to a
	// whole-file replace rather than allocating an n*m table.
	if n*m > 4_000_000 {
		ops := make([]op, 0, n+m)
		for i, l := range a {
			ops = append(ops, op{kind: opDel, text: l, aLine: i, bLine: 0})
		}
		for j, l := range b {
			ops = append(ops, op{kind: opAdd, text: l, aLine: 0, bLine: j})
		}
		return ops
	}
	tbl := make([][]int, n+1)
	for i := range tbl {
		tbl[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				tbl[i][j] = tbl[i+1][j+1] + 1
			} else if tbl[i+1][j] >= tbl[i][j+1] {
				tbl[i][j] = tbl[i+1][j]
			} else {
				tbl[i][j] = tbl[i][j+1]
			}
		}
	}
	var ops []op
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case a[i] == b[j]:
			ops = append(ops, op{kind: opEqual, text: a[i], aLine: i, bLine: j})
			i, j = i+1, j+1
		case tbl[i+1][j] >= tbl[i][j+1]:
			ops = append(ops, op{kind: opDel, text: a[i], aLine: i, bLine: j})
			i++
		default:
			ops = append(ops, op{kind: opAdd, text: b[j], aLine: i, bLine: j})
			j++
		}
	}
	for ; i < n; i++ {
		ops = append(ops, op{kind: opDel, text: a[i], aLine: i, bLine: j})
	}
	for ; j < m; j++ {
		ops = append(ops, op{kind: opAdd, text: b[j], aLine: i, bLine: j})
	}
	// An all-equal script means no change at all.
	for _, o := range ops {
		if o.kind != opEqual {
			return ops
		}
	}
	return nil
}
