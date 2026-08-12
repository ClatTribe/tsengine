package crossdetect

import (
	"sort"
	"strconv"

	"github.com/ClatTribe/tsengine/internal/correlate"
)

// chokepoint.go answers the question an attack-path engine exists to answer and this one did not:
// WHICH ONE THING DO I FIX FIRST?
//
// The product already computes cross-surface chains — a leaked key in code reaching a cloud crown
// jewel, a breached SaaS login reaching the same. It then hands over a ranked list of paths. That is
// the correct raw output and it is not an answer: twelve paths ranked by severity still means twelve
// pieces of work, and a founder reading it learns that things are bad rather than what to do on Monday.
//
// The useful observation is that paths OVERLAP. A leaked key, a public bucket and an over-permissive
// role are three findings, but if all three paths run through the same trust relationship then that
// trust relationship is one fix that collapses all three. Naming it turns a list into a decision.
//
// GROUNDED (§10). Everything here is counted from chains the engine already produced — the entity that
// bridges one step to the next, and the finding at each step. Nothing is inferred about the estate that
// the chains did not already assert, and a choke point with a single path is not reported as one,
// because "this appears in one path" is just the path.

// ChokePoint is one thing that appears across multiple attack paths.
type ChokePoint struct {
	// Kind distinguishes what the reader is being asked to fix: "entity" is the shared identifier that
	// bridges steps (a key, a role, a bucket), "finding" is a single weakness that several paths route
	// through. They call for different work, so they are not merged.
	Kind string `json:"kind"`
	// Ref is the entity value or finding id.
	Ref string `json:"ref"`
	// Label is what to show a human.
	Label string `json:"label"`
	// Paths is how many distinct attack paths run through it — the whole point of the ranking.
	Paths int `json:"paths"`
	// WorstSeverity is the severity of the most severe path it appears in, so a choke point on three
	// low paths does not outrank one on a critical.
	WorstSeverity string `json:"worst_severity"`
	// Why states the leverage in the reader's terms.
	Why string `json:"why"`
}

// ChokePoints ranks what appears in the most attack paths, most leverage first.
//
// Returns nothing when no shared element exists — which is a real answer, not a failure: it means each
// path is genuinely separate work, and saying so is more useful than promoting the least-unshared thing
// to look decisive.
func ChokePoints(chains []correlate.Chain) []ChokePoint {
	type agg struct {
		paths int
		worst string
		label string
		kind  string
	}
	// Count each element ONCE per chain — a bridge that repeats inside one path is still one path, and
	// counting repeats would rank a self-referential path above three genuinely distinct ones.
	byRef := map[string]*agg{}
	note := func(kind, ref, label, sev string) {
		if ref == "" {
			return
		}
		k := kind + "\x00" + ref
		a := byRef[k]
		if a == nil {
			a = &agg{kind: kind, label: label}
			byRef[k] = a
		}
		a.paths++
		// NOTE the direction: this package's sevRank is LOWER = WORSE (critical is 0), so "more severe"
		// is a smaller number. An empty a.worst ranks worst-last, so the first severity always wins.
		if a.worst == "" || sevRank(sev) < sevRank(a.worst) {
			a.worst = sev
		}
	}

	for _, c := range chains {
		seen := map[string]bool{}
		for _, s := range c.Steps {
			if s.ViaEntity != "" && !seen["e"+s.ViaEntity] {
				seen["e"+s.ViaEntity] = true
				note("entity", s.ViaEntity, s.ViaEntity, c.Severity)
			}
			if s.FindingID != "" && !seen["f"+s.FindingID] {
				seen["f"+s.FindingID] = true
				label := s.Title
				if label == "" {
					label = s.FindingID
				}
				note("finding", s.FindingID, label, c.Severity)
			}
		}
	}

	out := make([]ChokePoint, 0, len(byRef))
	for k, a := range byRef {
		if a.paths < 2 {
			continue // appearing in one path is not leverage, it IS the path
		}
		ref := k[len(a.kind)+1:]
		cp := ChokePoint{
			Kind: a.kind, Ref: ref, Label: a.label,
			Paths: a.paths, WorstSeverity: a.worst,
		}
		if a.kind == "entity" {
			cp.Why = "This identifier bridges a step in " + pathCount(a.paths) + ". Revoking or rotating it " +
				"severs every one of them."
		} else {
			cp.Why = "This single weakness appears in " + pathCount(a.paths) + ". Fixing it closes all of them."
		}
		out = append(out, cp)
	}

	// Most paths first; then worst severity; then a stable tiebreak so the ranking never reorders
	// between identical runs (a list that shuffles teaches a reader to distrust it).
	sort.Slice(out, func(i, j int) bool {
		if out[i].Paths != out[j].Paths {
			return out[i].Paths > out[j].Paths
		}
		if sevRank(out[i].WorstSeverity) != sevRank(out[j].WorstSeverity) {
			return sevRank(out[i].WorstSeverity) < sevRank(out[j].WorstSeverity) // lower = worse = first
		}
		return out[i].Ref < out[j].Ref
	})
	return out
}

// pathCount phrases the leverage. Deliberately not the package's existing plural() helper — that one
// pluralizes a noun, and this needs the whole phrase so the sentence reads the same in both branches.
func pathCount(n int) string {
	if n == 1 {
		return "1 attack path"
	}
	return strconv.Itoa(n) + " attack paths"
}
