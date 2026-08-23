package bench

import (
	"fmt"
	"sort"
	"strings"
)

// Render produces a human-readable bench report for one fixture run.
//
// Every report MUST cite the neutral competitor leaderboard — this is
// the anti-overfit discipline of CLAUDE.md §14.2.2: an L1 recall number
// is meaningless without "vs. what". The fixture loader already rejects
// fixtures with no competitor context, so Competitors is always present.
func Render(f *Fixture, res *RunResult) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== bench: %s (%s) ===\n", f.Name, f.Asset)
	if f.Description != "" {
		fmt.Fprintf(&b, "%s\n", f.Description)
	}
	fmt.Fprintf(&b, "metric:           %s\n", f.Metric)
	fmt.Fprintf(&b, "trials:           %d\n", res.RecallStats.N)
	fmt.Fprintf(&b, "detection recall: median=%.3f  p10=%.3f  p90=%.3f\n",
		res.RecallStats.Median, res.RecallStats.P10, res.RecallStats.P90)
	fmt.Fprintf(&b, "L1.5 enrichment:  median=%.3f  p10=%.3f  p90=%.3f\n",
		res.EnrichStats.Median, res.EnrichStats.P10, res.EnrichStats.P90)

	if len(res.Scores) > 0 {
		last := res.Scores[len(res.Scores)-1]
		fmt.Fprintf(&b, "raw findings:     %d\n", last.RawFindings)
		if len(last.Missed) > 0 {
			fmt.Fprintf(&b, "MISSED:           %s\n", strings.Join(last.Missed, ", "))
		}
		if len(last.FalsePositives) > 0 {
			fmt.Fprintf(&b, "FALSE POSITIVES:  %s\n", strings.Join(last.FalsePositives, ", "))
		}
		b.WriteString(renderScope(last.Scope))
	}

	b.WriteString(renderCompetitors(f.Competitors))

	verdict := "PASS"
	switch {
	case res.Unmeasured:
		// Deliberately its own verdict rather than a FAIL. The run was cut off, so
		// the number it produced is about the clock, not the product — reporting it
		// as a failure is how a timeout gets published as a detection gap.
		verdict = "UNMEASURED"
	case !res.AllPass:
		verdict = "FAIL"
	}
	fmt.Fprintf(&b, "verdict:          %s\n", verdict)
	if res.Unmeasured {
		fmt.Fprintf(&b, "why unmeasured:   %s\n", res.UnmeasuredReason)
	}
	return b.String()
}

// renderCompetitors formats the neutral competitor scorecard. Always
// emits a "competitors:" line so the render_report guard can assert it.
func renderCompetitors(c Competitors) string {
	var b strings.Builder
	b.WriteString("competitors:\n")
	if c.Leaderboard != "" {
		fmt.Fprintf(&b, "  leaderboard: %s\n", c.Leaderboard)
	}
	if len(c.Scores) > 0 {
		names := make([]string, 0, len(c.Scores))
		for n := range c.Scores {
			names = append(names, n)
		}
		sort.Strings(names)
		parts := make([]string, 0, len(names))
		for _, n := range names {
			parts = append(parts, fmt.Sprintf("%s %s", n, c.Scores[n]))
		}
		fmt.Fprintf(&b, "  scores:      %s\n", strings.Join(parts, " / "))
	}
	if c.Note != "" {
		fmt.Fprintf(&b, "  note:        %s\n", c.Note)
	}
	return b.String()
}

// RenderStub formats a non-runnable fixture: its competitor numbers
// plus why it can't run yet. The competitor citation is the point —
// the comparison framework is ready even before the corpus is deployed.
func RenderStub(f *Fixture) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== bench: %s (%s) [STUB — not runnable] ===\n", f.Name, f.Asset)
	if f.Description != "" {
		fmt.Fprintf(&b, "%s\n", f.Description)
	}
	fmt.Fprintf(&b, "metric:           %s\n", f.Metric)
	b.WriteString(renderCompetitors(f.Competitors))
	fmt.Fprintf(&b, "verdict:          SKIP (deploy corpus + set runnable:true to run)\n")
	return b.String()
}

// RenderAblation formats the L1.5-lift comparison.
func RenderAblation(f *Fixture, a *Ablation) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== L1.5 ablation: %s ===\n", f.Name)
	fmt.Fprintf(&b, "detection recall   L1.5-on=%.3f  L1.5-off=%.3f  (Δ=%.3f — expect ~0; L1.5 is translation, not detection)\n",
		a.Enabled.RecallStats.Median, a.Disabled.RecallStats.Median,
		a.Enabled.RecallStats.Median-a.Disabled.RecallStats.Median)
	fmt.Fprintf(&b, "enrichment coverage L1.5-on=%.3f  L1.5-off=%.3f  (Δ=%.3f — THIS is the L1.5 lift)\n",
		a.Enabled.EnrichStats.Median, a.Disabled.EnrichStats.Median,
		a.Enabled.EnrichStats.Median-a.Disabled.EnrichStats.Median)
	return b.String()
}

// renderScope prints the honest denominator directly beneath the recall figure it
// qualifies.
//
// IT MUST BE HERE, NOT ONLY IN THE JSON. The scope was added so a perfect recall over a
// one-token must_find could not be read as total coverage — and then it was computed and
// rendered nowhere, leaving the report saying exactly what the scope exists to prevent.
// That is the same defect this codebase keeps finding — a signal computed for a consumer
// that never consumes it — introduced by the change meant to fix it.
//
// The uncovered classes are NAMED, not counted: a count says something is missing without
// letting anyone see what, or disagree with the judgement.
func renderScope(sc *ScopeCoverage) string {
	if sc == nil {
		return "" // the fixture documents no denominator; claiming one would invent it
	}
	var b strings.Builder
	fmt.Fprintf(&b, "scope:            %d of %d documented defect classes are detectable; this fixture gates on %d\n",
		sc.Detectable, sc.Documented, sc.Measured)
	if len(sc.OWASPCovered) > 0 {
		fmt.Fprintf(&b, "  OWASP covered:   %s\n", strings.Join(sc.OWASPCovered, " "))
	}
	if len(sc.OWASPGated) > 0 {
		// Named separately because a customer running a normal scan does not get these.
		fmt.Fprintf(&b, "  OWASP gated:     %s  (detected only behind a precondition)\n", strings.Join(sc.OWASPGated, " "))
	}
	if len(sc.OWASPUncovered) > 0 {
		fmt.Fprintf(&b, "  OWASP uncovered: %s\n", strings.Join(sc.OWASPUncovered, " "))
	}
	if len(sc.UncoveredClasses) > 0 {
		fmt.Fprintf(&b, "  NOT DETECTED:    %s\n", strings.Join(sc.UncoveredClasses, "; "))
	}
	if len(sc.GatedClasses) > 0 {
		fmt.Fprintf(&b, "  gated classes:   %s\n", strings.Join(sc.GatedClasses, "; "))
	}
	return b.String()
}
