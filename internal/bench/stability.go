package bench

import (
	"context"
	"fmt"
	"os"
	"sort"
	"strings"

	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Finding stability — does the same scan of the same unchanged target return the same findings?
//
// # Why this is a first-class metric
//
// Measured on this engine: four identical api scans of one unchanged VAmPI instance returned 1, 1,
// 11 and 11 findings, with three different toolsets, and partial=false every time. Tools lost their
// per-tool timeout race under machine load and were dropped silently.
//
// That is not a recall problem and recall cannot see it. A per-asset Youden score is computed from a
// SINGLE run, so it reports whichever of those four outcomes it happened to draw. The industry
// framing is blunt: if a critical finding appears in 3 of 5 runs, a CI gate passes it 40% of the
// time. For a customer it means a vulnerability found on Monday can be absent on Tuesday with
// nothing changed and nothing reported as degraded.
//
// The measurement is the one external practice converged on — run the same scan N times and report
// what fraction of findings appear in EVERY run, plus whether severity stayed consistent for the
// ones that did.
//
// Identity is detect.Key (rule_id|endpoint), the same key the incident detector, retest verifier and
// defense bench use. Stability must mean "the same finding" in exactly the sense the product means
// it, or the number measures a definition nobody else applies.

// FlakyFinding is one finding that did not appear in every run.
type FlakyFinding struct {
	Key        string   `json:"key"`
	SeenInRuns int      `json:"seen_in_runs"`
	Severities []string `json:"severities,omitempty"` // distinct severities observed, when they differed
}

// StabilityReport is the multi-run scorecard.
type StabilityReport struct {
	Runs int `json:"runs"`
	// Distinct is the union of finding keys across all runs.
	Distinct int `json:"distinct"`
	// Stable is how many appeared in EVERY run.
	Stable int `json:"stable"`
	// StabilityRate is Stable/Distinct — 1.0 means every run agreed exactly.
	StabilityRate float64 `json:"stability_rate"`
	// SeverityInconsistent counts findings that appeared with more than one severity across runs.
	// A finding present in every run is still unreliable if it is high on Monday and low on Tuesday:
	// the escalation threshold is severity-based, so this decides whether an incident opens.
	SeverityInconsistent int `json:"severity_inconsistent"`
	// Flaky lists the unstable findings, worst first.
	Flaky []FlakyFinding `json:"flaky,omitempty"`
	// ToolsetVaried reports whether the runs dispatched different toolsets — the usual CAUSE of
	// instability, and the reason Scan.ToolsFailed is recorded.
	ToolsetVaried bool     `json:"toolset_varied"`
	Toolsets      []string `json:"toolsets,omitempty"`
	// FailedTools names tools that failed in at least one run, deduped.
	FailedTools []string `json:"failed_tools,omitempty"`
}

// ScoreStability compares N scans of the same unchanged target.
//
// Fewer than two runs cannot measure agreement, so the report is returned with Runs set and
// StabilityRate zero rather than a fabricated 1.0 — an unmeasurable quantity is not a perfect one
// (§10).
func ScoreStability(runs []*types.Scan) *StabilityReport {
	rep := &StabilityReport{Runs: len(runs)}
	if len(runs) < 2 {
		return rep
	}

	seen := map[string]int{}                   // key → number of runs containing it
	severities := map[string]map[string]bool{} // key → distinct severities
	toolsets := map[string]bool{}
	failed := map[string]bool{}

	for _, scan := range runs {
		if scan == nil {
			continue
		}
		// Grade the delivered set: it is what the customer is shown, and what instability actually
		// costs them.
		inThisRun := map[string]bool{}
		for _, f := range scan.FindingsEnriched {
			k := detect.Key(f)
			if !inThisRun[k] {
				inThisRun[k] = true
				seen[k]++
			}
			if severities[k] == nil {
				severities[k] = map[string]bool{}
			}
			severities[k][string(f.Severity)] = true
		}
		fired := append([]string{}, scan.AnchorsFired...)
		sort.Strings(fired)
		toolsets[strings.Join(fired, ",")] = true
		for _, tf := range scan.ToolsFailed {
			failed[tf.Tool] = true
		}
	}

	rep.Distinct = len(seen)
	for k, n := range seen {
		if n == len(runs) {
			rep.Stable++
		} else {
			f := FlakyFinding{Key: k, SeenInRuns: n}
			rep.Flaky = append(rep.Flaky, f)
		}
		if len(severities[k]) > 1 {
			rep.SeverityInconsistent++
			// Surface the disagreement on the flaky entry when there is one.
			for i := range rep.Flaky {
				if rep.Flaky[i].Key == k {
					rep.Flaky[i].Severities = sortedKeys(severities[k])
				}
			}
		}
	}
	if rep.Distinct > 0 {
		rep.StabilityRate = float64(rep.Stable) / float64(rep.Distinct)
	}
	sort.Slice(rep.Flaky, func(i, j int) bool {
		if rep.Flaky[i].SeenInRuns != rep.Flaky[j].SeenInRuns {
			return rep.Flaky[i].SeenInRuns < rep.Flaky[j].SeenInRuns
		}
		return rep.Flaky[i].Key < rep.Flaky[j].Key
	})

	rep.ToolsetVaried = len(toolsets) > 1
	rep.Toolsets = sortedKeys(toolsets)
	rep.FailedTools = sortedKeys(failed)
	return rep
}

func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// RenderStability formats the scorecard.
func RenderStability(r *StabilityReport) string {
	var b strings.Builder
	fmt.Fprintf(&b, "=== finding stability (%d runs, same unchanged target) ===\n", r.Runs)
	if r.Runs < 2 {
		b.WriteString("not measurable: agreement needs at least 2 runs.\n")
		return b.String()
	}
	fmt.Fprintf(&b, "stability rate:   %.1f%%  (%d of %d distinct findings appeared in EVERY run)\n",
		r.StabilityRate*100, r.Stable, r.Distinct)
	if r.SeverityInconsistent > 0 {
		fmt.Fprintf(&b, "severity drift:   %d finding(s) reported at more than one severity.\n"+
			"                  Escalation is severity-gated, so these decide whether an incident opens.\n",
			r.SeverityInconsistent)
	}
	if r.ToolsetVaried {
		fmt.Fprintf(&b, "toolset:          VARIED across runs — the usual cause. Distinct toolsets seen:\n")
		for _, t := range r.Toolsets {
			fmt.Fprintf(&b, "                    %s\n", t)
		}
	} else {
		fmt.Fprintf(&b, "toolset:          identical across runs\n")
	}
	if len(r.FailedTools) > 0 {
		fmt.Fprintf(&b, "tools that failed in >=1 run: %s\n", strings.Join(r.FailedTools, ", "))
	}
	if n := len(r.Flaky); n > 0 {
		fmt.Fprintf(&b, "flaky findings (%d), least-reliable first:\n", n)
		for i, f := range r.Flaky {
			if i >= 10 {
				fmt.Fprintf(&b, "  ... +%d more\n", n-10)
				break
			}
			sev := ""
			if len(f.Severities) > 0 {
				sev = "  severities=" + strings.Join(f.Severities, "/")
			}
			fmt.Fprintf(&b, "  %d/%d runs  %s%s\n", f.SeenInRuns, r.Runs, f.Key, sev)
		}
	}
	b.WriteString("\nA finding present in only some runs is one a CI gate passes some of the time.\n")
	return b.String()
}

// RunStability scans the same target N times and scores agreement between the runs.
//
// The target must be unchanged between runs — that is the whole premise. Any variation in the
// result is then the engine's, not the target's.
func RunStability(ctx context.Context, assetType, target string, runs int, opts RunOptions) (*StabilityReport, error) {
	if runs < 2 {
		return nil, fmt.Errorf("stability needs at least 2 runs, got %d: one run cannot measure agreement", runs)
	}
	opts = opts.withDefaults()
	fx := &Fixture{Name: "stability", Asset: assetType, Target: target}

	scans := make([]*types.Scan, 0, runs)
	for i := 0; i < runs; i++ {
		fmt.Fprintf(os.Stderr, "[stability] run %d/%d\n", i+1, runs)
		scan, err := runOnce(ctx, fx, opts)
		if err != nil {
			// A run that ERRORS is not a run that found nothing. Scoring it as an empty result would
			// invent instability the engine did not exhibit — the same conflation this whole metric
			// exists to expose.
			return nil, fmt.Errorf("stability: run %d/%d failed: %w", i+1, runs, err)
		}
		scans = append(scans, scan)
	}
	return ScoreStability(scans), nil
}
