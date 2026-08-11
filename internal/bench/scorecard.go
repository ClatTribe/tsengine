package bench

import (
	"fmt"
	"strings"
)

// scorecard.go computes the composite AI-Security-Engineer efficacy number against the 40% bar.
//
// WHY THE DENOMINATOR IS THE WHOLE JOB. It would be easy — and dishonest — to score only the tasks we
// have benchmarks for and report a flattering percentage. A security engineer's week is eight tasks,
// not the three we happen to be able to measure, so a task with no benchmark counts as NOT DONE. The
// number is deliberately harder to move that way, and it is the only version a customer could check.
//
// WHAT "DONE" MEANS. Per-task, done is: the task completes with no human input beyond approving side
// effects — the Claude Code model. A benchmark score is a proxy for that, so each task carries an
// explicit bar, and clearing the bar is what counts as done. The bars are set at "clearly better than
// what you would get with no AI at all", not at perfection.
//
// The output is designed to make the GAPS louder than the score, because at this stage the missing
// instruments matter more than the readings.

// TaskState is one task's measurement status.
type TaskState struct {
	ID   string // T1…T8
	Name string
	// Bench is the command that measures it, or "" when nothing measures it yet.
	Bench string
	// Bar is the threshold that counts as done, stated in the metric's own terms.
	Bar string
	// Score is the best measured value, or "" when unmeasured.
	Score string
	// Done reports whether the task clears its bar TODAY. Unmeasured is never done.
	Done bool
	// Note is the honest caveat — too few readings, a tuning result, no instrument at all.
	Note string
}

// EngineerScorecard is the current state of the eight tasks.
//
// Hand-maintained rather than computed live, deliberately: the numbers come from runs that need a
// model, a sandbox or fixtures, and inventing them at render time would produce a scorecard that
// always looks healthy. Each entry cites where its number came from so it can be re-derived.
func EngineerScorecard() []TaskState {
	return []TaskState{
		{
			ID: "T1", Name: "Triage — is this real, does it matter?",
			Bench: "tsbench triage", Bar: "Youden J ≥ 0.50 (beat the best deterministic baseline)",
			Score: "0.75", Done: true,
			Note: "llm + deterministic disposer, median of 4 runs (0.67–0.83). Model alone: 0.50, no better than a path check. Tuning result — the disposer's rules were chosen after seeing the failures.",
		},
		{
			ID: "T2", Name: "Localize — where is the fix?",
			Bench: "tsbench localize --hard", Bar: "recall@1 ≥ 0.80",
			Score: "1.00", Done: true,
			Note: "median of 3 runs on the hard corpus. The DEFAULT corpus saturates at 1.00 on the substrate and cannot discriminate — only --hard has headroom.",
		},
		{
			ID: "T3", Name: "Assess — is it reachable/exploitable?",
			Bench: "", Bar: "proven-or-honestly-unproven on a seeded set",
			Score: "", Done: false,
			Note: "The doubt→prove edge is wired and gated, but nothing SCORES it. No instrument.",
		},
		{
			ID: "T4", Name: "Fix — produce the change",
			Bench: "tsbench cvepatch --dataset <set>", Bar: "≥ 40% of seeded CVEs closed, execution-verified",
			Score: "", Done: false,
			Note: "INSTRUMENT RECOVERED from history (it was written, then dropped with an abandoned branch). The oracle is the strongest we have: a driver runs the exploit AND a regression and prints FIXED/NOT_FIXED, so a plausible-looking patch cannot score. Still unmeasured because the dataset is operator-provided and not committed — the remaining work is a runnable case set, not the harness.",
		},
		{
			ID: "T5", Name: "Verify — did the fix hold?",
			Bench: "tsbench defense", Bar: "remediation-capture ≥ 0.40",
			Score: "", Done: false,
			Note: "The right instrument — it re-uses the product's own retest.Verify so bench and product cannot drift — but ONE fixture. One scenario is not a measurement.",
		},
		{
			ID: "T6", Name: "Answer — query the estate",
			Bench: "", Bar: "correct answer from our own data on a seeded question set",
			Score: "", Done: false,
			Note: "search_estate now exists as an agent tool, so the capability is there. Nothing scores whether its answers are right.",
		},
		{
			ID: "T7", Name: "Report — evidence an auditor accepts",
			Bench: "", Bar: "signed, grounded, control-mapped",
			Score: "", Done: false,
			Note: "Strong unit coverage (grc, OSCAL) but no end-to-end efficacy score. Arguably the closest to done of the unmeasured five.",
		},
		{
			ID: "T8", Name: "Hand off — raise what isn't ours",
			Bench: "", Bar: "ticket filed with the context a receiver can act on",
			Score: "", Done: false,
			Note: "open_ticket exists as an agent tool. Unmeasured.",
		},
	}
}

// RenderEngineerScorecard renders the composite against the 40% bar.
func RenderEngineerScorecard(tasks []TaskState) string {
	done, measurable := 0, 0
	for _, t := range tasks {
		if t.Done {
			done++
		}
		if t.Bench != "" {
			measurable++
		}
	}
	efficacy := float64(done) / float64(len(tasks)) * 100
	coverage := float64(measurable) / float64(len(tasks)) * 100

	var b strings.Builder
	b.WriteString("# AI Security Engineer — efficacy scorecard\n\n")
	fmt.Fprintf(&b, "**Efficacy: %.0f%%** (%d of %d tasks clear their bar) — target 40%%\n\n", efficacy, done, len(tasks))
	fmt.Fprintf(&b, "**Measurement coverage: %.0f%%** (%d of %d tasks have a runnable benchmark)\n\n",
		coverage, measurable, len(tasks))
	b.WriteString("| | Task | Benchmark | Bar | Score | Done |\n|---|---|---|---|---|---|\n")
	for _, t := range tasks {
		bench, score := t.Bench, t.Score
		if bench == "" {
			bench = "*none*"
		}
		if score == "" {
			score = "—"
		}
		mark := "no"
		if t.Done {
			mark = "**yes**"
		}
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s | %s |\n", t.ID, t.Name, bench, t.Bar, score, mark)
	}

	b.WriteString("\n## Why the denominator is eight\n\n")
	b.WriteString("A task with no benchmark counts as NOT done. Scoring only the tasks we can measure would ")
	b.WriteString("produce a flattering number that nobody could check — and the missing instruments are ")
	b.WriteString("currently the bigger problem than the scores.\n\n")

	b.WriteString("## The gaps, in the order they should be closed\n\n")
	for _, t := range tasks {
		if !t.Done {
			fmt.Fprintf(&b, "- **%s %s** — %s\n", t.ID, t.Name, t.Note)
		}
	}
	b.WriteString("\n## What the measured tasks say\n\n")
	for _, t := range tasks {
		if t.Done {
			fmt.Fprintf(&b, "- **%s** (%s): %s\n", t.ID, t.Score, t.Note)
		}
	}
	return b.String()
}
