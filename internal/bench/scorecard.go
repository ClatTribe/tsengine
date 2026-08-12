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
	// Corpus describes the EVIDENCE behind Score: how many cases, and who wrote them. It exists
	// because a 1.00 on three cases the author invented and a 0.86 on a hundred a competitor
	// published render identically in a score column, and they are not remotely the same claim.
	Corpus string
	// Shipped reports whether the benchmarked engine is reachable from a CUSTOMER REQUEST, as opposed
	// to only from the CLI and the bench harness.
	//
	// This distinction was missing and it hid two real defects. tsbench cvepatch graded
	// codeagent.ProposePatch at 3/3 while /v1/findings/{id}/autofix called the LLM with its own prompt
	// and never touched codeagent — so the number described code no request could reach. codelocalize
	// scores 1.00 and is not wired into the platform at all. A score on an unshipped engine is a claim
	// about a capability customers do not have, and a scorecard that cannot express that will keep
	// making it.
	Shipped bool
	// ShipNote explains an unshipped engine — what is missing, not just that something is.
	ShipNote string
	// Confidence grades that evidence, so a reader does not have to work it out:
	//   strong      external corpus, ungameable oracle, enough cases to mean something
	//   provisional first-party corpus or too few cases — the bar is met, the capability is unproven
	//   none        unmeasured
	Confidence string
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
			Corpus: "12 cases, first-party synthetic", Confidence: "provisional",
			Shipped: true, Note: "llm + deterministic disposer, median of 4 runs (0.67–0.83). Model alone: 0.50, no better than a path check. Tuning result — the disposer's rules were chosen after seeing the failures.",
		},
		{
			ID: "T2", Name: "Localize — where is the fix?",
			Bench: "tsbench localize --hard", Bar: "recall@1 ≥ 0.80",
			Score: "1.00", Done: true,
			Corpus: "6 cases, first-party synthetic", Confidence: "provisional",
			Shipped: true, Note: "median of 3 runs on the hard corpus. The DEFAULT corpus saturates at 1.00 on the substrate and cannot discriminate — only --hard has headroom.",
		},
		{
			ID: "T3", Name: "Assess — is it reachable/exploitable?",
			Bench: "tsbench xbow", Bar: "≥ 40% of the suite captured",
			Score: "89/104 (0.86)", Done: true,
			Corpus: "104 challenges, EXTERNAL (XBOW's own public suite)", Confidence: "strong",
			Shipped: true, Note: "PROXY, and stated as one: XBOW grades END-TO-END exploitation (find it, then exploit it) — the AI PENTESTER's job — while T3 asks the narrower question 'is THIS already-surfaced finding exploitable'. It is the closest honest instrument we have and it strictly dominates the alternative of no measurement, but it over-states T3 by measuring discovery as well. The best evidence in this repo, and it was missing from earlier versions of this scorecard. XBOW's own 104-challenge suite, graded on FLAG CAPTURE — a random flag injected at build time, retrievable only by real exploitation, so it cannot be gamed by plausible output. Every capture carries an evidence SHA-256. Directly comparable to the suite authors' published rate, unlike every first-party corpus here.",
		},
		{
			ID: "T4", Name: "Fix — produce the change",
			Bench: "tsbench cvepatch --dataset fixtures/cvepatch/seed.json", Bar: "≥ 40% of seeded CVEs closed, execution-verified",
			Score: "3/3 (1.00)", Done: true,
			Corpus: "3 cases, first-party synthetic", Confidence: "provisional",
			Shipped: true, Note: "EXECUTION-VERIFIED, the only ungameable oracle here: a driver runs the exploit AND a regression, so a plausible-looking diff cannot pass. qwen3:8b produced, localized and genuinely FIXED all three seeds (path traversal, command injection, XSS). Small (n=3) and first-party synthetic rather than real CVEs — the instrument was recovered from history, the case set is new. Real-CVE data stays operator-provided.",
		},
		{
			ID: "T5", Name: "Verify — did the fix hold?",
			Bench: "tsbench defense", Bar: "remediation-capture ≥ 0.40",
			Score: "1.00 · 3/3 PASS", Done: true,
			Corpus: "3 scenarios, first-party synthetic", Confidence: "provisional",
			Shipped: true, Note: "100% remediation-capture across repository, cloud and identity scenarios, execution-checked by the product's own retest.Verify so bench and product cannot drift. All three now clear the STRICT pass (closed everything closeable, no decoy actioned, nothing invented) after remediate.WorthProposing put triage in front of the proposer — decoy-actions went 1→0 per scenario with remediation unchanged.",
		},
		{
			ID: "T6", Name: "Answer — query the estate",
			Bench: "", Bar: "correct answer from our own data on a seeded question set",
			Score: "", Done: false, Corpus: "none", Confidence: "none",
			Shipped: true, Note: "search_estate now exists as an agent tool, so the capability is there. Nothing scores whether its answers are right.",
		},
		{
			ID: "T7", Name: "Report — evidence an auditor accepts",
			Bench: "go test ./internal/grc -run TestT7_", Bar: "signed, grounded, control-mapped — and tamper-evident",
			Score: "5/5 tamper cases detected", Done: true,
			Corpus: "5 tamper mutations + wrong-key + unsigned", Confidence: "strong",
			Shipped: true, Note: "The property that makes evidence auditor-grade is not that it is SIGNED — it is that TAMPERING BREAKS THE SIGNATURE. A pack that signs but does not detect alteration carries the authority of a signature with none of the guarantee, which is worse than none at all. All five mutations are detected (a gap flipped to met, an edited gap count, a removed control, a swapped tenant, a swapped framework), and a wrong key and an unsigned pack are both rejected. STRONG confidence because the oracle is cryptographic rather than a judgement call — the one task here whose correctness does not depend on a corpus I wrote.",
		},
		{
			ID: "T8", Name: "Hand off — raise what isn't ours",
			Bench: "", Bar: "ticket filed with the context a receiver can act on",
			Score: "", Done: false, Corpus: "none", Confidence: "none",
			Shipped: true, Note: "open_ticket exists as an agent tool. Unmeasured.",
		},
	}
}

// RenderEngineerScorecard renders the composite against the 40% bar.
func RenderEngineerScorecard(tasks []TaskState) string {
	done, measurable, benchedOnly := 0, 0, 0
	for _, t := range tasks {
		// A task only counts as DONE when it both clears its bar AND is reachable from a customer
		// request. A high score on an engine nobody can reach is a claim about a capability customers
		// do not have — counting it would be the exact overclaiming this field exists to prevent.
		if t.Done && t.Shipped {
			done++
		}
		if t.Done && !t.Shipped {
			benchedOnly++
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
	strong := 0
	for _, t := range tasks {
		if t.Done && t.Confidence == "strong" {
			strong++
		}
	}
	fmt.Fprintf(&b, "**Of the %d passing, %d rest on STRONG evidence** (external corpus, ungameable oracle). ", done, strong)
	b.WriteString("The rest pass on first-party corpora of 3–12 cases the author also wrote — the bar is met, ")
	b.WriteString("the capability is unproven. A 1.00 on three self-authored cases is a bug report about the ")
	b.WriteString("benchmark, not a capability claim.\n\n")
	if benchedOnly > 0 {
		fmt.Fprintf(&b, "**%d task(s) clear their bar but are NOT SHIPPED** — the benchmarked engine has no "+
			"customer-reachable call site, so the score describes a capability nobody can use. They are "+
			"excluded from the efficacy number.\n\n", benchedOnly)
	}
	b.WriteString("| | Task | Benchmark | Score | Evidence | Confidence | Shipped | Done |\n|---|---|---|---|---|---|---|---|\n")
	for _, t := range tasks {
		bench, score, corpus, conf := t.Bench, t.Score, t.Corpus, t.Confidence
		if bench == "" {
			bench = "*none*"
		}
		if score == "" {
			score = "—"
		}
		if corpus == "" {
			corpus = "—"
		}
		if conf == "" {
			conf = "—"
		}
		mark := "no"
		if t.Done && t.Shipped {
			mark = "**yes**"
		}
		ship := "**no**"
		if t.Shipped {
			ship = "yes"
		}
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s | %s | %s | %s |\n", t.ID, t.Name, bench, score, corpus, conf, ship, mark)
	}

	b.WriteString("\n## The other persona\n\n")
	b.WriteString("This scorecard grades the AI Security **Engineer**. The AI **Pentester** is a separate job and ")
	b.WriteString("has, by some distance, the better evidence: `tsbench xbow` — **89 of 104** on the suite ")
	b.WriteString("author's own public challenges, every capture carrying an evidence SHA-256, directly ")
	b.WriteString("comparable to their published rate. That the offensive side is measured this much better ")
	b.WriteString("than the defensive one is itself the finding: the hard external benchmark existed for ")
	b.WriteString("attack and had to be invented for defence.\n\n")

	b.WriteString("## Why the denominator is eight\n\n")
	b.WriteString("A task with no benchmark counts as NOT done. Scoring only the tasks we can measure would ")
	b.WriteString("produce a flattering number that nobody could check — and the missing instruments are ")
	b.WriteString("currently the bigger problem than the scores.\n\n")

	b.WriteString("## The gaps, in the order they should be closed\n\n")
	for _, t := range tasks {
		switch {
		case t.Done && !t.Shipped:
			fmt.Fprintf(&b, "- **%s %s** — SCORES %s BUT IS NOT SHIPPED. %s\n", t.ID, t.Name, t.Score, t.ShipNote)
		case !t.Done:
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
