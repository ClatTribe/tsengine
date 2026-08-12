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
	// Engine records WHAT WAS MEASURED: "model" when the score depends on an LLM's judgement,
	// "deterministic" when it is produced by ordinary code with no model in the loop.
	//
	// This column exists because auditing T5 found the scorecard crediting the AI engineer for a
	// result the LLM had no part in: all eleven `tsbench defense` runs in the ledger are mode=substrate
	// — an agent arm has never been run — yet the entry sat in a scorecard titled "AI Security
	// Engineer" reading 1.00. The bench itself was honest (it prints "substrate (deterministic
	// remediation)" and separates the two so the delta is the agent's lift); the scorecard was where
	// that distinction got lost.
	//
	// Deterministic is not a lesser result — for "did the fix hold?" re-running the test is the RIGHT
	// answer and asking a model would be worse. The error was never the design, only the presentation:
	// a reader cannot otherwise tell which half of the product a number is about.
	Engine string
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
			Corpus: "12 cases, first-party synthetic", Engine: "model", Confidence: "provisional",
			Shipped: true, Note: "llm + deterministic disposer, median of 4 runs (0.67–0.83). Model alone: 0.50, no better than a path check. Tuning result — the disposer's rules were chosen after seeing the failures. THE SCORER ITSELF HAD NO TESTS until now: every triage number quoted here came out of untested arithmetic, and the rendered table asserts to the reader that keep-everything and drop-everything both score 0 — the entire argument for Youden over accuracy — with nothing behind it. Now pinned: degenerate strategies score 0, a perfect engine scores 1, a hand-worked case matches, and an engine that ERRORS is not scored as if it answered. Mutation-checked — replacing Youden with plain recall makes keep-everything score 1.00 and two tests fail.",
		},
		{
			ID: "T2", Name: "Localize — where is the fix?",
			Bench: "tsbench localize --hard", Bar: "recall@1 ≥ 0.80",
			Score: "1.00", Done: true,
			Corpus: "6 cases, first-party synthetic", Engine: "model", Confidence: "provisional",
			Shipped: true, Note: "THE SHIPPED TIER WAS NOT THE BENCHMARKED TIER until now. This entry quoted 1.00 (the LLM tier) while the customer-reachable adapter hardcoded HeuristicLocalizer — the 0.67 floor. The engine shipped; the tier did not, which is the Shipped column's own failure mode one layer deeper. The adapter now runs LLMLocalizer, which uses the heuristic as its floor and fallback, grounds every model proposal against real repo files, and degrades to the pure heuristic on a nil or erroring model — so a deployment without a model behaves exactly as before and one with a model can only rank up, never drop a heuristic hit. Reachable by a human too as of GET /v1/findings/{id}/localize. Median of 3 runs on the hard corpus. The DEFAULT corpus saturates at 1.00 on the substrate and cannot discriminate — only --hard has headroom.",
		},
		{
			ID: "T3", Name: "Assess — is it reachable/exploitable?",
			Bench: "tsbench xbow", Bar: "≥ 40% of the suite captured",
			Score: "pass@1 78/104 (0.75) · best-of-retry 89/104 (0.86)", Done: true,
			Corpus: "104 challenges, EXTERNAL (XBOW's own public suite)", Engine: "model", Confidence: "strong",
			Shipped: true, Note: "PROXY, and stated as one: XBOW grades END-TO-END exploitation (find it, then exploit it) — the AI PENTESTER's job — while T3 asks the narrower question 'is THIS already-surfaced finding exploitable'. It is the closest honest instrument we have and it strictly dominates the alternative of no measurement, but it over-states T3 by measuring discovery as well. The best evidence in this repo, and it was missing from earlier versions of this scorecard. XBOW's own 104-challenge suite, graded on FLAG CAPTURE — a random flag injected at build time, retrievable only by real exploitation, so it cannot be gamed by plausible output. Every capture carries an evidence SHA-256. WHAT THE 89 ACTUALLY IS, checked against bench/xbow-ledger.jsonl rather than taken on trust: 111 attempts over 97 distinct challenges across two days, 89 solved AT LEAST ONCE. Twelve challenges were attempted more than once and ELEVEN of those failed before they succeeded — so 0.86 is a best-of-retry figure, closer to pass@k than pass@1. First-attempt only is 78/104 = 0.75, an eleven-point gap. Retries are legitimate in agent benchmarking WHEN DISCLOSED, which is why both numbers are now on the entry. This also retracts a comparability claim that used to sit here: 'directly comparable to the suite authors' published rate' only holds if their figure is also best-of-retry, and that has not been checked — against a published pass@1 the old line flattered us by those eleven points. It remains the best evidence in this repo; it is not evidence of whichever number reads highest.",
		},
		{
			ID: "T4", Name: "Fix — produce the change",
			Bench: "tsbench cvepatch --dataset fixtures/cvepatch/seed.json", Bar: "≥ 40% of seeded CVEs closed, execution-verified",
			Score: "median 3/3 · range 2/3-3/3", Done: true,
			Corpus: "3 cases, first-party synthetic", Engine: "model", Confidence: "provisional",
			Shipped: true, Note: "EXECUTION-VERIFIED, the only ungameable oracle here: a driver runs the exploit AND a regression, so a plausible-looking diff cannot pass. THE ORACLE IS NOW PROVEN ABLE TO SAY NO (TestT4Oracle_RejectsAnUnfixedPatch): every observed run had returned fixed or unknown and a not_fixed had never actually been seen, which makes a working grader indistinguishable from one incapable of failing. Handing it the UNCHANGED vulnerable file is refused on all three seeds — so an engine that echoed its input would score zero, and these numbers are measurements rather than a rubber stamp. The yes-direction needs no separate test: the real runs grade model patches fixed. RE-RUNNING CORRECTED THIS ENTRY: it read a flat '3/3 (1.00)', which was the BEST run recorded as the score. Three runs give 3/3, 2/3, 3/3 - the same 8B non-determinism T1 shows across its 0.67-0.83 spread, with path-traversal the case that intermittently produces no patch at all, and nothing in codeagent changed between those runs. A single best run quoted as a capability is exactly the overclaiming the Confidence column exists to catch, so this is now the median with its range, matching how T1 and T2 are reported. It clears the 0.40 bar at every observation. Small (n=3) and first-party synthetic rather than real CVEs — the instrument was recovered from history, the case set is new. Real-CVE data stays operator-provided.",
		},
		{
			ID: "T5", Name: "Verify — did the fix hold?",
			Bench: "tsbench defense", Bar: "remediation-capture ≥ 0.40",
			Score: "remediation 1.00 · 3/4 strict PASS · agent decoys 1 vs substrate 2", Done: true,
			Corpus: "4 scenarios, first-party synthetic", Engine: "model + deterministic", Confidence: "provisional",
			Shipped: true, Note: "THE AGENT NOW SHOWS A MEASURED LIFT, once a scenario existed that could show one. The original three could not: their decoys are LOW severity, so remediate.WorthProposing drops them on severity alone and the substrate scored a perfect 0 decoy-actions without exercising judgement — no headroom, so both arms had to tie, which they did. The new high-severity-noise scenario puts every decoy at HIGH severity in ordinary application code, outside any test/fixture/docs path, so neither the severity rule nor the path heuristic can rescue an engine. There the substrate actions BOTH decoys (2) and the agent actions ONE (1, stable across four runs) with remediation unchanged at 2/2 — the first real substrate-to-agent delta on the defensive side. NEITHER ARM PASSES that scenario strictly (a strict pass needs zero decoy-actions), which is the point of adding it: 3 of 4 pass, and the 4th is where the arms separate. A scenario every engine passes cannot rank engines. A component-level probe locates the remaining miss precisely: the model reliably drops sample credentials shown in onboarding UI copy (3/3) but keeps a Stripe pk_test_ PUBLISHABLE key (2/3), i.e. it does not reliably know that key class is designed to be public. That is a nameable knowledge gap rather than a score. PREVIOUSLY the agent arm was declared and unimplemented; it refused honestly rather than scoring the substrate under an agent label, which is why the ledger was trustworthy enough to audit at all. AGENT LIFT WAS ZERO — but read why before reading that as a result about the model. `--mode agent` was declared and unimplemented (it refused honestly rather than scoring the substrate under an agent label, so the ledger stayed trustworthy); it is now wired to the SAME composed triager the product ships for T1 — the model decides which findings deserve work, remediate.Propose still builds the action, so the delta is the agent's TRIAGE and the model can never invent an action the deterministic proposer would not produce. Three agent runs now sit beside eleven substrate runs in the ledger and score IDENTICALLY: 3/3 PASS, 100% remediation, 0 decoys, 0 invented. THE BENCHMARK CANNOT SHOW A LIFT HERE, because the substrate already scores 1.00 — there is no headroom, exactly the flaw already noted on the localize DEFAULT corpus. So this is not evidence the model adds nothing; it is evidence the corpus cannot tell. A discriminating scenario set (decoys the severity heuristic actions and a human would not) is what would make the comparison mean something. PREVIOUSLY: this entry measured only the substrate — checked against bench/defense-ledger.jsonl: all ELEVEN runs are mode=substrate and an agent arm has never been run, yet this sat in a scorecard titled AI Security Engineer reading 1.00. For THIS task deterministic is the right answer — \"did the fix hold?\" should be settled by re-running the test, not by asking a model — so the design is correct and only the presentation was wrong. The bench always said so (it prints \"substrate (deterministic remediation)\" and keeps the two arms apart precisely so the delta is the agent's lift); the scorecard is where that got lost. The agent lift for T5 is therefore UNMEASURED, not zero. 100% remediation-capture across repository, cloud and identity scenarios, execution-checked by the product's own retest.Verify so bench and product cannot drift. All three now clear the STRICT pass (closed everything closeable, no decoy actioned, nothing invented) after remediate.WorthProposing put triage in front of the proposer — decoy-actions went 1→0 per scenario with remediation unchanged.",
		},
		{
			ID: "T6", Name: "Answer — query the estate",
			Bench: "go test ./internal/platformapi -run TestT6_", Bar: "correct answer from our own data on a seeded question set",
			Score: "5/5", Done: true,
			Corpus: "5 questions, first-party synthetic", Engine: "deterministic", Confidence: "provisional",
			Shipped: true, Note: "T6 is the one task where a WRONG answer does more damage than a missing one: an engineer who asks 'are we exposed to log4j?' acts on the reply, and a search that silently omits a match produces a false all-clear about the customer's own estate — indistinguishable downstream from a genuinely clean result, since both render as an empty list. The five cover the ways that happens: a match found anywhere in the finding rather than only the title (the log4j case hides in the package coordinate), unrelated findings NOT swept in, the header count agreeing with the rows shown, worst-severity-first so a truncated list still leads with the critical, and 'unproven' excluding what is already proven. Deterministic oracle — no model grades these — so it is firmer than the LLM-scored tasks at equal corpus size, but five self-authored questions is still five self-authored questions. MUTATION-CHECKED: making the matcher accept every finding regardless of query fails two of the five, so these detect a broken search rather than merely describing a working one.",
		},
		{
			ID: "T7", Name: "Report — evidence an auditor accepts",
			Bench: "go test ./internal/grc -run TestT7_", Bar: "signed, grounded, control-mapped — and tamper-evident",
			Score: "5/5 tamper cases detected", Done: true,
			Corpus: "5 tamper mutations + wrong-key + unsigned", Engine: "deterministic", Confidence: "strong",
			Shipped: true, Note: "The property that makes evidence auditor-grade is not that it is SIGNED — it is that TAMPERING BREAKS THE SIGNATURE. A pack that signs but does not detect alteration carries the authority of a signature with none of the guarantee, which is worse than none at all. All five mutations are detected (a gap flipped to met, an edited gap count, a removed control, a swapped tenant, a swapped framework), and a wrong key and an unsigned pack are both rejected. STRONG confidence because the oracle is cryptographic rather than a judgement call — the one task here whose correctness does not depend on a corpus I wrote. MUTATION-CHECKED, and it found something worth knowing: neutering the content-hash check alone changes nothing, and neutering the signature check alone still leaves tampering caught — the pack is protected by TWO independent mechanisms, either sufficient. Only with BOTH disabled does the tamper test fail, which is what proves the test is not vacuous.",
		},
		{
			ID: "T8", Name: "Hand off — raise what isn't ours",
			Bench: "go test ./internal/platformapi -run TestT8_", Bar: "ticket filed with the context a receiver can act on",
			Score: "5/5", Done: true,
			Corpus: "5 cases, first-party — 3 refusals, 2 content", Engine: "deterministic", Confidence: "provisional",
			Shipped: true, Note: "MEASURING THIS FOUND A REAL HOLE. open_ticket is the only engineer tool that WRITES into the customer's queue, and at tier 1 it auto-delivers to their real tracker stamped raised_by:ai-security-engineer. It took free text alone — so the model could file a ticket asserting anything, citing nothing anyone downstream could check, while every sibling tool (propose_fix, request_proof, locate_vulnerability) was anchored to a finding. Action.FindingID is documented 'always set — grounding' and this path left it empty. It now requires a finding id the adapter RESOLVES against the tenant's own findings, refusing when it does not exist (§10, and §18.2 inv. 2 — another tenant's id is unresolvable, not merely unauthorized), and stamps severity/location/tool/rule so a receiver on another team can act without coming back to ask. The pre-existing T8 self-test passed while citing NOTHING, which is how the hole survived: it asserted a ticket appeared, never that it was about anything real. MUTATION-CHECKED: removing the finding-resolution refusal fails two of the five.",
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
	strong := 0
	for _, t := range tasks {
		if t.Done && t.Confidence == "strong" {
			strong++
		}
	}
	// VERIFIABLE is the number that still has headroom. Efficacy counts tasks that clear a bar; once
	// every task has an instrument it pins at 100% and stops carrying information, while the thing that
	// actually limits the claim — how much of it rests on evidence we did not author — is unchanged at
	// 2 of 8. Reporting only the saturated number is how a scorecard turns into marketing.
	verifiable := float64(strong) / float64(len(tasks)) * 100

	b.WriteString("# AI Security Engineer — efficacy scorecard\n\n")
	fmt.Fprintf(&b, "**Efficacy: %.0f%%** (%d of %d tasks clear their bar) — target 40%%\n\n", efficacy, done, len(tasks))
	fmt.Fprintf(&b, "**Measurement coverage: %.0f%%** (%d of %d tasks have a runnable benchmark)\n\n",
		coverage, measurable, len(tasks))
	fmt.Fprintf(&b, "**Verifiable: %.0f%%** (%d of %d rest on evidence we did not author) — the number with "+
		"headroom left\n\n", verifiable, strong, len(tasks))

	// WHICH HALF OF THE PRODUCT IS THIS. Four of the eight scores come from an LLM's judgement and four
	// from ordinary deterministic code. In a document titled "AI Security Engineer" that is not a
	// detail: half the number describes machinery a model never touched. Deterministic is often the
	// BETTER engine for a task (re-running a test beats asking a model whether a fix held), so this is
	// not an admission of weakness — it is the difference between "the AI does this" and "the product
	// does this", which a single efficacy percentage silently merges.
	model := 0
	for _, t := range tasks {
		if t.Done && t.Engine == "model" {
			model++
		}
	}
	fmt.Fprintf(&b, "**Of the %d passing, %d depend on an LLM's judgement; %d are produced by deterministic "+
		"code with no model in the loop.** Deterministic is frequently the better engine — \"did the fix "+
		"hold?\" is settled by re-running the test, not by asking a model — so read this as scope, not "+
		"weakness. It is the difference between \"the AI does this\" and \"the product does this\", which "+
		"one efficacy percentage merges into nothing.\n\n", done, model, done-model)

	// A saturated headline is not an achievement, it is an exhausted denominator. Say so, or every
	// future reader takes 100% to mean the job is done rather than the ruler is used up.
	if done == len(tasks) {
		b.WriteString("> **100% here means the denominator is exhausted, not that the work is finished.** ")
		b.WriteString("This scorecard was built to make the missing instruments louder than the readings; ")
		b.WriteString("with every task instrumented it has done that job and can no longer tell you ")
		b.WriteString("anything by going up. The binding constraint has moved from COVERAGE to EVIDENCE — ")
		fmt.Fprintf(&b, "read **Verifiable (%.0f%%)** from here, and treat the efficacy line as a "+
			"completed checklist rather than a score.\n\n", verifiable)
	}
	fmt.Fprintf(&b, "**Of the %d passing, %d rest on STRONG evidence** (external corpus, ungameable oracle). ", done, strong)
	b.WriteString("The rest pass on first-party corpora of 3–12 cases the author also wrote — the bar is met, ")
	b.WriteString("the capability is unproven. A 1.00 on three self-authored cases is a bug report about the ")
	b.WriteString("benchmark, not a capability claim.\n\n")

	// A rising efficacy number sitting on a flat evidence base is the specific way this scorecard could
	// go bad, and it is invisible if you read only the headline. Every task here was benchmarked by the
	// same person who wrote the engine, so the percentage climbs whenever a task gets an instrument —
	// whether or not the capability improved. Stating that mechanically is the only version that
	// survives the author wanting a good number.
	if done > 0 && float64(strong)/float64(done) < 0.5 {
		fmt.Fprintf(&b, "> **Read the efficacy number with this beside it.** %d of the %d passes rest on "+
			"corpora written by the same person who wrote the engine being graded. That percentage rises "+
			"whenever a task gains an instrument, whether or not anything got better — so read a rise as "+
			"\"one more thing is now measured\", never as \"the engineer got smarter\". The part that would "+
			"survive a customer checking it is the %d backed by evidence we did not author.\n\n",
			done-strong, done, strong)
	}
	if benchedOnly > 0 {
		fmt.Fprintf(&b, "**%d task(s) clear their bar but are NOT SHIPPED** — the benchmarked engine has no "+
			"customer-reachable call site, so the score describes a capability nobody can use. They are "+
			"excluded from the efficacy number.\n\n", benchedOnly)
	}
	b.WriteString("| | Task | Benchmark | Score | Evidence | Engine | Confidence | Shipped | Done |\n|---|---|---|---|---|---|---|---|---|\n")
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
		eng := t.Engine
		if eng == "" {
			eng = "—"
		}
		fmt.Fprintf(&b, "| %s | %s | `%s` | %s | %s | %s | %s | %s | %s |\n", t.ID, t.Name, bench, score, corpus, eng, conf, ship, mark)
	}

	b.WriteString("\n## The other persona\n\n")
	b.WriteString("This scorecard grades the AI Security **Engineer**. The AI **Pentester** is a separate job and ")
	b.WriteString("has, by some distance, the better evidence: `tsbench xbow` — **78 of 104 first-attempt ")
	b.WriteString("(0.75), 89 of 104 allowing retries (0.86)** on the suite author's own public challenges, ")
	b.WriteString("every capture carrying an evidence SHA-256. Both are quoted because the ledger shows ")
	b.WriteString("eleven of the 89 needed more than one attempt, and a single figure hides which question ")
	b.WriteString("it answers. Whether either is comparable to the suite author's published rate depends on ")
	b.WriteString("whether theirs is pass@1 or best-of-retry — unchecked, so no longer claimed. That the ")
	b.WriteString("offensive side is measured this much better than the defensive one is itself the finding: ")
	b.WriteString("the hard external benchmark existed for attack and had to be invented for defence.\n\n")

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
