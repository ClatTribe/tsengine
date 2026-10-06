# Held-out code-review benchmark — recorded results

Recorded BEFORE any reviewer was changed in response (§14.2 rule 5). Each row's predictions file is
committed beside this one, so the number can be re-graded by anyone:

```bash
go run ./cmd/tsbench codereview score --corpus fixtures/codereview --predictions docs/bench/codereview/<file>.json
```

## 2026-10-05 — codesweep, heuristic planner, qwen3:8b (local Ollama), 5 of 26 cases

| | |
|---|---|
| configuration | `--localizer heuristic --max-tasks 8` — NOT the product's configuration (the product plans with the LLM localizer) |
| cases run | 5 (GHSA-4x45, -756x, -jjhp, -m37j, -x5c9); the other 21 were not run |
| strict / lenient recall | 0% / 0% |
| precision (lower bound) | 0% — 0 of 30 predictions on the key, all 30 unjudged |
| **reviewer shown a fixed file** | **0 of 5** |
| cost | unknown — qwen3:8b has no published price (the first run reported $0.27, which was EstimateCost's default frontier rate applied to a free local model; the runner now refuses to publish that) |

**What it says.** Nothing about the model yet. In every case the planner sent all 8 questions to files
the fix never touched — `pi_executor.py` instead of `server/bundles.py`, `registry.go` instead of
`content/file/utils.go`, and so on. A reviewer that is never shown the vulnerable file scores zero no
matter how capable its model is. The finding is about codesweep's PLANNING: the heuristic localizer,
capped at 8 questions, does not reach the vulnerable file on real repositories.

**What it does not say.** It is 5 cases, a non-product configuration and an 8B local model. It is not a
statement about codesweep in production, about deepsec, or about frontier models.

**Why it is worth recording.** Before this benchmark the planner's coverage was never measured on real
code; codesweep's own tests use synthetic repositories its sink table was written for. This is the first
number from an answer key we did not write, and like IAM-Vulnerable's 64.5% it is worth more for being
taken before anything was tuned to it.

**Next measurements** (each recorded here, unchanged, before any fix): the LLM localizer (the product's
configuration) on the same 5; all 26 cases; a frontier model; deepsec scored from its own export.

## 2026-10-06 — cost-vs-quality (`tsbench codereview cost-quality`)

The first comparison across configurations, on the free local model (qwen3:8b). The committed table is
`COST-QUALITY.md`; both predictions files are beside it, so the numbers re-grade with:

```bash
go run ./cmd/tsbench codereview cost-quality --corpus fixtures/codereview \
  --arm "LLM-plan=docs/bench/codereview/2026-10-05-codesweep-llmplan-qwen3-8b.json" \
  --arm "heuristic-plan=docs/bench/codereview/2026-10-05-codesweep-heuristic-qwen3-8b.json"
```

**The finding: the LLM planner fixed coverage; the small model is now the bottleneck.** The heuristic
planner showed the model a vulnerable file in **0 of 5** cases; the product's LLM planner showed it in
**3 of 4**. So the 0% recall in the earlier run was a planning failure, and the LLM planner largely
closes it. But recall is **still 0%** — in both cases where qwen3:8b was shown the vulnerable file
(jjhp, m37j) it flagged *other* files instead (verified: the predicted files and the key files are
disjoint, so this is a real miss, not a path-matching artefact). On an 8B local model, detection is the
wall once coverage is solved.

**What this does NOT yet say, and needs a key + a cap to answer:** whether a frontier model, now shown
the right file, actually finds the bug. That is the row that decides whether cheap-model routing is
viable for code review, and it is the whole point of the table. Cost is "unknown" for both rows because
qwen3:8b has no published price (not $0 — it is self-hosted/free, but these predictions files predate
the self-hosted-cost flag; a fresh run would mark them free).

**Next**, each recorded here before any model is chosen (once chosen, the corpus is no longer held out
for that choice — §14.2 rule 5): repeat the local arm ≥3× for spread; add a mid-price and a frontier
arm; report cost per correct finding across the tiers.
