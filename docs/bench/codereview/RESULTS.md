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
