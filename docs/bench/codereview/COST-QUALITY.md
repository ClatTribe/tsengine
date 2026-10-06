# Code-review cost vs quality

| model | repeats | recall strict (min–max) | recall lenient | precision ≥ | shown a fixed file | cost/run | cost per correct |
|---|---|---|---|---|---|---|---|
| codesweep LLM-plan · qwen3:8b (local) | 1 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 3.0/4 | unknown | — |
| codesweep heuristic-plan · qwen3:8b (local) | 1 | 0.0% (0.0–0.0) | 0.0% | 0.0% | 0.0/5 | unknown | — |

26 cases; 26 published after the 2025-12-31 cutoff.

## How to read this

- **Cost per correct** is total spend ÷ cases located (strict) across all repeats — cost per *finding*, not per token. Blank when a model reported no usage (unknown ≠ free) or found nothing.
- **Recall is strict and lenient** (the answer key is the fix, not the bug, so the truth is between them), and **precision is a lower bound** (off-key predictions are unjudged, not false).
- **Shown a fixed file** separates coverage from detection: a low recall here means the planner never pointed the model at the vulnerable file, so the model was not the bottleneck.
- **Spread matters at this scale.** A gap smaller than the min–max range is noise; prefer more repeats over trusting one run (DeepSecBench reports the median of three).

> **Held-out status:** once this table is used to CHOOSE a model, the corpus is no longer held out for that decision — a model picked on these cases has been tuned to them. Record the choice, then grow the corpus before the next comparison (§14.2 rule 5).
