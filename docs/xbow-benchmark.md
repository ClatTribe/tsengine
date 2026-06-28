# XBOW validation-benchmarks — same-suite parity measurement (rung 2)

This is the **rung-2** step on the AI-pentester validation ladder: run our deep pentest agent
against **XBOW's own public benchmark suite** and get a number that is *directly comparable* to
XBOW's published solve-rate — privately, reproducibly, with zero reputation risk, as many times as
we want while tuning.

> Ladder: (1) internal `tsbench agent` on Juice Shop/VAmPI → (2) **this: XBOW validation-benchmarks**
> → (3) commissioned Doyensec-style benchmark → (4) live HackerOne. Climb in order; each de-risks the
> next. Rung 2 is the cheap, private, same-suite yardstick.

## Why this suite

The [XBOW validation-benchmarks](https://github.com/xbow-engineering/validation-benchmarks) are 104
Dockerized web challenges XBOW's own security team uses, kept confidential until release. Each
benchmark's success criterion is **flag capture**: a random flag is injected at build time
(`docker compose build --build-arg flag=<flag>`) and hidden in the app; you "solve" it by exploiting
the vuln and retrieving the flag.

That criterion is the perfect fit for us:

- **Same-suite, directly comparable.** It's XBOW's own suite — our solve-rate vs theirs, apples to
  apples, no commissioned A/B needed.
- **Deterministic + ungameable.** The flag is a high-entropy secret; the agent can only reproduce it
  by *genuinely exploiting* the app. There is no LLM self-grading.
- **§10-grounded by construction.** A benchmark "win" *is* evidence — the captured flag — so a green
  number can never be a hallucinated one. This is exactly our zero-FP philosophy applied to scoring.

## What's built

- `internal/bench/xbow.go` — the **pure, unit-tested core**: suite parser (`LoadXBOWSuite`), the
  flag-capture grader (`FlagCaptured` / `FlagCapturedInScan`), and the scoreboard
  (`AggregateXBOW` / `RenderXBOWScoreboard`, overall + per-level + per-tag). Correct *before* any
  heavy live run.
- `cmd/tsbench/xbow.go` — the **live orchestrator** (`tsbench xbow`): per benchmark it injects a
  random flag, `docker compose build` + `up --wait`, runs `tsengine scan` (the deep agent) against
  the target, grades flag capture, and `compose down -v` (always, even on failure). A build/run
  failure is recorded as a miss with a note and the suite continues.

## Run it

```bash
# 0. one-time: clone the suite + build the sandbox image
git clone https://github.com/xbow-engineering/validation-benchmarks
make cli tsbench                          # builds ./bin/tsengine + ./bin/tsbench

# 1. validate the suite wiring with NO Docker/scan (loads configs, prints the plan)
./bin/tsbench xbow --suite ./validation-benchmarks --dry-run

# 2. the real measurement — needs Docker + the sandbox image + an LLM for the agent.
#    Start small (one level / a few IDs) before the full 104-benchmark sweep.
TSENGINE_SANDBOX_IMAGE=tsengine/sandbox:0.1.0 \
TSENGINE_ACTIVE_EXPLOIT=1 \
LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=qwen3:8b LLM_API_KEY=ollama \
  ./bin/tsbench xbow --suite ./validation-benchmarks --level 1 --out xbow-scoreboard
```

`--out xbow-scoreboard` writes `xbow-scoreboard.json` (per-benchmark results + the scoreboard) and
`xbow-scoreboard.md` (the rendered table). Other flags: `--only XBEN-001-24,XBEN-014-24`,
`--timeout 12m`, `--target-port <host-port>` (skip compose-port autodetect).

## Honest expectations

Flag capture demands **long-horizon, multi-step exploitation** — exactly the capability we identified
as the remaining gap to XBOW. So the first numbers will be **modest**, and they're gated on two things
that are *not* code:

1. **A capable model.** qwen3:8b is a smoke-test (weak + slow). A frontier/production LLM key is what
   moves this number. The orchestrator inherits `LLM_*` from the environment, so swapping the brain is
   a one-line change.
2. **Long-horizon chaining** in the deep agent (the deliberate architectural work tracked separately).

The point of this harness is to **measure that honestly and reproducibly** — the same number XBOW
reports, on the same suite — so every improvement to the model or the agent shows up as a real,
comparable delta instead of a self-graded claim.
