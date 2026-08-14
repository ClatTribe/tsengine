# Which model for which agent lane — measured

The L2 agents split into two lanes (`platform.AgentRole`), and this is the measurement that decides
what to put in each. It answers one question: **does a security-specialized model beat a general model
of the same size on our work?**

For the code lane, the answer is a clear no.

## Setup

| | |
|---|---|
| Task | vulnerability localization — "given this CWE, which file holds the sink?" |
| Corpus | `tsbench localize --hard` (6 scenarios: sanitized decoys, unreachable sinks, cross-file taint) |
| Metric | recall@1 and MRR, vs the deterministic heuristic substrate |
| Trials | 3 per arm, median reported (§14.2 multi-trial) |
| Runtime | local Ollama, one model resident at a time |

The two arms are matched so the comparison isolates **specialization**, not size or quantization:

| Arm | Params | Quant | Trained for |
|---|---|---|---|
| `qwen3:8b` | 8.2B | Q4_K_M | general |
| `foundation-sec-8b` | 8.0B | Q4_K_M | cybersecurity (Cisco Foundation AI, Llama-3.1-8B base) |

The **Instruct** build of Foundation-Sec was used deliberately. The base build is completion-only,
and `qwen3:8b` is instruction-tuned — pairing them would have measured instruction-following and
quietly made the security model look bad for a reason that has nothing to do with security.

## Result

recall@1 (substrate = 0.67, deterministic so constant across trials):

| Arm | median | range | Δ vs substrate |
|---|---|---|---|
| `qwen3:8b` | **1.00** | 0.83–1.00 | **+0.33** |
| `foundation-sec-8b` | 0.67 | 0.50–0.67 | +0.00 |

MRR (substrate = 0.81):

| Arm | median | range | Δ vs substrate |
|---|---|---|---|
| `qwen3:8b` | **1.00** | 0.92–1.00 | **+0.19** |
| `foundation-sec-8b` | 0.83 | 0.72–0.83 | +0.02 |

**The ranges do not overlap.** `qwen3`'s worst trial (0.83) still beats Foundation-Sec's best (0.67),
so this is a real separation rather than sampling noise on a 6-scenario corpus.

Foundation-Sec added nothing at the median, and in one of three trials it went **negative** (0.50 vs
the substrate's 0.67) — it actively displaced correct heuristic rankings.

### The gap is partly formatting, not only reasoning

`+0.00 lift` is an ambiguous number, and it took a second look to see why. `LLMLocalizer` degrades
**silently** to the heuristic when a model errors or returns an unparseable proposal (deliberate — a
broken model must never yield a falsely-confident ranking). So a model that never produced a usable
answer scores EXACTLY the substrate, which is indistinguishable from one that reasoned well and simply
agreed with it.

Measuring the parse rate separates them:

| Arm | usable proposals (observed) |
|---|---|
| `qwen3:8b` | 6/6 |
| `foundation-sec-8b` | 5/6, then 6/6 on a re-run — **intermittent**, and a different scenario each time |

So Foundation-Sec did genuinely reason on most scenarios — traces show its proposals grounded and
kept, it was simply ranking worse — but it *intermittently* emits output the harness cannot parse and
falls back. The rate is somewhere around zero-to-one scenario in six and is not stable enough from
these runs to quote as a figure; the point is that it is **nonzero for one arm and zero for the
other**, so part of the headline gap is format adherence rather than security reasoning.

That distinction matters for the conclusion. The defensible claim is *"weaker at this task, with a
real instruction-format weakness"* — not the flat *"the security model does not help"* the headline
number alone implies. `TestLocalizeParseRate` now reports this so a future comparison cannot repeat
the conflation.

## Why this is the expected result

Localization is *code navigation*: following untrusted data across a file boundary to the sink. That
is the `RoleCode` lane, and it is exactly the work the defensive-security model vendors say their
models are not for — Corma describes its model as being about logs, audits, and needle-in-haystack
correlation, and states it "doesn't have anything to do with coding."

Foundation-Sec is trained on security *knowledge*: its published wins are CTI-MCQA (multiple-choice
across MITRE ATT&CK / NIST / GDPR) and CTI-RCM (root-cause mapping). Neither rewards tracing a
variable through three Go files.

So this measurement **supports** the routing split rather than undermining it: put general models on
`RoleCode`. Before per-role routing existed, one model served both lanes and there was no way to
express that.

## What this does NOT show

Stated plainly, because it is the more interesting half:

1. **It does not test the analysis lane.** Triage, correlation, and control mapping are what a
   security-specialized model is actually trained for, and that claim is still unmeasured here. We do
   not yet have an analysis benchmark with headroom — building one is the open work.
2. **It is not a verdict on Foundation-Sec.** It is a verdict on Foundation-Sec *for localization*.
3. **N=6.** Non-overlapping ranges across 3 trials make the direction credible; the exact magnitudes
   should not be quoted precisely.
4. **The result is confounded by output format.** ~1 scenario in 6 was unparseable (above), so the
   measured gap mixes ranking quality with instruction-format adherence. A prompt or grammar tuned to
   this model's output style would likely close part — not necessarily all — of the difference. Anyone
   re-running this should check parse rate first and treat a low one as a harness problem.

## Reproducing

```bash
LLM_BASE_URL=http://localhost:11434/v1 LLM_MODEL=qwen3:8b \
  go run ./cmd/tsbench localize --hard --agent
```

Note the corpus flag. Without `--hard`, the default corpus scores **1.00 recall@1 on the heuristic
alone**, so every model ties at 1.00 and the ablation reads +0.00 regardless of quality — it cannot
discriminate, and a model comparison run on it would be meaningless.

**Before loading any local model, check weights against physical RAM.** Model size is two separate
budgets and only one fails loudly: disk decides whether the download completes (fails cleanly), RAM
decides whether the model can ever load (fails as a system crash). A 16.1 GB F16 build of this same
model was pulled onto a 16 GB machine during this work — the download succeeded, and loading it
thrashed the box until `watchdogd` missed 90 s of checkins and the kernel panicked. Use a Q4_K_M
build, and require `weights + ~4 GB < physical RAM`.
