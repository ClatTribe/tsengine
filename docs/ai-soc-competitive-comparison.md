# How good is our AI Security Engineer vs the competitors — the honest answer

The recurring, fair question: *how do we actually know where we stand against the commercial AI
SOCs* (Dropzone, Prophet Security, Simbian, CrowdStrike Charlotte, Microsoft Security Copilot)?
This doc is the honest answer — including the parts that are structurally hard.

## Why a clean "vs competitor" number is genuinely hard

1. **The competitors are closed SaaS.** You cannot run Dropzone or Prophet on a benchmark
   yourself — there's no downloadable model, no API you can point at a test corpus. So the usual
   "run everyone on the same yardstick" is not available to us directly.
2. **Their headline numbers are self-reported.** Prophet's "96% false-positive reduction",
   Dropzone's "5× MTTR" — these are vendor marketing claims measured on their own customers'
   traffic, not on any shared, audited benchmark. There is no neutral leaderboard for AI SOCs the
   way SWE-bench exists for coding agents.
3. **So the only credible comparison is a *shared public benchmark* whose paper *also* reports a
   competitor/frontier number.** Our number has to sit in the same ranking as someone else's, on
   the same task. That is exactly what we went and found.

## The one independent, public AI-SOC benchmark with a named competitor number

**CSA "Beyond the Hype: A Benchmark Study of AI Agents in the SOC"** (Cloud Security Alliance,
Oct 2025). 148 real SOC analysts, run *independently by the CSA* (not the vendor). Analysts
investigated two escalated Tier-2 alerts, with vs without AI assistance, scored on accuracy,
speed, completeness, and detail. The published per-scenario **accuracy**:

| Scenario | with AI (Dropzone) | manual (GuardDuty / Sentinel) |
|---|---|---|
| 1. AWS S3 / GuardDuty bucket access | **97%** | 86% |
| 2. Microsoft Entra ID failed logins | **85%** | 81% |

This is the yardstick. Both scenarios map directly onto detectors we *already run
deterministically*: S3 exposure → `clouddrift.Diff` (`resource-became-public`); Entra failed-login
spray → `identitythreat.Detect` (`password_spray` / `distributed_spray`).

## What we CAN run — a calibration check, not a scoreboard

`tsbench csa` runs faithful reconstructions of the two scenario types through our real detectors.
It is a **calibration / regression check**: do real threats fire, and do benign decoys stay silent.
On the 8 reconstructed episodes the detectors catch every threat and reject every decoy (an
intentionally-public static-site bucket, a re-tagged still-private bucket, a two-typos-then-success
login, failures spread over 9 hours) — the restraint half a naive always-escalate agent fails.

**This is NOT a comparison to Dropzone, and it is important to say why it can't be:**

- **The episodes are self-authored.** We know exactly what `clouddrift.Diff` and
  `identitythreat.Detect` do, so we can trivially write cases they pass. A 100% pass rate on our own
  8 cases is a *circular measurement* — it proves the detectors are wired and calibrated, nothing
  more. Reporting it as "100% vs Dropzone's 97%" would be overfitting dressed as a benchmark, and
  we don't do that.
- **Different sample and mode.** Dropzone's 97%/85% is over **148 real analysts** on **data we
  don't have**, measuring *humans with AI-assist*. Ours is an autonomous detector over 8 cases we
  wrote. These numbers are not comparable and are deliberately never placed in the same column.

What the check legitimately buys us: it's **autonomous and reproducible with no LLM key or proxy**,
so it runs in CI as a regression guard — and it caught a real drift-baseline bug while being built.
That's its whole value. It is a unit-test-grade calibration probe, not evidence of competitive rank.

## So how good ARE we vs competitors? Honestly: not yet measured

There is no credible number today, and manufacturing one from self-authored cases would be the
overfitting the reader should rightly distrust. A real comparison requires an **external labeled
dataset we did not author** — the only thing that removes the circularity. The candidates, all
gated, in priority order:

1. **Competitor trial accounts + a shared labeled alert corpus.** Sign up for Dropzone/Prophet
   trials, replay the same labeled alerts through them and through us, score identically. This is
   the gold standard and the only true head-to-head; it needs procurement + a corpus, not code.
2. **A public labeled SOC/alert dataset we didn't build.** Whatever exists that maps onto our
   detectors — the mapping is itself a judgment call, so this is weaker than (1), but it's external.
3. **The CSA's actual scenario telemetry** (if they release it) — drops straight into `tsbench csa`.
4. **An autonomous LLM key** so the *L2 agent* (not just the deterministic substrate) runs the
   scenarios and the broader benchmarks (SIR-Bench 794, CyberSecEval 1916) at scale, instead of the
   manual proxy.

The harness and the honest scoring are built (`tsbench csa`); the remaining step to an *audited*
number is procurement/credentials, not engineering. **Until one of the above lands, the correct
public statement is "not yet independently measured," not a percentage.**

## The one thing we can claim without a benchmark — architecturally

The CSA/OpenSec literature's consistent finding is that the AI-SOC failure mode is **not detection,
it's restraint** — frontier agents over-escalate on scary-looking or prompt-injected alerts. Our
design makes over-escalation *structurally* hard: the LLM *proposes*, a deterministic predicate
*disposes* (§10), every mutation is HITL-gated (§18.2 inv 3). That is an architecture property, not
a benchmark score — provable by inspection, and the honest thing to lead with competitively while
the measured comparison stays gated.

---

_Sources: CSA "Beyond the Hype: A Benchmark Study of AI Agents in the SOC" (cloudsecurityalliance.org,
Oct 2025) · Dropzone/CSA press materials · Prophet Security published customer metrics · ITBench-AA
(Artificial Analysis + IBM). Run the numbers with `tsbench csa`._
