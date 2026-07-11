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

## Our result on the same two scenarios

`tsbench csa` runs faithful reconstructions of the two scenario types through our real detectors
and scores triage accuracy — **reach the correct conclusion**: escalate a real threat, and (the
hard half) *do not* escalate a benign decoy.

| Scenario | Our engine (autonomous) | CSA with-AI | CSA manual |
|---|---|---|---|
| AWS S3 / GuardDuty bucket-exposure | **100% (4/4)** | 97% | 86% |
| Microsoft Entra failed-login | **100% (4/4)** | 85% | 81% |

8/8, including the 4 restraint decoys (an intentionally-public static-site bucket, a re-tagged but
still-private bucket, a two-typos-then-success login, failures spread over 9 hours). A naive
always-escalate agent scores 50% on this set — the decoys are what make the number mean something.

**Crucially, this number is AUTONOMOUS and reproducible with no LLM key and no proxy** — it runs
in CI. That closes the credibility hole in our other benchmark work (XBOW, CyberSecEval), where
every number was produced by a human-driven proxy one turn at a time.

## What this is NOT — read before quoting it

- **A reproduction, not the CSA's data.** Their per-scenario telemetry isn't public. These are
  faithful reconstructions of the two scenario *types* from the published description, labeled by
  real-world correctness — not reverse-engineered to pass (the detectors run as-is; see the decoys).
- **A different operating mode.** The CSA measured *humans* (with vs without AI-assist). Ours is
  the engine triaging *autonomously*. Same task and same ground-truth axis, but the numbers sit
  **side-by-side, not head-to-head** — 100% autonomous-correct on 8 episodes is not the same claim
  as "beats Dropzone's 97% on 148 analysts."
- **A small set.** Eight episodes. It demonstrates the capability is there and correctly
  calibrated; it is not a statistically-powered win.
- **Two of the four CSA measures.** We score accuracy + consistency (deterministic → 0% run-to-run
  variance). Speed and human-detail are human-workflow measures that don't map to an autonomous
  engine.

## Where our architecture should genuinely win — and why

The CSA/OpenSec literature's consistent finding is that the AI-SOC failure mode is **not detection,
it's restraint** — frontier agents over-escalate on scary-looking or prompt-injected alerts. Our
design makes over-escalation structurally hard: the LLM *proposes*, a deterministic predicate
*disposes* (§10), and every mutation is HITL-gated (§18.2 inv 3). The restraint decoys in this
benchmark are exactly that property, measured. That is the dimension to lead with competitively —
not raw recall.

## What would turn "side-by-side" into a real head-to-head

Three gated inputs, in priority order:

1. **Competitor trial accounts + a shared labeled alert corpus.** Sign up for Dropzone/Prophet
   trials, replay the same labeled alerts through them and through us, score identically. This is
   the gold standard and the only true head-to-head; it needs procurement + a corpus, not code.
2. **The CSA's actual scenario telemetry** (if they release it) — drops straight into `tsbench csa`.
3. **An autonomous LLM key** so the *L2 agent* (not just the deterministic substrate) runs the
   scenarios and the broader benchmarks (SIR-Bench 794 cases, CyberSecEval 1916) at scale, instead
   of the manual proxy.

The harness, the scenario reconstructions, and the honest scoring are built (`tsbench csa`). The
remaining step to an audited win is procurement/credentials, not engineering.

---

_Sources: CSA "Beyond the Hype: A Benchmark Study of AI Agents in the SOC" (cloudsecurityalliance.org,
Oct 2025) · Dropzone/CSA press materials · Prophet Security published customer metrics · ITBench-AA
(Artificial Analysis + IBM). Run the numbers with `tsbench csa`._
