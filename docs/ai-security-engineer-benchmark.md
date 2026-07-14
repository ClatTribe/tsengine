# Benchmarking the AI Security Engineer (code) — the honest path

The AI Security Engineer works *on top of* the L1 scanners to do an **app-sec engineer's job**: confirm
a real vulnerability and **fix it**. Benchmarking it means measuring that job — not snippet detection,
and not a different domain. Two public benchmarks were evaluated and rejected as mismatches, then a
disk-light adaptation was built.

## Why the obvious public benchmarks don't fit

| Benchmark | What it measures | Verdict |
|---|---|---|
| **CyberSecEval** (Meta) | is an isolated *snippet* insecure? (SAST pattern-match) | Wrong **layer** — that's L1 detection, which we wrap OSS for (§13). Not the engineer's reasoning/fix job. |
| **SEC-bench** (NeurIPS 2025) | agent patches a real CVE, verified by rebuild + sanitizer | Right **shape**, wrong **domain**: all 300 instances are native **C++** ASan fuzzing bugs. Our engineer does web/api/library app-sec. And its oracle needs **>200GB of Docker images** (violates the disk budget). |

Running our app-sec engine on 300 C++ crash bugs would score ~0 for the wrong reason, and "improving"
that would mean building C++ memory-safety capability — off-product, and textbook benchmark overfitting.

## What we built: SEC-bench's methodology, our domain, disk-light

`tsbench cvepatch` keeps SEC-bench's rigor (**real CVE + a gold patch as external ground truth + fix
verification**) and applies it to app-sec, disk-light:

- **Instances** = the vulnerable file(s) + the real fixing commit (a few KB), operator-provided via
  `--dataset` (external real CVEs; not committed — the CyberSecEval gate). No 200GB rebuild.
- **Engine under test** = `codeagent.ProposePatch` — the engineer's real code-fix capability (ADR
  0013/0014). Model proposes, a deterministic verifier disposes (§10). Single-shot, so even the manual
  dev proxy can drive it.
- **Scoring** — three generic signals, no per-CVE logic (overfit-free, §14.2):
  - `produced` — the engineer returned an applicable file rewrite
  - `localized` — the rewrite touches a file the gold patch also touched
  - `fixed` — an **execution oracle** applies the patch, runs the CVE's **real PoC + a regression
    check**, and sets FIXED only when the exploit is *blocked* **and** legit behaviour still works. The
    PoC lives in the instance data (external), never in the scoring code. The engineer can never mark
    its own fix working — the oracle decides.

## First run (frontier brain via the dev proxy, execution-verified)

Two real npm prototype-pollution CVEs, fixes produced by a capable model (the proxy), verified by
running the actual exploit:

| Instance | CVE | produced | localized | fixed (executed) |
|---|---|---|---|---|
| dot-prop | CVE-2020-8116 | ✓ | ✓ | **FIXED** — `({}).polluted` stays `undefined`, `get/set` still works |
| minimist | CVE-2020-7598 | ✓ | ✓ | **FIXED** — `--__proto__.x` blocked, arg parsing still works |

**Honest reading — this is a small, real proof, not a competitive score:**

- **N=2, one class, frontier-driven.** It proves the *capability* is real and the harness is sound
  (real CVEs, real fixes, execution-verified — the opposite of a self-graded number: the oracle runs
  the actual exploit). It is **not** a statistically-powered rate and makes no claim vs SEC-bench's 34%.
- **The engine, driven by a capable model, fixes real CVEs end-to-end.** The bottleneck to a *scaled*
  number is a capable **autonomous** model: the free local 8B (qwen3:8b) is too weak to drive the
  agent, so a real at-scale run needs an API key — not code. (SEC-bench's own SOTA is 34%; this is a
  hard task.)
- **Selection is ours** (2 external CVEs we chose); the vuln + gold fix are external/real, but a larger,
  third-party-curated instance set is the next step to remove selection bias.

## The improvement: propose→verify→REFINE (measured, non-overfit)

Running the benchmark exposed a real engine limitation: `ProposePatch` was **single-shot** — one
attempt, no recovery when the first fix is *incomplete*. The classic case: a prototype-pollution fix
that guards `__proto__` but not `constructor`/`prototype`, which a `--constructor.prototype.x` payload
still bypasses (the exact minimist CVE-2020-7598 → CVE-2021-44906 progression).

`codeagent.ProposePatchIterative` adds the loop the product already uses on offense (the XBOW iterative
driver) and for fix-verification (`retest.Verify`): propose → let the **deterministic execution oracle
dispose** the attempt → on failure, thread the verifier's *real output* back into a refined attempt.
Bounded by `--refine N`. Grounded (§10): the model widens the search across attempts, but the oracle —
never the model — decides "fixed", so refinement can't manufacture a false success. Overfit-free
(§14.2): the refine prompt carries only the verifier's real failure output, never an instance hint.

**Measured on the real bypass case** (`--constructor.prototype.polluted` PoC):

| Mode | Result |
|---|---|
| single-shot (`--refine 1`) | `not_fixed` — the `__proto__`-only fix leaves the constructor bypass open |
| refine loop (`--refine 3`) | **`fixed` at attempt 2** — the failure fed back → complete guard → oracle confirms |

So the engine now recovers a fix the single-shot path reported broken — the improvement that raises the
`fixed` rate is a real long-horizon capability, not tuning to the instances.

## What it takes to scale to a real number

1. **A capable autonomous model** (API key) — run `ProposePatch` over N instances unattended.
2. **A bigger external instance set** — pull real app-sec CVE fixing commits from OSV/GHSA across
   languages/classes (disk-light per instance), ideally a third-party-curated list to remove selection bias.
3. Each instance ships a PoC + regression check → the execution oracle scores `fixed` automatically, CI-runnable.

The harness, the engine hook, and the execution oracle are built (`tsbench cvepatch`). Scaling is
credentials + instance-curation, not engineering.
