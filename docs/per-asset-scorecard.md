# Per-asset scorecard — what is measured, and how much it is worth

**Read this instead of asking "how good are we on X".** Every number here was produced by running the
product, not by reading code. Where a number does not exist, the row says so.

Last measured: **2026-08-16**. Reproduce with the commands in each row.

---

## 1. The scorecard

Confidence is about the **ground truth**, not the score. A perfect number over three test cases is
worth less than a middling one over 2,740, and reporting them alike is how a benchmark misleads.

| Asset | Measured | Ground truth | Confidence |
|---|---|---|---|
| **repository** (SAST) | **46.5 % Youden** — 3rd on the published cohort (Veracode 51, Checkmarx 47, **us**, Fortify 35, SonarQube 6) | 2 740 OWASP BenchmarkJava cases, neutral | **High** |
| **container_image** | **1.000 recall** (3/3 must-find CVEs, 416 raw findings) · **FP-control PASS** (0 high/critical on a clean image) | 3 CVEs + 1 clean image | **Low** — paired, but thin |
| **cloud_account** | **6/6 CIS recall**, +0.17 lift over prowler-only, **1 unexpected finding** | 6 seeded violations (CIS has ~60) | **Low** |
| **api** | 11 findings on VAmPI | none — no must-find list | **None** |
| **web_application** | 26.7 % Youden on the cases a completing scan reached | 15 of 1 133 WAVSEP cases (1.3 %) | **Very low** |
| **domain**, **ip_address** | — | — | **Untested** |

```bash
tsbench sast --target <BenchmarkJava> --ground-truth expectedresults-1.2.csv
tsbench run  --fixture fixtures/container/nginx-vuln/fixture.json
tsbench run  --fixture fixtures/container/alpine-clean/fixture.json
tsbench cloud-baseline
tsbench wavsep --target <wavsep-root> --ground-truth fixtures/web/wavsep/expected-cases.csv
```

### What the repository number actually says

The headline hides the useful part. Per category, recall is **90–96 %** in the weak classes while
specificity is **12–27 %** (cmdi 93/13, sqli 93/27, ldapi 96/12). **We are not missing
vulnerabilities; we are failing to rule out the safe twins** OWASP Benchmark ships to punish pattern
matching. That is a dataflow problem a rule cannot solve in principle — an argument for the CodeQL
escalation (§5.3), not for more semgrep rules. `trustbound` (52/58) is the one genuine recall gap.

### The L1.5 chain, at the escalation floor

Graded at `types.SeverityHigh` — `detect.Detector`'s incident threshold, i.e. the line where anyone
is actually paged:

| | Youden | TP | FP | FN |
|---|---|---|---|---|
| raw, all severities (leaderboard) | 46.54 % | 1248 | 552 | 167 |
| raw, ≥ high (ablation baseline) | 0.52 % | 237 | 215 | 1178 |
| delivered, ≥ high (post-L1.5) | 5.57 % | 490 | 385 | 925 |

**L1.5 lift: +5.05 points**, earned by *promoting* — true positives at the floor go 237 → 490 as the
exploitability hook raises real vulnerabilities. That work ran unmeasured for months because the
scorer ignored severity.

---

## 2. Stability — the number a single run cannot fake

Every score above comes from **one run**, so each reports whichever outcome that run drew. Four
identical api scans of one unchanged target returned **1, 1, 11 and 11** findings, `partial=false`
throughout.

```bash
tsbench stability --asset api --target <t> --runs 3
```

Measured on VAmPI:

```
stability rate:  100.0%   (findings that appeared, appeared every time)
toolset:         VARIED   with schemathesis / without
tools failed:    kiterunner, schemathesis
```

**The tools are deterministic; the deadline is not.** `TSENGINE_TOOL_TIMEOUT` is a wall-clock cap and
tools dispatch concurrently, so under CPU load a tool that normally finishes is killed and
contributes nothing. Reproducible: `TSENGINE_TOOL_TIMEOUT=20s` → `tools_failed=2` every time.

Consequence, now fixed: a degraded pass used to **resolve incidents** and **confirm fixes** from the
absence of findings — telling customers a live vulnerability was fixed because a scanner timed out.
Such a pass now routes to the open-only path.

---

## 3. Agent measurement — per task

Our own agent harnesses (`xbow`, `cvepatch`, `defense`) are corpora we chose with oracles we wrote.
[BountyBench](https://github.com/bountybench/bountybench) splits work the way a security team does,
on 31 production codebases, with an oracle we do not control.

```bash
tsbench bountybench --tasks <bountytasks-checkout>
```

```
46 bounties · 44 patch tasks · 46 exploit tasks · 43 with verify.sh · $5,786 paid
in a class we cover:     21
in a class we do NOT:    25
```

Detect + Exploit is the **AI pentester**; Patch is the **AI security engineer**. The 25 uncovered are
not a uniform backlog: **CWE-20** is a catch-all parent class where a coverage claim would be
meaningless, and **CWE-400** (resource exhaustion) needs load or fuzzing rather than pattern
matching. Those need different techniques, not more rules.

**Not yet a score.** Running our agent against these tasks needs their Python + Docker harness with
our binary as the workflow implementation. The inventory is the honest denominator; a score would
require their runner.

---

## 4. What would raise confidence, in order

1. **Broaden the thin fixtures** — container (3 CVEs) and cloud (6 of ~60 CIS controls). Both report
   near-perfect scores on ground truth too small to carry them.
2. **A completing web scan.** 1.3 % coverage is not a measurement, and the slice is crawl-ordered
   rather than sampled — at cap 15 every XSS case reached was DOM-XSS, 4 of the corpus's 98.
3. **api ground truth** — a must-find list for VAmPI, which has published BOLA/SQLi/JWT flaws.
4. **Agent scores via BountyBench's runner**, not ours.
5. **domain and ip** — untested, and last in the asset priority order.

None of this is blocked on infrastructure. Every harness above runs on one laptop with Docker.
