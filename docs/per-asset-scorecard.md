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
| **cloud_account** | **19/19 CIS recall** (prowler 18/19), **+0.05 lift**, **1 unexpected finding** | 19 seeded violations (CIS has ~60) | **Low** |
| **api** | **1.000 recall** (SQLi detected on VAmPI), **verdict PASS** | VAmPI's own documented vuln list; SQLi is the only class an L1 scan surfaces today (BOLA/mass-assign need L2/operator config, 4 classes uncovered) | **Low** — real ground truth, one class |
| **web_application** | 26.7 % Youden on the cases a completing scan reached | 15 of 1 133 WAVSEP cases (1.3 %) | **Very low** |
| **domain**, **ip_address** | — | fixtures are STUBS awaiting a deployed corpus (vulhub-style host), not fixtures nobody ran | **Not buildable yet** |

```bash
tsbench sast --target <BenchmarkJava> --ground-truth expectedresults-1.2.csv
tsbench run  --fixture fixtures/container/nginx-vuln/fixture.json
tsbench run  --fixture fixtures/container/alpine-clean/fixture.json
tsbench run  --fixture fixtures/api/vampi/fixture.json
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

1. **Broaden the thin fixtures — but not container.** Cloud went 6 → 19 controls and the correction
   is instructive: the engine lift fell from **+0.17 to +0.05**. Nothing changed in the engine; one
   extra detection out of 6 reads as 17 %, the same detection out of 19 reads as 5 %. A near-perfect
   score on a small denominator flatters whatever it measures.

   **Container is the exception, and an earlier version of this list got it wrong.** Its 3-CVE
   must-find looks like the same problem and is not. For container CVE scanning the ground truth and
   the tool's knowledge come from the *same upstream databases* — trivy and grype ARE the CVE
   database — so "recall against this image's known CVEs" mostly asks whether our plumbing surfaces
   what the DB already says. Going 3 → 30 CVEs yields a bigger number meaning the same thing.

   That is structurally unlike the others: SAST's ground truth is hand-labelled source with planted
   safe twins, WAVSEP is a purpose-built vulnerable app, CIS is an external standard. Those
   denominators are independent of the tool; container's is not. The informative container metric is
   the **FP-control half** (specificity on a clean image), which already exists and passes — it
   measures something no CVE database can hand us.
2. **A completing web scan.** 1.3 % coverage is not a measurement, and the slice is crawl-ordered
   rather than sampled — at cap 15 every XSS case reached was DOM-XSS, 4 of the corpus's 98.
3. **api breadth** — SQLi now passes (recall 1.000). The other 4 detectable-in-principle classes need L2 wiring or operator config; 4 more (data exposure, enumeration, RegexDOS, rate limiting) need capabilities we do not have. The fixture records all 9 as the honest denominator.
4. **Agent scores via BountyBench's runner**, not ours.
5. **domain and ip** — untested, and last in the asset priority order.

None of this is blocked on infrastructure. Every harness above runs on one laptop with Docker.
