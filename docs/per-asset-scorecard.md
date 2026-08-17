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
| **web_application** | per-category, measured at the evaluation-set level: **sqli 78.95 %** (TP=15 FP=0 FN=4) · **reflected-xss 25.00 %** (TP=8 FP=0 FN=24) | 19 + 32 of 1 133 WAVSEP cases | **Low** — representative slices, small |
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

### What the web numbers say

Two evaluation sets, scanned at the level WAVSEP actually serves (the category roots 404):

| class | Youden | TP | FP | FN |
|---|---|---|---|---|
| sqli | **78.95 %** | 15 | **0** | 4 |
| reflected-xss | **25.00 %** | 8 | **0** | 24 |

**FP=0 in both.** That is the opposite profile to the repository asset, where recall is 90–96 % and
specificity 12–27 %. The DAST path is precise and under-sensitive; the SAST path is sensitive and
imprecise. They fail in opposite directions, so "improve web detection" and "improve SAST detection"
are different jobs.

The 25 % on reflected XSS is a **real gap, not a sampling artifact** — the full 32-case GET set, the
mainstream reflected-XSS corpus. An earlier `xss 0.00 %` was measured on 4 DOM-XSS cases and a later
one on a single cookie case; neither was informative, and both are superseded.

**The gap is script-context XSS, not XSS.** Breaking the misses down by injection context:

| context | example cases | detected |
|---|---|---|
| HTML body / attribute | `Tag2TagScope`, `Tag2HtmlComment`, `Event2*PropertyScope` | yes |
| **JavaScript** | `Js2JsEventScope`, `Js2PropertyJsScope`, `Js2ScriptSupportingProperty` | **0 of ~10** |
| **VBScript** | `Vbs2VbsEventScope`, `Vbs2*QuoteVbsEventScope` | **0 of 3** |

Zero script-context cases were detected **in either of two runs**. Escaping a JS string or event
handler needs payloads dalfox is not generating here. That is a specific capability gap someone can
act on; "reflected XSS is 25 %" is not.

**Measured: web findings are unstable, not just the toolset.** `tsbench stability --runs 3` over the
reflected-XSS set reports **54 flaky findings**, many present in only **1 of 3 runs**. That is
qualitatively worse than api, where the stability rate was 100 % and only the TOOLSET varied — there,
whatever ran was reliable. Here the same tool, on the same unchanged target, reaches different
conclusions between runs, so a CI gate on any of those 54 passes only some of the time.

Consequence: the per-class percentages above are point estimates with real, unquantified spread. The
durable finding is the CLASS-level one (script-context undetected in every run); the percentages are
indicative.

**Caveat — this benchmark is itself non-deterministic.** Two identical scans returned **9 vs 7
distinct cases and 751 vs 667 findings**; one case was found in one run and missed in the other. Same
wall-clock timeout mechanism as everywhere else. So per-case membership is NOT stable and must not be
quoted; the context-family boundary is, because it held across both runs. Any single web Youden here
carries unquantified run-to-run variance — `tsbench stability` is the tool for putting a number on
it, and has not been run against web yet.

For scale: Acunetix/Netsparker publish 87 % overall, Burp 78 %, ZAP 56 % — over the whole corpus, so
these per-set figures are not leaderboard-comparable yet.

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

## 3b. AI security engineer — patch pipeline (execution-verified)

The defensive agent's core job is PATCH: given a vulnerable app + a finding, produce a fix that
CLOSES the exploit without breaking the app. `tsbench cvepatch` grades that with an EXECUTION oracle —
it applies the patch, re-runs the exploit (must now fail) and the app's own driver (must still pass).

```bash
tsbench cvepatch --dataset <cve-set> [--responses <fixes>]   # execution-verified, not LLM-judged
```

Measured on the 3-instance seed (rce / lfi / xss), fixes supplied via the proxy-replay path:

| instance | class | produced | localized to gold file | execution-verified FIXED |
|---|---|---|---|---|
| command-injection-py | rce | ✓ | ✓ | ✓ |
| path-traversal-node | lfi | ✓ | ✓ | ✓ |
| xss-render-node | xss | ✓ | ✓ | ✓ |

**3/3, and the oracle is real** — the docker exploit no longer fires and the functional driver still
passes. That proves the pipeline (parse → apply → verify) works, and it is a stronger result than the
pentester's, where the proxy got a grounded finding but the flag stalled on relay state-threading.

**Honest limit — same as every self-authored fixture: the seed is first-party** (`cve: n/a — first-party
seed`). 3/3 on 3 seeds is a smoke test of the pipeline, not a benchmark of the engineer. A credible
number needs an EXTERNAL CVE set, and here is the concrete blocker — confirmed by inspecting the
actual tasks, not assumed:

- **BountyBench** (44 patch tasks) is APP-LEVEL. lunary/bounty_0 patches a multi-file TypeScript
  backend (`codebase/packages/backend/src/api/v1/projects/index.ts` + `authorization.ts`), ships a
  `docker-compose.yml`, and its `verify.sh` runs against the live app. cvepatch's oracle is
  single-file / single-runtime (one node or python file + a driver), so it CANNOT consume BountyBench
  directly — scoring it means running BountyBench's own Docker+Python harness with our codeagent as
  the patch_workflow, plus a frontier LLM.
- **CyberGym** is the same shape (its own harness); **SEC-bench** is C++/200GB — wrong domain.

So: the pipeline is execution-verified and proven on seeds; a NUMBER on an external CVE set is gated
on running that benchmark's own app-level harness + a frontier LLM — the same resource gate as the
pentester and cloud, not missing code. cvepatch's disk-light single-file format is deliberate
(laptop/CI) and is exactly why it does not drop-in against app-level corpora.

## 3c. What the customer is TOLD (dimension 3) — live-verified

Three surfaces claimed more than the engine proved. All three now report their own basis, and all
three were verified against a running platform (SQLite-backed, real HTTP), not just unit tests:

| Surface | The overclaim | Now | Live proof |
|---|---|---|---|
| `/coverage` | "No findings recorded" over an API whose top risks were never testable | names the untested classes + how to enable them | unscanned api asset → BOLA/BFLA/cross-user-auth listed w/ OWASP refs; **3 → 0 after posting an authz-test config** |
| `/posture` | "No risks found — this posture source is clean" | "Assessed <when>" vs "Not assessed yet" | a CLEAN device ingest (0 findings) → `assessed=true` + timestamp, while tprm/clouddrift stay `assessed=false` |
| `/attack-paths` | "No attack paths — that's good" over an unscanned estate | reports `correlated_findings` | unscanned tenant → `count=0, correlated_findings=0`; basis rises to 1 when a finding is added |

The shared root cause: these assessors are GROUNDED, so a clean estate legitimately yields zero
findings — which makes "assessed, clean" and "never ran" byte-identical in the store. Every fix
records the BASIS (was it assessed / what was it correlated over) rather than softening the wording,
so the reassurance shrinks as the customer configures instead of being a permanent disclaimer.

**Not verified: the rendered pages in a browser.** The preview launcher fails with an environment-level
`EPERM: uv_cwd` from npm and cannot target a worktree, so the React render is checked by `tsc` +
the live JSON the components consume, not by pixels.

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
