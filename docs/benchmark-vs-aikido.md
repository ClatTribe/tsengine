# Benchmark: tsengine vs Aikido Security

How tsengine measures up against [Aikido](https://www.aikido.dev/) — the closest
commercial analogue (consolidated AppSec + cloud + AI-pentest, built on OSS engines,
human-in-the-loop). This doc answers the two questions directly:

1. **What benchmark can we use, per asset type?**
2. **Where do we stand against Aikido on each?**

It is the Aikido-specific companion to [benchmark.md](../benchmark.md) (our per-asset
benchmark matrix), [SCOREBOARD.md](../SCOREBOARD.md) (our number vs every competitor), and
[competitive-roadmap.md](competitive-roadmap.md). Everything here is grounded in a published
source or a number our harness measured — claims with neither are marked *pending*, never
guessed (CLAUDE.md §10).

> **Last reconciled:** 2026-06-21, from aikido.dev + the Doyensec Aikido-vs-XBOW report.

---

## TL;DR

- **The two products prove performance in opposite ways.** Aikido publishes **one** neutral
  head-to-head (Doyensec's commissioned *Aikido vs XBOW* AI-pentest benchmark) plus a "**95 %
  noise reduction**" marketing figure — and **no** per-scanner recall numbers on any neutral
  benchmark (OWASP Benchmark, WAVSEP, etc.). tsengine does the inverse: we publish **per-asset
  recall on the neutral academic benchmarks** (WAVSEP, OWASP Benchmark, CIS) plus an **L1.5
  ablation** that quantifies our own noise reduction — and our agentic head-to-head is *pending
  a live run*.
- **Both wrap the same class of OSS engines**, so raw L1 detection recall is *structurally
  comparable* — the wrapped tool sets the ceiling for both. The fight is won on (a) **noise /
  false-positive control**, (b) **verified (exploitation-proven) findings**, and (c)
  **coverage breadth**.
- **Shared reference point: XBOW.** Aikido benchmarks itself against XBOW (Doyensec); XBOW is
  already a named competitor in our agent leaderboard (`internal/bench/agent.go`). That lets us
  triangulate without a direct A/B we can't run.

---

## How each side proves performance

| | **Aikido** | **tsengine** |
|---|---|---|
| Neutral per-asset recall (WAVSEP, OWASP Benchmark, CIS) | **Not published** | **Published** — `tsbench wavsep / sast / cloud`, scored vs the academic leaderboards |
| Agentic / AI-pentest head-to-head | **Doyensec** commissioned *Aikido vs XBOW* (49 vs 31 verified) | `bench/agent` (detection_rate + **verified_rate**); live targets WebGoat + Juice Shop — *pending live run* |
| Noise / false-positive control | "**95 % noise reduction**" (marketing, no method published) | **L1.5 ablation** (`TSENGINE_L15_DISABLED=1`) measures the lift; **FP-control fixtures** on clean targets with a severity floor (CLAUDE.md §14.1.1) |
| Proof artifact | A vendor-commissioned PDF | A **signed, reproducible** evidence bundle per scan (CLAUDE.md §10) + a CI-gated bench harness |

Neither approach is wrong — they reflect different go-to-market. Aikido proves *outcome on a
real pentest*; we prove *recall on a controlled corpus* **and** keep the agentic outcome bar
(`verified_rate`) as the lead metric (competitive-roadmap Track 1).

---

## Per-asset-type benchmark landscape

For every asset type: the neutral benchmark that exists, whether **Aikido** publishes a number
on it, our **harness**, and the read. (Our measured numbers live in
[SCOREBOARD.md](../SCOREBOARD.md); `—` = harness ready, live number pending the sandbox image +
target — we do not print a number we have not measured.)

| Asset type | Neutral benchmark | Aikido publishes? | tsengine harness | Our number | Read |
|---|---|---|---|---|---|
| **web_application** (DAST) | **WAVSEP** (Shay Chen) — Acunetix/Netsparker 87 %, Burp 78 %, ZAP 56 % | No (DAST is "surface monitoring"; no WAVSEP score) | `tsbench wavsep` (Youden) | — pending live target | Both unproven on WAVSEP; **we have the harness + the bar**, Aikido publishes neither |
| **repository — SAST** | **OWASP Benchmark v1.2** — Veracode 51 %, Checkmarx 47 %, Fortify 35 %, SonarQube 6 % | No | `tsbench sast` (Youden) | **0.387 (≈39 %)** — above the Fortify 35 % bar | **We have a measured neutral-benchmark number; Aikido has none** |
| **repository — SCA** | No neutral leaderboard (Snyk/Dependabot self-publish) | No | `bench/sca_lockfiles` (must-find CVE recall) | — pending | Both wrap OSS SCA → recall tracks the tool; differentiator is reachability + noise |
| **repository — secrets/IaC/malware/EOL/license** | No neutral leaderboard | No | per-tool parity (`tsbench parity`) | — pending | Feature-coverage parity (both cover the category); see matrix below |
| **container_image** | No neutral leaderboard (Trivy/Anchore self-publish) | No | `bench/container_cves` (must-find CVE recall) | — pending | Both wrap Trivy-class engines → comparable; we add a 2nd CVE DB (grype) for corroboration |
| **api** | VAmPI + crAPI write-ups (no neutral leaderboard) | No | `bench/api_fixtures` (must-find) | — pending | Neither has a neutral score; authz logic (BOLA/BFLA) is an open category for both |
| **ip_address** | None neutral (Tenable/Qualys, no scorecard) | No (not an Aikido surface) | `bench/ip_services` (must-find) | — pending | **Coverage gap in Aikido's favour of us** — Aikido does not scan raw IP/host ranges |
| **domain** | subfinder/amass published enum rates | No (not an Aikido surface) | `bench/recon_breadth` (subdomain rate) | — pending | **Our-only surface** — external recon/attack-surface enum |
| **cloud_account** — CSPM (L1) | **CIS AWS Foundations** (mock-account recall) | No (CSPM shipped; no published CIS recall) | `tsbench cloud` (CIS-section recall) | — pending | Both wrap Prowler-class CSPM → comparable; we publish the CIS bar |
| **cloud_account** — attack-path engine (L2) | CloudGoat (Rhino) published solutions; prowler-grounded reachability | No (CSPM only; no attack-path benchmark) | `tsbench cloud-engine` (deterministic, no sandbox) | **2/2 CloudGoat · 100 % path recall** (measured this run) | **A lane Aikido doesn't benchmark** — reachability-true attack paths + verified remediation, measured + auditable |
| **mobile_application** | None neutral | No (not an Aikido surface) | per-tool parity (mobsfscan) | — pending | **Our-only surface** |
| **L2 agent / AI-pentest** | **Doyensec** *Aikido vs XBOW* (49 vs 31 verified) | **Yes** — the one neutral head-to-head | `bench/agent` (detection_rate + **verified_rate**) | — pending live run | See the head-to-head below — XBOW is the shared yardstick |

**The structural read:** on the *static* lanes (SAST/SCA/secrets/IaC/container/CSPM) Aikido and
tsengine both **compose open-source engines**, so raw recall is set by the wrapped tool and is
comparable by construction — and *neither* vendor's marketing recall is independently
benchmarked **except ours** (OWASP-SAST 39 %). On the *surface* lanes (ip_address, domain,
mobile) tsengine covers asset types **Aikido does not**. The genuine contest is the **agent
lane** and the **noise axis** below.

---

## The agent / AI-pentest head-to-head (the one Aikido benchmark)

Doyensec (independent, commissioned) ran **Aikido vs XBOW** in May 2026 — same two randomly
chosen open-source apps, same **$4 000** tier, every finding manually validated by a senior
researcher and peer-reviewed:

| Metric | Aikido | XBOW |
|---|---|---|
| Manually-verified vulnerabilities | **49** | 31 (**+58 % for Aikido**) |
| High / critical | **9** | 5 |
| False-positive rate | 4 % | 3 % (near-identical) |
| Finding overlap | only **3** of all findings overlapped → breadth, not duplication |
| Code access | white-box (ingests the codebase) | black-box (external only) |

**Why this lets us benchmark against Aikido without a direct A/B:** XBOW is already the anchor
of our agent leaderboard (`agentCompetitors`, "HackerOne US #1, PoC-validated, ~0 FP"). Aikido's
edge over XBOW is attributed by Doyensec to **white-box code access**, *not* to a smarter agent
or a lower FP rate (FP was a wash). tsengine is **also white-box on the repository asset** (we
ingest the repo: semgrep + the SCA/secret/IaC stack) **and** black-box on web/api — i.e. we have
the structural advantage Doyensec credits Aikido for, *plus* surfaces neither runs. Our job is to
**convert that into a published `verified_rate`** via a live `bench/agent` run (Track 1, A1) —
that is the number that would make this a direct, defensible comparison. Until then we state the
triangulation, not a fabricated head-to-head.

---

## The DEFENSE benchmark (the AI Security Engineer — a lane nobody benchmarks)

XBOW is the yardstick for the *attacker*. There is **no neutral benchmark for the defensive AI
Security Engineer** — Aikido, Dropzone, Prophet, and every AI-SOC vendor publish MTTR anecdotes and
internal accuracy, not a leaderboard, because triage/prioritization is subjective. So we *define*
one, anchored on the single part of the defense job that is execution-verifiable: **did the fix
actually close the vuln.**

`tsbench defense` (`internal/bench/defense.go`, scenarios under `fixtures/defense/`) grades a seeded
code+cloud estate against a known answer key. The hero metric is **remediation-capture** — the
fraction of seeded vulns the engineer's proposed fix *provably closes on re-scan*, computed by reusing
the SAME `retest.Verify` the product runs (so bench and product can never drift on "what is fixed").
Its respected external analog is **SWE-bench Verified** ("does the patch make the test pass") — same
execution-verified spirit. Around it: attack-path recall (the cross-surface chain), triage precision
(decoys left alone), and grounding (FP=0, the §10 bar).

The load-bearing design choice is the **substrate-vs-agent ablation** (`--mode`): the same scenario
runs deterministic-remediation-only *and* engineer-driven, and the delta is the LLM engineer's
**measured lift**. Nobody else ablates their AI against their own substrate — so this is a defensible
number Aikido's "95% noise" slogan cannot answer. The committed baseline
(`bench/defense-ledger.jsonl`) shows the deterministic substrate remediates + finds the code→cloud
chain but *fails triage on the decoy* — exactly where the engineer's lift lands.

Two symmetric, ungameable, climbing scoreboards result: **attack** = XBOW flags captured, **defense**
= vulns verifiably remediated + agent-lift. The defense one is something no AI-SOC competitor
publishes. (Honest caveat: triage-precision at scale needs a labeled decoy corpus — the one defensive
dimension that can't be grounded without curation; remediation-capture and path-recall ground cheaply.)

---

## The noise / false-positive axis (Aikido's headline metric)

Aikido leads with "**reduce noise by 95 %**" (no published method). This is the same axis our
**L1.5 enrichment chain** targets, and unlike the 95 % figure ours is **measurable and ablatable**:

- **`TSENGINE_L15_DISABLED=1`** re-runs any bench with the L1.5 hook chain off, so the
  noise-reduction lift is the *measured delta*, not a slogan (CLAUDE.md §14.1).
- **FP-control fixtures** (`fixtures/container/alpine-clean`, `fixtures/repo/clean`) score a
  **severity floor** — any finding at/above `high` on a clean target is a false positive
  (`Score.FalsePositiveCount`) — pairing sensitivity with specificity (Youden) per asset
  (CLAUDE.md §14.1.1).
- The L1/L1.5 split means the **security engineer still sees raw findings** (`findings_raw`)
  while the developer sees the de-noised view (`findings_enriched`) — both ship, the demotions
  are logged + recoverable (`l15_audit_log`). Aikido's AutoTriage de-prioritises but does not
  publish an auditable demotion ledger.

**Read:** we can *prove* our noise reduction and let an auditor replay it; Aikido asserts a
number. We already have one **measured** instance: on the prowler-grounded account
(`tsbench cloud-engine --cloudquery`) the engine took **10 prowler findings down to 2 reachable
attack-paths** — it downgraded 6 as config-bad-but-not-on-a-reachable-path, each downgrade
replayable against the snapshot. That is an 80 % cut on this account, *grounded and auditable*,
versus Aikido's unmeasured "95 %". Producing the same delta on the SAST/container benches (the
`TSENGINE_L15_DISABLED` ablation) is the concrete next bench run.

---

## Coverage matrix (capability parity)

What each platform covers. `✓` = shipped, `—` = not offered, `partial` = subset.
Aikido coverage is from aikido.dev (2026-06-21); ours from [benchmark.md](../benchmark.md) + CLAUDE.md §3.

| Capability | Aikido | tsengine |
|---|---|---|
| SAST | ✓ | ✓ (semgrep + codeql escalation) |
| SCA (dependencies) | ✓ | ✓ (trivy + grype + osv, reachability) |
| Secrets | ✓ | ✓ (gitleaks + trufflehog) |
| Malware / malicious packages | ✓ | ✓ |
| IaC | ✓ | ✓ (checkov) |
| Container image | ✓ | ✓ (trivy + grype + dockle + cosign) |
| CSPM (cloud posture) | ✓ | ✓ (prowler + scoutsuite) |
| EOL / outdated runtime | ✓ | ✓ |
| License risk | ✓ | ✓ (SBOM copyleft) |
| DAST / web | ✓ (surface monitoring) | ✓ (nuclei + dalfox + sqlmap, recon→fan-out) |
| API security | ✓ | ✓ (spec-ingest + schemathesis + kiterunner + inql) |
| AI pentest (verified exploitation) | ✓ (Doyensec-benchmarked) | ✓ (active driver, consent-gated; `verified_rate`) — *bench pending* |
| Runtime protection (in-app firewall) | ✓ (blocks) | ✓ **consumes** the signal (RASP events → exploitability), never blocks (§13) |
| **IP / host range scanning** | — | ✓ (naabu + nmap + nuclei) |
| **Domain / external attack-surface recon** | — | ✓ (subfinder + amass + crt.sh + dnstwist) |
| **Mobile application** | — | ✓ (mobsfscan) |
| **SSPM (SaaS posture)** | partial | ✓ (GitHub org + Slack; Atlassian/Zoom/Salesforce next) |
| **Identity / email-auth posture** (Workspace/M365/Okta, DMARC/SPF/DKIM) | — | ✓ (`internal/operate`) |
| **Compliance frameworks mapped** | subset | ✓ 14 (SOC2/ISO/PCI/HIPAA/CIS/NIST/GDPR/…) with signed evidence |
| **Signed, reproducible evidence bundle** | — | ✓ (ed25519 attestation, CLAUDE.md §10) |

**Read:** at AppSec/cloud parity, tsengine **adds four surfaces Aikido doesn't run** (IP, domain,
mobile, identity/email posture), a deeper compliance layer (14 frameworks + signed evidence), and
treats runtime as a *signal* rather than a blocker. Aikido's edge today is the **published
agentic benchmark** and **brand/scale social proof** (50k+ orgs) — the former we can close with a
live `bench/agent` run, the latter is a real-data/market dependency, not an engineering gap.

---

## What's measured vs pending (honest status)

| Lane | Status |
|---|---|
| Repository · SAST (OWASP Benchmark) | **Measured: 0.387 Youden** (above Fortify 35 %) |
| Cloud · attack-path engine — CloudGoat replay | **Measured: 2/2** scenarios reached the documented real-lab compromise (`tsbench cloud-engine --cloudgoat`) |
| Cloud · attack-path engine — prowler-grounded account | **Measured: 100 % attack-path recall** (2/2 reachable targets); engine surfaced 2 reachable paths from 10 prowler findings and **downgraded 6** as not-on-a-reachable-path — an auditable noise cut (`tsbench cloud-engine --cloudquery`) |
| Web / SCA / container / api / ip / domain L1 lanes | Harness + scorer + competitor bar **ready**; live recall **pending** the sandbox image build + a reachable target (heavy; out of scope for an analysis pass) |
| Agent · `verified_rate` vs the Doyensec/XBOW yardstick | **Pending a live `bench/agent` run** (Track 1 A1) — the single highest-value number to close this comparison |

These cloud numbers were **measured in this pass** — the cloud attack-path engine is
deterministic + snapshot-driven (LLM-free, CLAUDE.md §10), so it scores without the sandbox or
a live account. The remaining L1 recall lanes need the sandbox (`make sandbox-image`) + a
reachable target, then `tsbench scoreboard --results <json> --out SCOREBOARD.md` refreshes the
board. We deliberately did **not** print estimated numbers — only what ran.

### What we measured this run (2026-06-21)

```
$ tsbench cloud-engine --cloudgoat        # vs CloudGoat (Rhino) published pentest solutions
[PASS] cloud_breach_s3            reached documented compromise: cg-secret-s3-bucket-cardholder-data
[PASS] iam_privesc_by_rollback   reached documented compromise: admin
calibration: 2/2 scenarios matched the documented real-lab compromise.

$ tsbench cloud-engine --cloudquery       # prowler-grounded account, scored vs the cloudiam answer key
prowler findings (catalog over the config): 10  →  engine real paths: 2, downgraded: 6
attack-path recall: 100.00%  (2/2 real targets reached)
verdict: PASS
  path: internet reaches web    runs as web-role    reads acme-customer-pii
  path: internet reaches deploy runs as deploy-role escalates to effective-admin
  + 2 verified remediations (cloudiam.Authorize confirms each cuts the path)
```

This is the cloud lane's answer to Aikido's two headline claims at once: an **outcome** (reaches
the same compromise a documented human pentest did, CloudGoat 2/2 — the *form* of proof Aikido's
Doyensec report uses) **and** a **measured, auditable noise cut** (10 prowler findings → 2
reachable paths, every downgrade replayable — the *substance* behind Aikido's unmeasured "95 %").

### The honesty probe: a held-out generalization test (and what it found)

We also ran the **anti-overfit holdout** (`tsbench cloud-engine --holdout 30`) — 30 freshly
*generated* accounts whose ground truth is labelled **independently** by `cloudiam` (full
permission-boundary + trust-policy evaluation), not by the engine's own oracle:

```
attack-path recall:             100.00%  (60/60 genuinely-reachable paths)
FP-reduction (known shapes):    100.00%  (120/120)   ← in-distribution
FP-reduction (HELD-OUT shapes):   0.00%  (0/120)     ← the generalization probe → verdict FAIL
```

**We report this, we don't hide it.** Recall generalises (100 %), but on *novel* trust/boundary
shapes the graph ingest **over-approximates reachability** — it adds an assume-role / privesc
edge from the inventory without re-checking that the target's trust policy or the principal's
permission boundary actually permits the move, so it can report a *blocked* path as real. The
fix is known and scoped: **wire `cloudiam.Authorize` (which already evaluates boundaries + trust
policies) into the `cloudgraph` ingest edge-builder** (`internal/cloudgraph/ingest.go` — the
`EdgeAssumeRole` / `EdgePrivesc` adds) so an edge is only created when the move is actually
authorized. Tracked as the cloud-engine precision follow-up.

The point for this comparison: **we run a held-out probe that can fail us, and publish the
result.** Aikido publishes a single commissioned head-to-head and a round "95 %" with no
precision/generalization data at all. Surfacing our own over-approximation is the grounding
discipline (CLAUDE.md §10) working as intended — the bar is an *honest* number, not a flattering
one.

---

## Sources

- Aikido platform & claims — <https://www.aikido.dev/> (coverage, "95 % noise reduction",
  "Aikido vs XBOW: 58 % more vulnerabilities").
- Doyensec independent *Aikido vs XBOW* benchmark (May 2026) —
  <https://www.aikido.dev/reports/aikido-vs-xbow> and
  <https://blog.doyensec.com/2026/05/27/aikido-xbow.html>.
- Our framework — [benchmark.md](../benchmark.md), [SCOREBOARD.md](../SCOREBOARD.md),
  [competitive-roadmap.md](competitive-roadmap.md), CLAUDE.md §14.
