# benchmark.md — tsengine L1 benchmark matrix

How each of the 7 asset types is detected and benchmarked. This is the
operational companion to [arch.md](arch.md) §benchmark-infrastructure and
[CLAUDE.md](CLAUDE.md) §14.

`✓` marks tools **wrapped + installed in the sandbox image today**. Other
tools are the documented target set — **anchor tier** fires on every scan,
**registry tier** is on-demand via the tool-replay API (CLAUDE.md §4).

---

## The matrix

| # | Asset type | Popular benchmark (neutral competitor scores) | Detection tools |
|---|---|---|---|
| 1 | **web_application** | **WAVSEP** (Shay Chen, sectoolmarket.com) — Acunetix 87%, Netsparker 87%, Burp 78%, WebInspect 76%, AppScan 69%, ZAP 56% | `✓` katana (recon), `✓` nuclei, `✓` dalfox, `✓` sqlmap (SQLi specialist), `✓` httpx, `✓` seed_auth (authed re-scan) · *escalation (signal-gated):* `✓` nuclei DAST/OAST (param→blind), `✓` nuclei default-logins (login), `✓` ffuf (thin surface) · *registry:* wapiti, nikto, ZAP-active |
| 2 | **api** | **VAmPI** + **crAPI** working-group writeups (no neutral leaderboard; Salt / Wallarm commercial) | `✓` openapi_spec_ingest (recon), `✓` schemathesis (spec fuzz), `✓` nuclei (`tags=api,graphql,jwt,oauth`, per-method routed) · *escalation:* `✓` kiterunner (spec→shadow routes), `✓` inql (graphql→introspection) · *authz backlog (Akto/ADR):* scan_api_bola/bfla/mass_assignment |
| 3 | **repository** | **OWASP Benchmark v1.2** (SAST) — Veracode 51%, Checkmarx 47%, Fortify 35%, SonarQube 6%; SCA: Snyk / Dependabot self-published | `✓` semgrep (SAST), `✓` gitleaks + `✓` trufflehog (secrets), `✓` trivy fs + `✓` grype + `✓` osv-scanner (SCA ×3), `✓` checkov (IaC), `✓` hadolint (Dockerfile), `✓` syft (SBOM) · *escalation:* `✓` codeql (semgrep-injection→taint), `✓` mobsfscan (mobile) · *registry:* brakeman, gosec, snyk-code |
| 4 | **container_image** | None neutral — Trivy / Snyk Container / Anchore self-published | `✓` trivy image (CVE + misconfig + secret, base-layer skip), `✓` grype (2nd CVE DB), `✓` dockle (CIS misconfig), `✓` syft (SBOM), `✓` cosign (signature/SLSA provenance) · *registry:* clair, kube-bench, snyk-container |
| 5 | **ip_address** | None neutral — Tenable / Qualys / Rapid7 (no open scorecard) | `✓` naabu (recon → port surface), `✓` nmap (deep `-sV`), `✓` httpx (HTTP probe + tech), `✓` nuclei (per-port tag-routed) · *escalation:* `✓` hydra (auth-port→default-creds) · *registry:* masscan, rustscan, openvas |
| 6 | **domain** | None neutral — subfinder vs amass vs assetfinder published enum rates | `✓` subfinder + `✓` amass + `✓` crt.sh (enum ×3, union), `✓` checkdmarc (DNS hygiene), `✓` dnstwist (lookalike/typosquat), `✓` nuclei (takeover) · child-asset pivot → web/ip · *registry:* findomain, censys-cli, bbot |
| 7 | **cloud_account** | None neutral — Prowler / scout-suite self-published; CIS AWS Foundations recall | `✓` prowler + `✓` scoutsuite (posture ×2, corroboration) · *registry:* `✓` cloudfox (IAM attack-path, scope-gated), pacu (gated), cloudmapper, principal-mapper |

---

## Benchmark build status (per asset)

The harness (`tsbench`, `internal/bench`) is fully built and tested. What
varies per asset is whether a *fixture is wired to a reachable target/corpus*
and (for neutral-leaderboard assets) whether a per-category scorer exists.
Legend: **✓ live** = runnable + scored; **⚠ scorer-ready** = harness + scorer
+ competitor numbers ready, target reachable, number pending; **⚠ stub** =
harness ready, target not wired; **✗ none** = no fixture.

> **Leg-up — reuse the strix target images.** The strix project left several
> intentionally-vulnerable **target images already on the build host**.
> tsengine can point `tsbench` at them directly (no new deployment), exactly
> as we did for WAVSEP.

| Asset | Class | Benchmark dataset | Neutral leaderboard | Target image local (ex-strix) | Status |
|---|---|---|---|---|---|
| **web_application** | DAST | **WAVSEP** (1,133 cases) | Acunetix 87 / Netsparker 87 / Burp 78 / WebInspect 76 / AppScan 69 / ZAP 56 (Shay Chen) | ✅ `zaproxy/wavsep` | **⚠ scorer-ready** — full recon→fan-out + **form-param synthesis** live; per-category Youden run in progress |
| **repository** | SAST | **OWASP Benchmark v1.2** (BenchmarkJava, 2,740 cases) | Veracode 51 / Checkmarx 47 / Fortify 35 / SonarQube 6 | ✅ `strix-bench/owasp-benchmark:v1.2` | **✅ live — overall Youden 38.67%** (TP=1094 FP=512 TN=813 FN=321; clean run, not partial). Between Fortify (35) and Checkmarx (47), ≫ SonarQube (6). `tsbench sast` + per-CWE scorer (`internal/bench/sast.go`). Best cats: securecookie/weakrand 100, hash 69, xss 30. Gap: crypto 0 (CWE-327 unmapped by semgrep p/security-audit) |
| **repository** | SCA | OWASP **NodeGoat** + lockfiles | Snyk / Dependabot (self-published) | ⬇️ git repo (lockfile scan, no image) | **⚠ stub** — trivy-fs/grype/osv wrapped; must-find CVE set |
| **repository** | IaC | **TerraGoat** / KICS samples | Checkov / tfsec / KICS (self) | ✗ (clone TerraGoat) | **✗ none** — checkov wrapped; corpus not wired |
| **api** | spec-fuzz / authz | **VAmPI** + **crAPI** | none neutral (Salt / Wallarm commercial) | ✅ `erev0s/vampi` + `crapi/*` | **⚠ stub** — openapi+schemathesis must-find fixture |
| **container_image** | CVE / misconfig | must-find CVE set (nginx:1.14) | Trivy / Snyk / Anchore (self) | ✅ `nginx` images | **✓ live** — recall 1.0 on must-find CVEs, 0 FP on clean alpine |
| **ip_address** | network / services | vulnerable-services host | Tenable / Qualys / Rapid7 (no scorecard) | ⚠ compose (ex-strix `vulnerable-services`) | **⚠ stub** — naabu open-port must-find |
| **domain** | recon breadth | subdomain-enum corpus | subfinder vs amass (published rates) | ✗ (needs a target domain) | **⚠ stub** — subdomain-found must-find |
| **cloud_account** | CSPM / CIS | CIS Benchmark vs mock AWS | Prowler / scout-suite (self) · CIS AWS Foundations recall | ✗ **strix had none** (tsengine-only asset) | **⚠ stub** — prowler/scoutsuite wrapped; needs seeded mock AWS |

**Status: 2 of 7 live** (container_image; **repository/SAST — Youden 38.67%**);
web (WAVSEP) is scorer-ready but the full-corpus fan-out times out at 50m
(detection proven on focused scans; scaling fix tracked). The rest are
harness-ready stubs blocked on a target, not on tsengine code. Per CLAUDE.md §14, every fixture **must**
cite its competitor leaderboard — the loader rejects one that doesn't (§14.2.2).

> **L1 vs L2 benchmarks.** This matrix is **L1 detection recall** (did we find
> the vuln the OSS tool would?). The **L2 exploit/agentic** benchmarks —
> **XBEN** (104 web CTF, strix scored 96%), **Juice Shop**, **WebGoat** —
> measure *completion_rate* (did the agent chain + capture the flag), a
> different metric on the ADR-gated autonomous-exploiter track (arch.md).
> `bkimminich/juice-shop` + `webgoat/webgoat` are already local for that track.

---

## Proposal: wiring L1 benchmarks for all 7 assets

The harness, multi-trial (median + p10/p90), L1.5 ablation, and anti-overfit
guards are built. What remains per asset is a **fixture wired to a reachable
target** plus, for the two neutral-leaderboard assets, a per-category Youden
scorer. Ordered by effort — exploit the locally-available ex-strix images first.

### Tier 1 — target image already local (≈ WAVSEP effort each)

1. **repository / SAST → OWASP Benchmark v1.2 — highest value** (the 2nd neutral
   leaderboard after WAVSEP). Mount `strix-bench/owasp-benchmark:v1.2`'s
   BenchmarkJava tree at `/workspace`; add a per-CWE Youden scorer keyed on
   `expectedresults-1.2.csv` (the SAST analogue of the WAVSEP CWE→category map);
   `tsbench sast --target <repo> --ground-truth expectedresults-1.2.csv`. Scores
   vs Veracode 51 / Checkmarx 47 / Fortify 35 / SonarQube 6.
2. **api → VAmPI (+ crAPI)**. Bring up the local `erev0s/vampi` (and `crapi/*`
   compose); `openapi_spec_ingest` → schemathesis/nuclei/kiterunner fan-out;
   score the written must-find set (BOLA / BFLA / mass-assignment / JWT). No
   neutral leaderboard → internal must-find recall.
3. **web → Juice Shop / WebGoat** (secondary DAST corpus). `bkimminich/juice-shop`
   + `webgoat/webgoat` already local — a second DAST data point beyond WAVSEP
   (and the bridge to the L2 completion_rate track).

### Tier 2 — clone a repo (no running target)

4. **repository / SCA → NodeGoat + lockfiles**. Clone NodeGoat; trivy-fs / grype /
   osv-scanner over its lockfiles; must-find CVE recall vs Snyk / Dependabot.
5. **repository / IaC → TerraGoat / KICS samples**. Clone TerraGoat; checkov over
   it; must-find recall vs Checkov / tfsec / KICS.

### Tier 3 — needs a provisioned target

6. **ip_address → vulnerable-services host**. Stand up the ex-strix
   `vulnerable-services` compose (or a vulhub host); naabu → nmap → nuclei;
   must-find open-port/service recall.
7. **domain → recon breadth**. Point subfinder + amass + crt.sh at a controlled
   zone (or a public bug-bounty scope) with known subdomains; subdomain-discovery
   rate vs published subfinder/amass numbers.
8. **cloud_account → CIS vs mock AWS**. Seed a mock AWS account (LocalStack, or a
   sandbox account with known CIS misconfigs); prowler + scoutsuite; CIS-control
   recall. tsengine-only asset (no strix precedent) — the compliance differentiator.

### Cross-cutting requirements (every new bench)

- **Scorer**: per-CWE/category Youden for the neutral-leaderboard assets
  (web ✓ built, repo-SAST ✗ to build); **must-find recall** for the rest.
- **Anti-overfit source-grep** (`internal/bench/guard_test.go`) must forbid each
  new SUT identifier — `benchmarkjava`, `vampi`, `crapi`, `nodegoat`,
  `terragoat` — in scoring code (§14.2.1). Ground truth lives in fixture JSON only.
- Every fixture **must** cite its competitor leaderboard or the loader rejects
  it (§14.2.2); reports always emit a `competitors:` block.
- **Multi-trial** (median + p10/p90) and the **L1.5 ablation**
  (`TSENGINE_L15_DISABLED=1`) are already wired — reuse them.

---

## Running benchmarks

```sh
make bench            # run the live container fixtures
make bench-ablation   # L1.5 on-vs-off on the container fixture

# individual fixtures:
./bin/tsbench run      --fixture fixtures/container/nginx-vuln
./bin/tsbench ablation --fixture fixtures/container/nginx-vuln

# WAVSEP: per-category Youden vs. the commercial leaderboard (W5).
# Drives a deployed WAVSEP webapp through the full recon→fan-out pipeline,
# scores findings by CWE→category, renders the competitor comparison.
./bin/tsbench wavsep --target http://<wavsep-host>:8080 \
                     --ground-truth fixtures/web/wavsep/expected-cases.csv
```

`run` repeats N trials (`--trials N`) and reports **median + p10/p90** —
single-trial numbers are noise (CLAUDE.md §14.2.3).

---

## The L1.5 ablation — the load-bearing measurement

`tsbench ablation` runs each fixture twice — L1.5 hooks on, then off
(`TSENGINE_L15_DISABLED=1`) — and reports both deltas:

```
detection recall    L1.5-on=1.000  L1.5-off=1.000  (Δ=0.000 — L1.5 is translation, not detection)
enrichment coverage L1.5-on=1.000  L1.5-off=0.000  (Δ=1.000 — THIS is the L1.5 lift)
```

This empirically validates the architecture's central claim (CLAUDE.md
§1.5.1): **L1.5 adds zero detection and 100% enrichment.** It's the
translation layer for the non-security audience, not a detector. A PR that
moves the detection-recall Δ away from 0 is changing L1, not L1.5, and is
scored against the L1 recall bench.

---

## Anti-overfit guards (CLAUDE.md §14.2)

1. **Source-grep** — `internal/bench/guard_test.go` fails the build if any
   SUT identifier (juice-shop, bkimminich, vampi, crapi, nginx, alpine, a
   CVE id, …) appears in the scoring code. All ground truth lives in
   fixture JSON, never in scoring logic.
2. **Mandatory competitor citation** — the fixture loader rejects a fixture
   with no leaderboard or note; `Render` always emits a `competitors:` block.
3. **Multi-trial** — median + p10/p90 over N.
4. **Per-layer ablation** — the L1.5 Δ above.

---

## Why some assets have no neutral leaderboard

Only web (WAVSEP) and source-code SAST (OWASP Benchmark) have neutral,
published, vendor-comparable scorecards. API / container / network / domain
/ cloud scanning vendors all self-publish, so for those assets recall is
measured against a curated must-find set derived from the target's known
advisories — internal, but reproducible and pinned to a corpus version
(CLAUDE.md §10). When a neutral scorecard surfaces for one of them, its
fixture's `competitors` block is updated and the comparison goes live.

> OWASP Benchmark mixes SAST and DAST tools on the same Java corpus. The
> SAST cohort (Veracode/Checkmarx/Fortify/SonarQube) is the comparison for
> `repository`; DAST tools on that corpus (ZAP 13%) are not — see
> CLAUDE.md §6.1.1.
