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
| 1 | **web_application** | **WAVSEP** (Shay Chen, sectoolmarket.com) — Acunetix 87%, Netsparker 87%, Burp 78%, WebInspect 76%, AppScan 69%, ZAP 56% | `✓` katana (recon), `✓` nuclei, `✓` dalfox, `✓` sqlmap (SQLi specialist), `✓` httpx, `✓` seed_auth (authed re-scan) · *anchor:* ffuf, hydra, smuggler, http_security_headers_audit, tls_audit, cors_deep_check, csrf_check, open_redirect_check · *registry:* wapiti, nikto, jaeles, arachni, w3af, skipfish, ZAP-active, gobuster |
| 2 | **api** | **VAmPI** + **crAPI** working-group writeups (no neutral leaderboard; Salt / Wallarm commercial) | `✓` openapi_spec_ingest (recon), `✓` schemathesis (spec fuzz), `✓` nuclei (`tags=api,graphql,jwt,oauth`, per-method routed) · *anchor:* kiterunner, inql · *authz backlog (Akto/ADR):* scan_api_bola/bfla/mass_assignment · *registry:* APIClarity, ZAP-API, restler |
| 3 | **repository** | **OWASP Benchmark v1.2** (SAST) — Veracode 51%, Checkmarx 47%, Fortify 35%, SonarQube 6%; SCA: Snyk / Dependabot self-published | `✓` semgrep (SAST), `✓` gitleaks + `✓` trufflehog (secrets), `✓` trivy fs + `✓` grype + `✓` osv-scanner (SCA ×3), `✓` checkov (IaC), `✓` hadolint (Dockerfile), `✓` syft (SBOM) · *anchor:* bandit, mobsfscan, tfsec · *registry:* CodeQL (taint-flow), brakeman, gosec, staticcheck, snyk-code, kics |
| 4 | **container_image** | None neutral — Trivy / Snyk Container / Anchore self-published | `✓` trivy image (CVE + misconfig + secret, base-layer skip), `✓` grype (2nd CVE DB), `✓` dockle (CIS misconfig), `✓` syft (SBOM) · *anchor:* anchore, hadolint · *registry:* clair, kube-bench, falco-rules, snyk-container |
| 5 | **ip_address** | None neutral — Tenable / Qualys / Rapid7 (no open scorecard) | `✓` naabu (recon → port surface), `✓` nmap (deep `-sV`), `✓` httpx (HTTP probe + tech), `✓` nuclei (per-port tag-routed) · *anchor:* tls_audit (via nuclei ssl tags) · *registry:* masscan, rustscan, nessus-essentials, openvas |
| 6 | **domain** | None neutral — subfinder vs amass vs assetfinder published enum rates | `✓` subfinder + `✓` amass + `✓` crt.sh (enum ×3, union), `✓` checkdmarc (DNS hygiene), `✓` nuclei (takeover) · child-asset pivot → web/ip · *registry:* findomain, censys-cli, shodan-cli, bbot |
| 7 | **cloud_account** | None neutral — Prowler / scout-suite self-published; CIS AWS Foundations recall | `✓` prowler + `✓` scoutsuite (posture ×2, corroboration) · *registry:* `✓` cloudfox (IAM attack-path, scope-gated), pacu (gated), cloudmapper, principal-mapper |

---

## Benchmark build status (per asset)

The harness (`tsbench`, `internal/bench`) is fully built and tested. What
varies is whether each asset has a *fixture wired to a corpus*. Legend:
**✓ live** = runnable + passing; **⚠ stub** = harness + competitor numbers
ready, corpus not yet deployed; **✗ none** = no fixture yet.

| Asset | Popular benchmark | Fixture | Built? |
|---|---|---|---|
| **container_image** | (no neutral leaderboard) — Trivy / Snyk / Anchore self-published | `fixtures/container/nginx-vuln` + `alpine-clean` | **✓ live** — recall 1.0 on nginx:1.14 (must-find CVEs), 0 false-positives on clean alpine:3.18 |
| **web_application** | **WAVSEP** (Shay Chen) — Acunetix 87% / Burp 78% / ZAP 56% | `fixtures/web/wavsep` | **⚠ scorer-ready** — per-category Youden scorer + `tsbench wavsep` subcommand built (W5); CWE→WAVSEP category map (sqli/xss/pathtraver/redirect/…). Blocked on: deploy the WAVSEP webapp reachable from the sandbox **and** rebuild the image (katana/sqlmap/seed_auth not yet baked) |
| **repository** | **OWASP Benchmark v1.2** (SAST) — Veracode 51% / Checkmarx 47% / Fortify 35% / SonarQube 6% | `fixtures/repo/owasp-benchmark` | **⚠ stub** — semgrep now wrapped (tool-ready); needs the BenchmarkJava source tree mounted at `/workspace` |
| **api** | **VAmPI** + **crAPI** (no neutral leaderboard) | `fixtures/api/vampi` | **⚠ stub** — must-find fixture written (openapi+schemathesis); needs VAmPI deployed + image rebuilt |
| **ip_address** | (no neutral leaderboard) — Tenable / Qualys / Rapid7 | `fixtures/ip/services` | **⚠ stub** — must-find fixture written (naabu open-port); needs a services host + image rebuilt |
| **domain** | (no neutral leaderboard) — subfinder vs amass published rates | `fixtures/domain/recon` | **⚠ stub** — must-find fixture written (subdomain-found); needs a target domain + image rebuilt |
| **cloud_account** | (no neutral) — Prowler / scout-suite; CIS AWS Foundations | `fixtures/cloud/baseline` | **⚠ stub** — fixture written; needs a seeded mock AWS account + image rebuilt |

**Summary: 1 of 7 assets has a live benchmark** (container_image); the other
six are **stubs** — every asset now has a fixture that cites its competitor
context and loads through the harness. They're blocked on deploying the
external corpus/target (and, for the asset-wave tools, a single image
rebuild), not on tsengine code.

Per CLAUDE.md §14, a benchmark is meaningless without "vs. what" — so every
fixture **must** cite its competitor leaderboard, and the harness refuses to
load one that doesn't (CLAUDE.md §14.2.2).

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
