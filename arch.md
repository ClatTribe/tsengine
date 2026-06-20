# arch.md — tsengine L1 architecture map

This document is the architecture map for tsengine's L1 + L1.5 + L2 detection
stack across all 8 asset types. It is the source of truth for "what tool
runs where, what filter applies, what the dashboard surfaces, what we
benchmark against." Keep this updated when you change anchor lists,
registry tools, filter rules, or compliance mappings.

For deeper invariants (host vs sandbox boundary, the L1.5 hook order, the
≤12-tool cap, reproducibility), see [CLAUDE.md](CLAUDE.md).

---

## Table of contents

1. [Per-asset architecture matrix](#per-asset-architecture-matrix)
   - [web_application](#web_application--dast)
   - [api](#api--dast--spec-driven)
   - [repository](#repository--sast--sca)
   - [container_image](#container_image--image-scan)
   - [ip_address](#ip_address--network-scan)
   - [domain](#domain--asset-discovery--dns-hygiene)
   - [cloud_account](#cloud_account--posture--compliance)
2. [Anchor vs registry tier](#anchor-vs-registry-tier)
3. [L1.5 hook chain](#l15-hook-chain)
4. [Sandbox → host findings propagation](#sandbox--host-findings-propagation)
5. [Tool-replay API](#tool-replay-api)
6. [Threat intel enrichment at L1](#threat-intel-enrichment-at-l1)
7. [Compliance control mapping at L1](#compliance-control-mapping-at-l1)
8. [Reproducibility / attestation](#reproducibility--attestation)
9. [L1 dashboard contract](#l1-dashboard-contract)
10. [Detection layer model (L0 → L3)](#detection-layer-model-l0--l3)
11. [Host vs sandbox boundary](#host-vs-sandbox-boundary)
12. [L2 OODA loop (parked)](#l2-ooda-loop-parked)
13. [Benchmark infrastructure](#benchmark-infrastructure)
14. [Repo layout](#repo-layout)
15. [Build phases](#build-phases)
16. [The repeating pattern](#the-repeating-pattern)
17. [Where to look in code](#where-to-look-in-code)

---

## Per-asset architecture matrix

For each asset type: anchor tools (always-fire), registry tools (on-demand
via the tool-replay API), filter dimension, L1.5 enrichment, L2 catalog
shape, bench.

### `web_application` — DAST

| Layer | Element | Detail |
|---|---|---|
| **Anchor tier** | Recon | katana (crawl), webapp_recon_pipeline (SPA crawl), openapi_spec_ingest, fingerprint_tech_stack |
| | Deep exploit | sqlmap, dalfox, nuclei (template corpus), smuggler, ffuf, hydra (default creds) |
| | DOM-aware | scan_xss, dom_xss_static_probe, scan_cache_deception, scan_websocket_auth, scan_prototype_pollution |
| | Hygiene | http_security_headers_audit, tls_audit, cors_deep_check, csrf_check, open_redirect_check |
| **Registry tier** | (on-demand via /replay) | wpscan (WordPress CMS DAST — also escalation-fired), wapiti, nikto, jaeles, arachni, w3af, skipfish, ZAP active, gobuster |
| **L1 filtration** | Static-asset drop | `.css`, `.png`, `.woff`, bundled JS — extension filter |
| | Destructive drop | `/admin/delete-*`, `/logout` — destructive-class filter |
| | Scope | Same host or subdomain only; off-host (twitter, CDN) dropped. `scope.scope_hosts` whitelists extras |
| | Shape dedup | `(host, path-shape, sorted-query-names)`; `/items/1` ≡ `/items/2` → `/items/:int`; UUID/hash/date placeholders too |
| | Login protection | `/login`, `/signin` → nuclei only (skip sqlmap to avoid lockout / CAPTCHA) |
| | Per-URL tool routing | sqlmap on SQL-like params; dalfox on text params; open_redirect on `url=`/`redirect=`; nuclei always |
| **L1.5 enrichment** | (cross-asset — see §3) | FP filter → surface_priority → exploitability → corroborator → threat_intel → compliance → post_emit_verifier → cross-tool merge |
| **L2 catalog (≤12)** | READ STATE (4) | workflow_status, list_pending_findings, get_finding, get_recon_artifact |
| | FETCH EXTERNAL (2) | query_threat_intel, lookup_compliance_mapping |
| | RE-DISPATCH (2) | rescan, dispatch_l2_probe (kind ∈ {idor, auth_flow, business_logic} or tool=`<registry tool>` for arbitrary registry invocation) |
| | ORIENT (1) | think (persists to lead_reasoning_trace) |
| | COMMIT (2) | create_vulnerability_report, finish_scan |
| | PRIMITIVES (1) | send_request |
| **Bench** | Headline | `bench/wavsep` (1,133 cases) |
| | Comparator | Acunetix 87% / Netsparker 87% / Burp 78% / ZAP 56% (Shay Chen WAVSEP, sectoolmarket.com) |

> **Implemented DAST pipeline (W1–W6).** The matrix above is the target
> catalog. What ships today is the deterministic L1 pipeline that fans the
> built anchors across a crawled surface:
>
> 1. **Recon** (W1) — `katana` crawls the target *in the sandbox* (not a
>    host helper; strix's mistake was routing recon host-side).
>    `Result.DiscoveredURLs` → `asset.CollectSurface` (dedupe, target-first,
>    cap `TSENGINE_FANOUT_MAX_URLS`=200). No recon tool → graceful fallback
>    to single-target `PlanAnchors`.
> 2. **Filtration** (W2) — `filterSurface`: scope → static-asset drop →
>    destructive-path drop → shape-dedup (`/items/1`≡`/items/N`→`:int`,
>    plus uuid/hash/date). `internal/asset/web/{filter,shape}.go`.
> 3. **Fan-out** (W1/W4) — `PlanFanout`: `nuclei`+`httpx` run **once** over
>    the whole surface (`-list`/`-l`); `dalfox`+`sqlmap` run **per-URL on
>    param-bearing URLs only** (an injection point is required). sqlmap is
>    the SQLi specialist (W4) — stdout Parameter/Type parse → CWE-89.
> 4. **Wave ordering** (W3) — `partitionWaves` (`internal/orchestrator/deps.go`)
>    topo-sorts dispatches by a static dependency table. All-independent
>    batches collapse to one wave (zero overhead). Lands the guard *before*
>    any state-coupled tool exists, so strix's Q4.2 unguarded-parallel race
>    is impossible by construction.
> 5. **Authenticated re-scan** (W6) — when `Asset.Auth` is set, `PlanFanout`
>    prepends a `seed_auth` dispatch (passthrough cookie, or form-login →
>    `Set-Cookie`). nuclei/dalfox/sqlmap/httpx depend on `seed_auth` in the
>    table → it runs in wave 0; `executeWaves` threads the captured session
>    (`Result.CapturedSession`, sandbox-boundary-only, never in the
>    dashboard) into the detectors' `args["cookie"]` in wave 1 (an explicit
>    cookie is never clobbered). CLI: `--auth-cookie` | `--auth-login-url
>    --auth-username --auth-password`. Auth failure → no session →
>    detectors scan unauthenticated (graceful).
>
> **Backlog (not built):** SPA/JS-rendered crawl (`webapp_recon_pipeline`),
> DOM-aware specialists (`scan_xss`, `dom_xss_static_probe`, prototype
> pollution, cache deception), request-smuggling (`smuggler`), CSRF-token /
> multi-step / SPA login in `seed_auth`, and the registry-tier tools
> (wapiti, nikto, ZAP active, …). The L2 catalog rows are Phase 6.

---

### Escalation triggers — conditional depth (deterministic L1, waves E0–E4)

After detection, each handler may run a depth stage that fires expensive
tools ONLY on a matching signal (CLAUDE.md §5.3). Reproducible, bounded
(`TSENGINE_ESCALATION_MAX`=50, per-tool timeout), provenance-tagged
(`Dispatch.EscalatedFrom`). The deterministic half of "which tool when";
open-ended reasoning stays L2 (Phase 6).

| Asset | Signal | Depth tool | Why (gap no detector fills) |
|---|---|---|---|
| web | param URL | nuclei DAST/OAST (interactsh) | blind/out-of-band SSRF/XXE/RCE |
| web | login URL | nuclei `default-logins` | default creds |
| web | thin crawl surface | ffuf | hidden paths katana can't reach |
| web | WordPress surface (wp-login/wp-content/xmlrpc) | wpscan | vulnerable plugins/themes, user enum, exposed wp-config — CMS-specific gap generic DAST misses |
| ip | open auth port (22/3306/…) | hydra | default/weak service creds |
| api | spec ingested | kiterunner | undocumented/shadow routes |
| api | `/graphql` endpoint | inql | GraphQL introspection/schema |
| repository | semgrep injection finding | CodeQL (that language) | interprocedural taint past semgrep's ceiling |
| repository | mobile-file finding | mobsfscan | Android/iOS-specific SAST |
| repository | Go-project finding (`.go` / `go.mod`) | govulncheck | call-graph REACHABILITY — only the SCA CVEs whose vulnerable symbol is actually called (SCA FP-killer; ADR 0003) |

Unconditional breadth tools (dnstwist on domain, cosign on container) are
NOT escalation — they fan out / anchor every scan.

---

### `api` — DAST + spec-driven

| Layer | Element | Detail |
|---|---|---|
| **Anchor tier** | Recon | openapi_spec_ingest, fingerprint_tech_stack, discover_graphql_endpoints, sbom_extract, kiterunner |
| | Spec-driven fuzz | schemathesis, map_graphql_inql |
| | API specialists | scan_api_bola (OWASP API1), scan_api_bfla (API5), scan_api_mass_assignment (API3), scan_idor, scan_api_rate_limit, jwt_audit |
| | Broad signature | nuclei, scan_sqli, scan_xxe, scan_ssrf, scan_ssti, scan_path_traversal, scan_nosql_injection, scan_cmd_injection |
| **Registry tier** | (on-demand) | APIClarity (spec drift), ZAP API scan, restler, fuzzapi, hydra (API auth) |
| **L1 filtration** | Health endpoint drop | `/health`, `/metrics`, `/ping`, `/readyz`, `/version`, `/favicon.ico` |
| | Spec endpoint drop | `/swagger`, `/openapi.json`, `/v3/api-docs` |
| | Per-method routing | BOLA / IDOR → GET with `:id`; BFLA → POST/PUT/PATCH/DELETE; mass_assignment → POST/PUT/PATCH (no DELETE — nothing to mass-assign) |
| **L2 catalog** | Same shape as web | `dispatch_l2_probe(kind="business_logic")` is the API-specific re-dispatch |
| **Bench** | Headline | `bench/api_fixtures` (VAmPI + crAPI) |
| | Comparator | None public — VAmPI/crAPI working-group writeups; Salt/Wallarm (commercial) |

> **Implemented (wave A4).** Spec-ingest→fan-out: `openapi_spec_ingest`
> (pure-Go, fetches+parses the spec → `METHOD url` surface) is the recon
> tool; `PlanFanout` runs `schemathesis` once on the resolved schema +
> `nuclei` once over the operations (api tags). Per-method routing
> (`classifyOp`) is pre-declared for the authz specialists. **Backlog:**
> kiterunner + inql (registry sources); BOLA/BFLA/mass-assignment await an
> OSS wrapper (Akto) or an ADR — §13 forbids in-house. Fixture:
> `fixtures/api/vampi`.

---

### `repository` — SAST + SCA

| Layer | Element | Detail |
|---|---|---|
| **Anchor tier** | SAST (pattern-match) | semgrep (lang-aware packs — `p/java`+`p/findsecbugs`+`p/cwe-top-25` for Java, `p/python` for Python, `p/javascript`+`p/nodejsscan` for JS, etc.), bandit (Python), mobsfscan (Android/iOS) |
| | SCA (lockfiles) | trivy fs, grype, osv-scanner |
| | Secrets | gitleaks, trufflehog |
| | IaC / Dockerfiles | checkov, hadolint, tfsec |
| | SBOM | syft |
| **Registry tier** | (on-demand) | CodeQL (taint-flow SAST — biggest depth gain), brakeman, gosec, staticcheck, snyk-code (free CLI), kics, terrascan |
| **L1 filtration** | Language detection | semgrep packs chosen per language |
| | File-tree filter | Skip `node_modules/`, `vendor/`, `.git/`, `__pycache__/`, `dist/`, `build/`, `*.min.js`, binaries > 5MB |
| **L2 catalog** | Specialists | build_code_map, terminal_execute; rest of catalog same as web |
| **Bench** | Headline | `bench/owasp_benchmark` (2,740 cases) |
| | Comparator | Veracode 51% / Checkmarx 47% / Fortify 35% / SonarQube 6% (OWASP Benchmark v1.2 SAST leaderboard) |

> **Implemented (wave A5).** Wrapped: semgrep, gitleaks+trufflehog,
> trivy-fs+grype+**osv-scanner** (SCA ×3 → strong corroboration),
> **checkov** (IaC — the HashiCorp/cloud-native coverage strix's in-house
> engine lacked), **hadolint** (Dockerfile), **syft** (SBOM). CodeQL stays
> registry-tier (taint-flow depth). osv-scanner emits the CVE in its
> RuleID so the 3-source corroborator joins them.

---

### `container_image` — Image scan

| Layer | Element | Detail |
|---|---|---|
| **Anchor tier** | CVE detection | trivy image (gold standard), grype (second CVE DB for corroboration) |
| | Misconfig | dockle, hadolint (Dockerfile) |
| | SBOM | syft (CycloneDX) |
| | Policy | anchore (CIS Docker Benchmark) |
| **Registry tier** | (on-demand) | clair, kube-bench (for k8s manifests), falco-rules, snyk container (free CLI) |
| **L1 filtration** | Base-layer skip | `--ignore-base` so customer-added vulns surface separately from alpine/debian baseline noise |
| | Multi-arch fan-out | Per-platform scan for multi-arch manifests |
| **L2 catalog** | Specialists | scan_image_dockle, terminal_execute |
| **Bench** | Headline | `bench/container_cves` (nginx-vuln + custom images) |
| | Comparator | None public — Trivy/Snyk/Anchore self-published |

> **Implemented (wave A5).** trivy image + grype + dockle + **syft** (SBOM).
> trivy runs with base-layer skip (`--ignore-unfixed`) so app-fixable CVEs
> stand apart from the unfixable base-image baseline (strix Q5.42).

---

### `ip_address` — Network scan

| Layer | Element | Detail |
|---|---|---|
| **Anchor tier** | Port discovery | nmap, naabu |
| | HTTP probe | httpx, probe_http_port |
| | Service probes | probe_redis_no_auth, probe_ftp_anonymous, probe_smb |
| | Templates | nuclei (per-port tag-routed) |
| | TLS | tls_audit |
| **Registry tier** | (on-demand) | masscan (large-range scanning), rustscan, nessus-essentials (when licensed), openvas |
| **L1 filtration** | Closed/filtered port skip | Only open ports get probed (nmap filters) |
| | Per-port nuclei tag-filter | 22 → `ssh,openssh`; 443 → `https,tls,ssl,tech,default-login`; 3306 → `mysql`; 6379 → `redis`; 9200 → `elastic,elasticsearch`; 27017 → `mongodb` |
| | HTTP vs network URL form | `http(s)://host:port/` for HTTP ports; bare `host:port` for network templates |
| **L2 catalog** | Specialists | send_request, terminal_execute |
| **Bench** | Headline | `bench/ip_services` (vulnerable-services + Vulhub CVE recipes) |
| | Comparator | Tenable / Qualys / Rapid7 — no open scorecard |

> **Implemented (wave A1).** Recon→fan-out: `naabu` discovers open ports
> (the surface), `PlanFanout` runs deep `nmap -sV` on the discovered ports,
> `httpx` on HTTP-like ports, and `nuclei` **per-port with routed tags**
> (22→ssh, 443→ssl,tls, 3306→mysql, …; unknown→network) — strix's ~50×
> speedup (iter-Q5.43). Graceful fallback to nmap+httpx on the bare target
> when naabu is absent. Fixture: `fixtures/ip/services`.

---

### `domain` — Asset discovery + DNS hygiene

| Layer | Element | Detail |
|---|---|---|
| **Anchor tier** | Subdomain enum | subfinder, amass, assetfinder |
| | Cert transparency | crt.sh integration |
| | DNS hygiene | checkdmarc (SPF/DKIM/DMARC/CAA/MTA-STS) |
| | Typosquats | dnstwist |
| | Pipeline | domain_recon_pipeline (orchestrates the above) |
| | Web hygiene | nuclei against `http(s)://<domain>` |
| **Registry tier** | (on-demand) | findomain, censys-cli, shodan-cli (when licensed), bbot (full mode), securitytrails-cli |
| **L1 filtration** | Catch-all DNS skip | `*.x.com` resolving everywhere → suppress |
| | Child-asset pivot | Each active subdomain → spawn child `web_application` (if 80/443 open) or `ip_address` (otherwise) |
| **L2 catalog** | Specialists | send_request, terminal_execute |
| **Bench** | Headline | `bench/recon_breadth` (subdomain recall against known-target fixtures) |
| | Comparator | subfinder vs amass vs assetfinder published rates |

> **Implemented (wave A2).** Recon→fan-out: `subfinder`+`amass`+`crt.sh`
> enumerate (the union lifts recall; crt.sh is pure-Go, no binary),
> `PlanFanout` runs `checkdmarc` (DNS hygiene) + `nuclei` takeover templates
> + `httpx` over the surface. Discovered subdomains become
> `Scan.ChildAssets` (web/ip children) so webappsec spawns child scans
> rather than re-enumerating. Fixture: `fixtures/domain/recon`.

---

### `cloud_account` — Posture + compliance

The compliance team's primary asset. Without it, tsengine doesn't serve the compliance audience.

| Layer | Element | Detail |
|---|---|---|
| **Anchor tier** | Multi-cloud posture | prowler (AWS/GCP/Azure), scout-suite (AWS/GCP/Azure/AliCloud) |
| | AWS deep | cloudsploit, cs-suite |
| | Inventory | cloudquery (writes to SQL), steampipe (queries via SQL) |
| | IAM analysis | parliament (AWS IAM policy linting) |
| **Registry tier** | (on-demand) | pacu (offensive — gated by explicit scope opt-in), cloudmapper, smogcloud, principal-mapper |
| **L1 filtration** | Service scope | Customer-declared services/regions only — don't scan unused regions |
| | Read-only enforcement | Only read API calls; no `iam:Create*`, `ec2:Terminate*`, etc. — gate via IAM-policy linter on credentials provided |
| | Per-framework rule selection | If `scan.compliance_targets=["soc2","pci"]`, prowler runs SOC2+PCI rule packs only |
| **L1.5 enrichment** | Same chain as other assets | + extra: `compliance.map` is high-density at this asset (most findings ARE compliance findings) |
| **L2 catalog** | Specialists | terminal_execute, query_cloud_resource (steampipe query wrapper) |
| **Bench** | Headline | `bench/cloud_baseline` (mock AWS account with known misconfigs) |
| | Comparator | Prowler / scout-suite self-published; CIS AWS Foundations recall |

> **Implemented (wave A3).** Two posture engines — `prowler` + `scoutsuite`
> (different rule sets → corroboration, the cloud analog of trivy+grype).
> `cloudfox` is registry-tier, scope-gated read-only IAM attack-path
> enumeration (the privilege-escalation depth bar). Compliance mapping is
> honest by construction: a path maps to a framework only where a real control
> nexus exists across the 14-framework set (CLAUDE.md §8) — e.g. an
> internet-exposed sensitive-data path cites NIST 800-53 SC-7/SC-28 + GDPR
> Art. 32 + CCPA; unmapped frameworks are dropped, never mis-claimed.
> Fixture: `fixtures/cloud/baseline`.

**Authentication**: scan config carries `cloud.credentials` (assumed-role ARN or scoped read-only keys). Sandbox container receives credentials via short-lived env vars + scope-limited IAM session. Credentials never written to disk inside the container; rotated per-scan.

---

### `mobile_application` — Mobile app SAST + secrets + SCA

The mobile-app team's asset. Single-stage like `repository` (the app bundle / source tree *is* the surface — no recon → fan-out). The CLI bind-mounts the unpacked Android/iOS app (APK contents / source tree / IPA payload) read-only at `/workspace`; every tool scans that path. Its own asset (not a `repository` sub-mode) because the audience, tool set, and bench are mobile-specific.

| Layer | Element | Detail |
|---|---|---|
| **Anchor tier** | Mobile SAST | mobsfscan — Android/iOS insecure-storage, weak-crypto, exported-component, WebView, deep-link rules |
| | Secrets | gitleaks — hardcoded API keys / tokens (different engine → corroborates mobsfscan's secret rules); the #1 real-world mobile leak |
| | SCA | trivy fs — CVEs in bundled dependency manifests (`mode=fs`) |
| **Registry tier** | (on-demand) | semgrep (Kotlin/Swift/Java mobile packs), trufflehog (deep verified-secret scan); apkid (packer/obfuscator fingerprint) + a full MobSF dynamic pass are the documented next additions |
| **L1 filtration** | Bundle wholesale | anchors scan the mounted bundle; per-tool exclude wiring lives in the wrappers |
| **L1.5 enrichment** | Same chain as other assets | mobsfscan findings carry CWEs → `compliance.map` annotates controls like any SAST finding |
| **Bench** | Headline | `bench/mobile_app` (planted Android/iOS insecure patterns — next addition) |
| | Comparator | MobSF / NowSecure self-published; no neutral public leaderboard |

> **Implemented (assets Phase 3a).** New first-class asset type
> (`pkg/types.AssetMobileApplication`) + Handler (`internal/asset/mobile`).
> Anchors are mobsfscan + gitleaks + trivy — all already baked into the
> sandbox image (shared with `repository`), so mobile adds reach without a
> new sandbox tool. `mobsfscan` already existed as a `repository` escalation
> (mobile-file finding → mobsfscan); the mobile asset promotes it to an
> anchor and routes the whole scan around the mobile threat model. Grounded
> (no in-house detector — §13); the depth tools (apkid, MobSF dynamic) are a
> documented backlog item, never a silent in-house build.

**Note**: scanning a built binary (APK/IPA) requires decompilation first — today the asset expects an unpacked bundle / source tree at `/workspace`; an automatic `apktool`/`jadx` decompile prepass is the documented next addition.

---

## Anchor vs registry tier

Every asset has two tiers (CLAUDE.md §4):

| Tier | When it fires | Surface to |
|---|---|---|
| **Anchor** | Every scan, deterministically | Both L1 audiences (security + compliance) + L2 |
| **Registry** | On-demand via tool-replay API (§5) | Webappsec UI "investigate" button + L2 `dispatch_l2_probe(tool=...)` + explicit `scan.registry_opt_in=[...]` config |

Anchor tools are curated for: high recall, low FP, low cost, low destructive risk. Registry tools are everything else worth wrapping — noisier scanners, slower deep-exploits, niche tools, paid tools (when licensed).

A CI invariant (`tests/asset/anchor_tier_size_test.go`) caps the anchor count per asset (~12). Otherwise per-scan time explodes. Registry tier is unbounded.

---

## L1.5 hook chain

Every asset shares the same enrichment pipeline. Hooks fire in this order inside `tracer.Add`:

```
1. pre_emission_fp_filter          → drops planted-decoy shapes; surfaces in l15_audit_log
2. fp_filter.demote                → severity bumps per rule
3. surface_priority.annotate       → annotates surface_priority block
4. exploitability.annotate         → annotates exploitability block; may bump severity
5. corroborator_ledger.check       → cross-source agreement → attaches corroborated_by[]
6. threat_intel.enrich             → CVSS/KEV/EPSS/advisories for CVE-bearing findings
7. compliance.map                  → SOC2/PCI/HIPAA/CIS/NIST control annotation
8. post_emit_verifier              → re-fires via tool-replay to upgrade pattern_match → verified
9. cross_tool_merge                → cross-tool dedup
10. tracer.Append                  → persists to findings_enriched
```

**Ablation**: `TSENGINE_L15_DISABLED=1` skips the entire chain. The delta vs. the baseline at any asset's L1 bench is the L1.5 lift.

**Two output streams**: `findings_raw` captures the pre-hook state; `findings_enriched` captures post-hook. Both ship in `vulnerabilities.json` (§9).

---

## Sandbox → host findings propagation

Tools running inside the sandbox container that call `tracer.Add` from inside their body write to the sandbox-side tracer (which is hookless — L1.5 chain lives on host). The sidecar pattern bridges:

```
sandbox tool calls tracer.Add(finding)
   ↓ (writes to sandbox tracer singleton)
tool-server snapshots tracer diff post-call
   ↓ injects findings into ToolResult.SandboxEmittedFindings
[HTTP response]
host internal/sandbox.Client.Execute()
   ↓ extracts SandboxEmittedFindings
   ↓ host_tracer.Add(...)            ← L1.5 hooks fire HERE
```

The sidecar key is stripped from the returned `ToolResult` before callers see it.

The propagation is best-effort — any failure during re-emission is logged + swallowed; it never crashes the execute path.

---

## Tool-replay API

See CLAUDE.md §9 for the request/response spec. The architectural shape:

```
webappsec UI "investigate" button
   ↓ HTTP POST tsengine:/replay
internal/replay handler
   ↓ resolves scan_id → corpus pin + sandbox image digest
   ↓ spawns or reuses sandbox container (same digest)
   ↓ dispatches via internal/sandbox.Client → tool-server /execute
   ↓ findings flow through standard L1.5 chain
   ↓ appended to original scan's findings_raw + findings_enriched
   ↓ replay_id annotation on each new finding
```

L2 reaches the same API via `dispatch_l2_probe(tool=..., args=...)` — no separate codepath.

---

## Threat intel enrichment at L1

CLAUDE.md §7. Hook fires at step 6 of the L1.5 chain.

```
finding with cve_id="CVE-2024-1234"
   ↓ threat_intel.enrich
   ↓ lookups (24h cache, on-disk corpus):
      • CVSS v3.1 base score → from NVD JSON feed
      • KEV listing → from CISA KEV catalog
      • EPSS score → from FIRST.org daily CSV
      • vendor advisories → from per-vendor URL corpus
      • exploit availability → ExploitDB + Metasploit module DB + GitHub PoC search
   ↓ annotates finding.threat_intel {
        cvss, kev:{listed, date_added},
        epss:{score, percentile, as_of},
        advisories[], exploits[]
     }
```

The corpus version is pinned per scan (§8).

L2's `query_threat_intel` tool serves a different purpose — arbitrary CVE lookup during LLM reasoning. Both coexist.

---

## Compliance control mapping at L1

CLAUDE.md §8. Hook fires at step 7 of the L1.5 chain.

```
finding with cwe=["CWE-89"], rule_id="nuclei::sqli-error-based"
   ↓ compliance.map
   ↓ lookups (versioned YAML corpus):
      • soc2:   CWE-89 → ["CC6.1","CC6.6"]
      • pci:    CWE-89 → ["6.2.1","6.2.4"]
      • hipaa:  CWE-89 → ["164.312(a)(1)"]
      • cis_v8: CWE-89 → ["7.5","16.11"]
      • nist_csf: CWE-89 → ["PR.IP-12","DE.CM-8"]
   ↓ annotates finding.compliance { soc2:[...], pci:[...], ... }
```

The mapping corpus lives in `compliance_corpus/` and is versioned independently from threat intel.

---

## Reproducibility / attestation

CLAUDE.md §10. The architectural shape:

```
scan start
   ↓ resolve corpus versions (nuclei, semgrep, trivy, KEV, EPSS, compliance)
   ↓ resolve sandbox image digest
   ↓ write to scan_manifest.json {scan_id, corpus, sandbox_image_digest, started_at}

scan completion
   ↓ canonicalize findings JSON (sorted keys, no float drift)
   ↓ SHA-256 over canonical JSON + manifest
   ↓ sign with tsengine-prod-key (ed25519)
   ↓ write to vulnerabilities.json.attestation { sha256, signature, signer, signed_at }

re-run by scan_id
   ↓ load manifest, pin same corpus + image digest
   ↓ spawn sandbox from same digest
   ↓ replay anchor sequence
   ↓ compare findings — expect equality (within tolerance: timestamps, ordering)
```

A CI test in `tests/reproducibility/` pins this: any new tool or hook that introduces nondeterminism breaks the gate.

---

## L1 dashboard contract

See CLAUDE.md §6 for the full schema. The contract is **frozen in Phase 0** — every wrapper must conform.

Two views in one file:

* `findings_raw` — pre-L1.5 (security engineer audience)
* `findings_enriched` — post-L1.5 (compliance audience + L2 input)

Plus:

* `l15_audit_log` — every demotion, dismissal, merge with reason (security engineer can override in webappsec)
* `attestation` — cryptographic integrity for compliance evidence
* `corpus` + `sandbox_image_digest` — for replay / reproducibility

---

## Detection layer model (L0 → L3)

CLAUDE.md §5. Quick reference:

| Layer | What runs | Where | Refresh cadence |
|---|---|---|---|
| L0 | OSS signature corpora | Sandbox | Cron-paged + delta-verified |
| L1 | Anchor tools per asset | Sandbox | Per-scan |
| L1.5 | Host-side enrichment hooks | Host | Per-finding |
| L2 | LLM Lead — ≤12-tool catalog | Host drives sandbox | Per-scan, model-paced |
| L2.5 | Verifier (re-fire with benign-control payload) | Mixed | Per finding flagged |
| L3 | Portfolio-level | Host | Future |

---

## Host vs sandbox boundary

CLAUDE.md §12. Quick reference:

| Concern | Host | Sandbox |
|---|---|---|
| `cmd/tsengine` CLI | ✓ | |
| Orchestrator | ✓ | |
| L1.5 hook chain | ✓ | |
| Tool binaries (nuclei, sqlmap, prowler, etc.) | | ✓ |
| `cmd/tool-server` HTTP API | | ✓ |
| Findings store | ✓ (with hooks) | ✓ (hookless; sidecar) |

---

## L2 OODA loop (parked)

L2 is **not built** in Phase 0–5. Architecture is reserved per CLAUDE.md §2:

| OODA phase | Tools the LLM uses |
|---|---|
| **OBSERVE** | workflow_status, list_pending_findings, get_finding, get_recon_artifact |
| **ORIENT** | think (persisting), query_threat_intel, lookup_compliance_mapping |
| **DECIDE** | (inline in LLM response — no tool) |
| **ACT** | rescan, dispatch_l2_probe (kind ∈ {idor, auth_flow, business_logic} OR tool=`<registry tool>`), send_request, terminal_execute, create_vulnerability_report, finish_scan |

≤12 catalog per asset (Invariant L2-CAP). When L2 ships in Phase 6, the catalog above is the starting shape.

---

## Benchmark infrastructure

CLAUDE.md §14. Per-asset bench targets:

| Asset | Bench | External comparison |
|---|---|---|
| web_application | `bench/wavsep` | Acunetix 87%, Burp 78%, ZAP 56% |
| api | `bench/api_fixtures` | None public |
| repository (SAST) | `bench/owasp_benchmark` | Veracode 51%, Checkmarx 47% |
| repository (SCA) | `bench/sca_lockfiles` | Snyk self-published |
| container_image | `bench/container_cves` | None public |
| ip_address | `bench/ip_services` | None public |
| domain | `bench/recon_breadth` | subfinder/amass published |
| cloud_account | `bench/cloud_baseline` | None public; CIS recall |

---

## L2 design (Phase 6) — the AI security engineer

L2 is a **triage/translator**, not an autonomous exploiter. It reads L1's
complete findings and produces the developer/PM artifact (prioritize →
chain → verify → explain → remediate). It detects nothing, drives no recon,
runs no known escalations — open-ended reasoning only. `internal/l2/`.

**Architecture (L2-0, built):** single Lead, ReAct loop over a phase state
machine (triage→investigate→chain→report), hard ≤12-tool catalog, budget
caps + progress watchdog, render guard, OODA-shaped actionable rejections.
Provider-agnostic `Client` (Anthropic default).

**Locked per-asset catalog (≤12, ~10) — BUILT (L2-1..L2-4):**
```
advance_phase · get_finding · query_threat_intel · lookup_compliance_mapping ·
dispatch_l2_probe · send_request · record_hypothesis · create_vulnerability_report ·
update_finding · finish_scan
```
Assembled by `BuildCatalog(Deps)`; external tools (threat-intel / compliance
/ probe / send_request) are included only when their backing service is wired
(a partial `Deps` yields a valid smaller catalog). `Catalog.Validate()`
enforces the per-phase ≤12 cap, gated by a CI test on the full-width catalog.

**Real adapters (`internal/l2/adapters`, built).** The four external-service
interfaces are wired to production backings — and this is where the strix
divergence is concrete. Where strix exposes ~10 live-API threat-intel tools +
raw `terminal`/`python` for depth, tsengine collapses each into ONE tool
backed by existing, reproducible L1 infra:
- `ThreatIntelLookup` → the L1.5 `threat_intel` corpus (pinned per scan, §10 —
  NOT a live NVD/Perplexity call). Shared `hooks.ThreatIntel.Lookup`.
- `ComplianceLookup` → the L1.5 `compliance` corpus. Shared `hooks.Compliance.Lookup`.
- `Prober` → `internal/replay` (§9 "thin wrapper over /replay" — deterministic
  re-fire, NOT raw shell).
- `HTTPDoer` → a bounded host `net/http` client (scheme allow-list, timeout,
  capped body) — a *verification* primitive, not strix's Burp-style repeater.
`adapters.NewDeps(...)` assembles a fully-wired `l2.Deps`. Still pending: the
CLI/orchestrator step that calls it post-L1 + persists the L2 report to the
dashboard, and the live LLM generate path.
Depth comes from `dispatch_l2_probe` (re-fire a deterministic L1/registry
tool via /replay) — NOT raw shell/browser. No `think` (reasoning isn't a
tool, §2.7). `record_hypothesis` (durable plan, TodoWrite-style) is the one
addition over the dropped `think`: it persists to `State.Hypotheses` and is
re-surfaced in the compaction summary, so it's §2.7-legit and survives
compaction.

**Commit + verification model (L2-2/L2-4, built):**
- `create_vulnerability_report` is **eager-emit** (available in every phase,
  no gate) and **grounded at the tool boundary** — it must cite existing L1
  finding ids (the "never invent" rule enforced in code, not just the
  prompt). Reasoning rides as parameters (kill_chain, plain_english,
  remediation); the report lands on `types.Finding.L2` (`*L2Report`).
- Fresh reports emit at `pattern_match` strength. `update_finding` upgrades to
  `verified` only once independent methods confirm it — **HIGH/CRITICAL need
  ≥2 independent methods** (`verifyGate`), because a lone signature match is
  the false-positive class L2 exists to filter.
- **Auto-bypass:** after 3 rejections of the same phase-gated tool the loop
  advances the phase and runs the call — the hard backstop for strix's 36×
  finish_scan rejection loop.

**Context engineering (Claude Code-informed, L2-0 built):** four-tier
memory — hot (recent turns) / warm (compacted) / **crystal** (findings +
plan, durable, read on demand via tools, never re-derived from prose) /
cold (audit). Auto-compaction fires when the last turn's real context
(`Usage.InputTokens`) crosses `CompactAtFraction` of the model window; it's
**deterministic + templated** (a progress summary from State, no extra LLM
call) — cheaper + reproducible (§10) than an LLM summary, affordable
because crystal memory makes the narrative expendable. System prompt stays
fixed (cache prefix). This is what lets the Lead do proper analysis on a
1000-finding scan.

**L2 waves:** L2-1 read-state (`get_finding`) ✓ · L2-2 commit tools
(`create_vulnerability_report` / `update_finding` / `record_hypothesis`) + CI
cap test ✓ · L2-3 threat-intel/compliance + `dispatch_l2_probe` +
`send_request` ✓ · L2-4 verification (pattern_match→verified, ≥2 methods) +
auto-bypass ✓ · **L2-5 bench (detection_rate + completion_rate) — next.**

### Roadmap: autonomous-exploiter track (ADR-gated, not default)

A *separate* future track turns L2 into an XBOW/strix-XBEN-class **active
exploiter** (capture-the-flag, live chaining). It needs **exploit
primitives** — `terminal_execute`, `browser_action`, an HTTP repeater,
`submit_flag`, file I/O — which:
- break the ≤12 cap (strix needed ~25 even in orchestrator mode),
- add nondeterminism + arbitrary code-exec risk (needs a hardened,
  network-egress-scoped sandbox + an explicit safety model),
- are measured by **completion_rate** (flag captured?), a different metric
  from the translator's detection_rate.

This is **gated behind an ADR** (safety/sandbox model, cap exemption,
reproducibility fence) — never enabled by default, and reachable only as a
registry-tier capability, so the deterministic+reproducible translator L2
stays the product's spine.

---

## Repo layout

```
tsengine/
├── cmd/
│   ├── tsengine/         # CLI entry
│   └── tool-server/      # sandbox-side HTTP API
├── internal/
│   ├── asset/            # per-asset orchestration (7 modules)
│   ├── tool/             # OSS tool wrappers (one pkg per tool)
│   ├── orchestrator/     # anchor prepass + dispatch
│   ├── sandbox/          # docker runtime + HTTP client
│   ├── tracer/           # findings store + L1.5 hook chain
│   ├── dashboard/        # vulnerabilities.json renderer
│   ├── replay/           # tool-replay API handler
│   ├── l2/               # L2 Lead agent (Phase 6): ReAct loop, phases,
│   │                     #   ≤12 catalog, budget, compaction
│   └── bench/            # per-asset bench harnesses
├── pkg/
│   └── types/            # Finding, Asset, AssetType, MITRETechnique
├── compliance_corpus/    # versioned YAML mappings (SOC2/PCI/HIPAA/CIS/NIST)
├── threat_intel_corpus/  # versioned CVE/KEV/EPSS snapshots
├── fixtures/             # WAVSEP, OWASP Benchmark, VAmPI, vulhub
├── docker/
│   └── sandbox/          # Dockerfile baking OSS binaries
├── tests/
│   ├── integration/
│   ├── reproducibility/
│   └── asset/
└── docs/
    ├── arch.md           # this file
    └── CLAUDE.md         # canonical invariants
```

---

## Build phases

See CLAUDE.md §16 for the canonical table.

| Phase | Theme |
|---|---|
| 0 | Foundation + dashboard schema + reproducibility invariants |
| 1 | Sandbox + first tool E2E |
| 2 | web_application asset (anchor + registry, WAVSEP bench, tool-replay API) |
| 3 | Other 6 assets (api, repo, container, ip, domain, cloud_account) |
| 4 | L1.5 + threat intel + compliance mapping |
| 5 | Template refresh + attestation |
| 6 | L2 layer |

---

## The repeating pattern

The pattern across the asset matrix:

> **L1 = anchor OSS tools wrapping + per-asset filter + per-element routing + registry tier for dig-deeper → L1.5 enrichment (FP filter, surface_priority, exploitability, corroborator, threat_intel, compliance map) → L2 LLM orchestrates over a ≤12-tool catalog tied to OODA.**

The asset types differ in *what gets filtered* and *which audience the dashboard primarily serves*:

| Asset | Filter dimension | Primary audience |
|---|---|---|
| web_application | URLs | security |
| api | endpoints (method + path-shape) | security |
| repository | files (extension + tree position) | security + compliance |
| container_image | image layers | security + compliance |
| ip_address | open ports | security |
| domain | subdomains | security + compliance |
| cloud_account | services / regions | compliance |

The *shape* is identical across all 7 — applying the same `anchors → filter → normalize → enrich → map` pattern to each asset's specific surface.

---

## Where to look in code

| Path | Purpose |
|---|---|
| `internal/orchestrator/prepass.go` | L1 anchor dispatch. Reads `internal/asset/<asset>.Handler.Anchors()`, runs them concurrently, applies asset filter |
| `internal/asset/<asset>/` | Per-asset Handler: anchors, filter, normalize |
| `internal/tool/<tool>/` | Per-tool wrapper. `Tool` interface impl |
| `internal/tool/registry.go` | Global Tool registry — host view sees all tools, dispatcher reads `SandboxExecution()` |
| `cmd/tool-server/main.go` | Sandbox HTTP API |
| `internal/sandbox/runtime.go` | Container lifecycle |
| `internal/sandbox/client.go` | Host-side HTTP client → tool-server |
| `internal/tracer/tracer.go` | Findings store + L1.5 hook chain |
| `internal/tracer/hooks/` | Individual L1.5 hooks (fp_filter, surface_priority, exploitability, corroborator, threat_intel, compliance, post_emit_verifier, cross_tool_merge) |
| `internal/dashboard/render.go` | `vulnerabilities.json` renderer |
| `internal/replay/handler.go` | Tool-replay API |
| `internal/bench/<asset>/` | Per-asset bench harness |
| `compliance_corpus/` | Versioned YAML mappings (SOC2, PCI, HIPAA, CIS, NIST) |
| `threat_intel_corpus/` | Versioned CVE/KEV/EPSS snapshots |
| `CLAUDE.md` | Canonical architecture invariants (host/sandbox, ≤12-tool cap, tool-existence principle, reproducibility, build phases) |
