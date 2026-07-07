# CLAUDE.md â tsengine architecture invariants

This file is loaded into every Claude turn working on this repo.
**Read this before proposing architectural changes.**

When you change something architectural, **update this file in the same PR**
so future turns see the new layout.

---

## 1. Repository identity

`tsengine` is a Go-native two-layer security + compliance engine. The
design lineage is strix (Python, `ClatTribe/strix`) â strix's architecture
docs are the source for the principles below â but tsengine shares **no
code** with strix. Fresh build.

Paired with `webappsec` (the SaaS wrapper that consumes tsengine output,
persists findings, renders the dashboard, and exposes the tool-replay UI
to security engineers).

**Direct push to `main` is blocked â always ship via PR.**

---

## 2. The L1 / L2 layer model â read before any architectural change

tsengine has **two layers serving three audiences**:

### 2.1 L1 â complete OSS vuln discovery for security + compliance

- **Audience**: security engineers + compliance auditors (peers, not subordinate)
- **Artifact**: `vulnerabilities.json` (the dashboard contract â Â§6) + signed evidence bundle
- **"Best-in-class" means**: per-tool recall equals the standalone OSS tool. If we drop findings the OSS tool would have found, L1 has failed regardless of what L2 does next.
- **What runs here**:
  - All OSS scanners (anchor tier always-fire; registry tier on-demand â Â§4)
  - L1.5 enrichment hooks (FP filter, surface_priority, exploitability, corroborator)
  - Threat intel enrichment at finding emission (Â§7)
  - Compliance control mapping at finding emission (Â§8)

### 2.2 L2 â AI security and compliance engineer

- **Audience**: developers, PMs, non-security teams who can't triage raw scanner output
- **Artifact**: prioritized findings, chain narrative, remediation patches, plain-English explanations, compliance evidence packs
- **What runs here**: LLM Lead agent over a â¤12-tool catalog tied to OODA (Â§2.6)
- L2 **cannot translate findings L1 didn't surface.** L2 is the translator, not the detector.

### 2.3 The 2Ã2

| Layer | Audience | Artifact | Quality bar |
|---|---|---|---|
| L1 | security engineer | per-tool raw findings, MITRE-attributed | recall = standalone OSS tool |
| L1 | compliance auditor | findings + control mapping + reproducible evidence | every emission tied to a control; reproducible re-run |
| L2 | developer / PM | prioritized list, chains, patches, plain-English | actionable without consulting a security engineer |

### 2.4 What this means for every PR

* **L1 PRs** are scored on per-asset detection recall vs. the standalone OSS tool baseline. Token economy is not the gate.
* **L1 PRs that improve enrichment but regress raw recall are rejected.** The security engineer audience reads pre-L1.5 findings; if L1.5 drops them silently, that's a regression even if L2 looks better.
* **L2 PRs that improve translation but regress L1 recall are rejected.** Same reason.
* **L2 PRs that reduce token usage but regress L1 recall are rejected.**

### 2.5 What this means for the codebase shape

* No in-house detection scanners â Â§13 codifies this. The L1 layer **only** wraps OSS tools, because that's the only way to be "best-in-class" at detection.
* L1.5 hooks **add information for L2's translation job**, not mutate the L1 dashboard the security team sees. The L1 dashboard renders pre-L1.5 findings (`findings_raw`); L2's developer-facing output renders post-L1.5 findings (`findings_enriched`). Both ship.
* L1.5 demotions, dismissals, and merges must be **logged + recoverable** so the L1 audience can audit them. `l15_audit_log[]` in `vulnerabilities.json` is this audit log; webappsec exposes it to the security engineer for override.

### 2.6 The â¤12-tool cap (Invariant L2-CAP)

> For every asset type, the number of tools visible to the L2 Lead at any point in the scan is **â¤ 12**. Past ~12, LLM tool-use accuracy degrades steeply.

The cap counts **what the LLM sees in the system prompt** â the minimal CORE tools + the per-asset specialist set. It does NOT count:

* Tools that fire deterministically in the L1 prepass (the LLM never sees them â they're always-on coverage)
* Tools that auto-fire inside `finish_scan` (compliance evidence, remediation plan â terminal artifacts)
* Tools reachable via the registry tier â those reach the LLM only via `dispatch_l2_probe(tool=...)`, not as direct catalog slots

A CI invariant test gates any PR that raises any asset's catalog past the cap.

### 2.7 The tool-existence principle for L2

> Tools are the LLM's hands, not its brain.

L2 tools exist only when:

| Condition | Why a tool is needed |
|---|---|
| Real-time external data | LLM training cutoff is stale (CVE/EPSS/KEV state, vendor advisories) |
| Re-trigger a deterministic scan | LLM can't run subprocess / network I/O |
| Persistent side-effect | Committing a finding, advancing workflow phase, terminating scan |
| Reading state outside conversation context | `workflow_status`, `list_pending_findings` |

Reasoning over data already in context, reformatting, and decisions encoded inline in the response are **not** tools â those happen in the LLM's response text. Reasoning *commits* (chain narrative, customer priority) ride as parameters on `create_vulnerability_report`.

---

## 3. Asset types (8)

Every scan target maps to exactly one asset type. The asset type determines which anchor tools fire, which filter rules apply, and which competitor leaderboard the bench compares against.

| Asset | Description | Primary audience |
|---|---|---|
| `web_application` | Deployed HTTP/HTTPS app | security |
| `api` | REST / GraphQL / gRPC endpoint | security |
| `repository` | Source-code tree + lockfiles | security + compliance |
| `container_image` | Docker / OCI image | security + compliance |
| `ip_address` | IP / CIDR / range | security |
| `domain` | Domain + subdomains | security + compliance |
| `cloud_account` | AWS / GCP / Azure account | compliance |
| `mobile_application` | Android (APK / source) or iOS (IPA / source) app bundle | security |

The `cloud_account` asset is what makes tsengine usable for SOC2/PCI compliance teams. Without it, the engine only covers infrastructure surfaces. The `mobile_application` asset (single-stage, like `repository`: the bundle *is* the surface) covers the mobile-app-team audience competitors carve out as a separate offering â anchored on mobsfscan (mobile SAST) + gitleaks (hardcoded secrets) + trivy fs (bundled-dep SCA), plus a registry tier of semgrep (mobile packs) + trufflehog + **apkid** (packer/obfuscator/anti-analysis fingerprint â a tampering/repackaging signal mobsfscan's SAST misses; `internal/tool/apkid`). Count invariant: `pkg/types.AllAssetTypes()` + its test pin the count (now 8).

For the per-asset anchor + registry tool lists, filter rules, and bench targets, see [arch.md](arch.md).

---

## 4. The anchor + registry tier model

Every asset's L1 catalog has **two tiers**:

### 4.1 Anchor tier
Tools that fire **deterministically on every scan** of the asset. Always-on coverage; the LLM never has to choose. Curated for: high recall, low false-positive, low cost, low destructive risk. CI-capped at ~12 per asset.

### 4.2 Registry tier
Tools that are **wrapped and available on-demand** but don't fire by default. Surfaced via the **tool-replay API** (Â§9) when:

* The security engineer drills into a finding in webappsec and asks for deeper investigation
* The L2 LLM dispatches via `dispatch_l2_probe(tool=..., args=...)`
* A scan config explicitly opts in via `scan.registry_opt_in=[...]`

### 4.3 Why two tiers

* The security engineer needs to "dig deeper" after seeing an anchor finding â without restarting the scan
* The "complete OSS coverage" promise can't be delivered with anchors alone; some tools are too noisy / slow / overlapping to fire by default but valuable on-demand
* The L2 LLM gets a small catalog (â¤12) but can reach into the registry through one tool (`dispatch_l2_probe`) when it needs depth

Per-asset anchor + registry lists live in [arch.md](arch.md).

---

## 5. The detection layer model (L0 â L3)

| Layer | What runs | Where | Refresh cadence |
|---|---|---|---|
| **L0** | OSS signature corpora â nuclei templates, semgrep packs, sqlmap payloads, KEV list, EPSS scores, trivy DB, compliance control corpus | Sandbox | Cron-paged + delta-verified against L1 benches |
| **L1** | Deterministic anchor tools per asset (Â§3) | Sandbox | Per-scan |
| **L1.5** | Host-side enrichment hooks â FP filter, surface_priority, exploitability, corroborator, threat_intel.enrich, compliance.map, post_emit_verifier | Host | Per-finding |
| **L2** | LLM Lead â agent_loop with â¤12-tool catalog | Host drives sandbox tool calls | Per-scan, model-paced |
| **L2.5** | Verifier â re-fire L1 tool via tool-replay with benign-control payload to upgrade `pattern_match` â `verified` | Mixed | Per finding flagged for verification |
| **L3** | Portfolio-level (cross-scan dedup, multi-target correlation) | Host | Future |

### 5.1 The L1 recon â fan-out pipeline (deterministic, not LLM-driven)

Recon-capable assets run a **two-stage L1 flow** in the orchestrator â
discover the surface, then fan detection tools across it. Four assets are
reconâfan-out today: **web** (katana crawl), **ip_address** (naabu port
discovery â per-port nuclei routing), **domain** (subfinder+amass+crt.sh
enum â child-asset pivot), **api** (openapi_spec_ingest â per-method
routing). repository + container_image stay single-stage (the tree / image
is the whole surface). This is the L1 prepass, entirely deterministic; the
L2 LLM never drives it (strix's "model ignored the recon directive" class
of bug, Â§10, is structurally impossible here).

The contract â invariants, not implementation detail:

1. **Recon is a hard stage, not a prompt.** A `ReconHandler` exposes
   `Recon()`; if it returns tools they run first (`katana` crawls *in the
   sandbox*). `Result.DiscoveredURLs` â `CollectSurface` (dedupe,
   target-always-included, capped by `TSENGINE_FANOUT_MAX_URLS`=200). No
   recon tools â graceful fallback to single-target `PlanAnchors`.
2. **Fan-out shape is the tool's, not uniform.** `PlanFanout` decides:
   list-mode tools (`nuclei`, `httpx`) run **once** over the whole surface
   (`-list`); injection tools (`dalfox`, `sqlmap`) run **per-URL on
   param-bearing URLs only**. Running list-mode tools per-URL is the WAVSEP
   2h+ trap â don't.
3. **Surface filtration runs before fan-out.** Scope â static-asset drop â
   destructive-path drop â URL-shape dedup (`/items/1`â¡`/items/N`). The cap
   + filtration are the guard against strix's unbounded fan-out (Q5.34l).
4. **Dispatch is wave-ordered, never flat-parallel when state-coupled.**
   `partitionWaves` (`internal/orchestrator/deps.go`) topo-sorts by a static
   dependency table: concurrent within a wave, sequential across. An
   all-independent batch collapses to one wave (zero overhead). The
   classifier landed **before** any state-coupled tool existed, so strix's
   Q4.2 unguarded-parallel-auth race is impossible by construction. When you
   add a tool that reads another's side-effect, **add the edge to
   `toolDependencies`** â do not rely on dispatch order.
5. **Authenticated scan = a `seed_auth` tool in wave 0.** When `Asset.Auth`
   is set, `PlanFanout` prepends a `seed_auth` dispatch (passthrough cookie,
   or form-login â captured `Set-Cookie`). The authed detectors depend on it
   in the table â it runs first; `executeWaves` threads the captured session
   (`Result.CapturedSession` â crosses the sandbox boundary but is **never**
   written to `vulnerabilities.json`) into the detectors' `args["cookie"]`,
   never clobbering an explicit cookie. Auth failure â no session â
   unauthenticated scan (graceful, never crashes).
6. **Recon dispatch shape is the handler's (`ReconPlanner`).** A handler may
   implement `PlanRecon(target)` to shape its recon dispatches (crawl depth,
   spec URL, bare apex) instead of the generic single-arg mapping â e.g. web
   crawls at depth 3 (depth 2 can't reach a real app's surface), domain
   passes the bare apex, api passes the base URL. Mirrors `PlanFanout`.

### 5.2 Cross-asset invariants (the strix-mistake guardrails)

These hold for **every** asset, recon or single-stage:

1. **Loopback rewrite at the host/sandbox boundary (C2).** The sandbox
   client rewrites loopback hosts (`localhost`, `127.0.0.1`, `0.0.0.0`) in
   URL/host args (`target`/`targets`/`login_url`/`url`/`urls`) to
   `host.docker.internal`, and the runtime always adds `--add-host
   host.docker.internal:host-gateway`. Without this, network probes hit the
   sandbox itself â strix watched ip_address recall collapse 1.0â0.0.
2. **Single timeout source of truth + opt-in per-tool cap (C3).** The host
   scan `--timeout` (propagated via request-ctx cancellation into the
   sandbox) is the only deadline â there is **no** fixed host client
   timeout, so strix's "timeout split-brain" can't occur.
   `TSENGINE_TOOL_TIMEOUT` is an opt-in per-tool wall-clock cap so one
   runaway tool can't starve the scan.
3. **Tool arg contracts are validated (C4).** Each wrapper declares
   `tool.ArgSpec.KnownArgs`; a CI test (`internal/asset/argcontract`)
   asserts every key a Handler dispatches is recognized. A mis-wired arg is
   a **loud build failure**, not strix's silent "unexpected keyword
   argument" recall drop.
4. **Per-asset routing table.** "Run the whole corpus everywhere" is the
   universal perf/noise trap â solved per asset: web per-URL, api per-method
   (`classifyOp`), ip per-port nuclei tags (~50Ã speedup), container
   base-layer skip, domain child-triage. Add the routing dimension when you
   add an asset's fan-out.
5. **Child-asset pivot is a first-class artifact (C5).** A handler may
   implement `ChildAssetExtractor.ChildAssets(findings)` â `Scan.ChildAssets`
   (domain subdomains â web/ip child targets) so webappsec spawns child
   scans instead of re-enumerating (strix's re-enumeration trap).
6. **Wrap OSS; never build in-house detectors (Â§13).** strix rebuilt IaC,
   CSPM, SCA, and taint analysis in-house and reverted each to OSS. Every
   asset wave here wraps an OSS tool. Where no OSS exists (API BOLA/BFLA
   authz logic), it's a **documented ADR/backlog item**, never a silent
   in-house build.

### 5.3 The escalation stage â conditional depth (deterministic, L1)

After detection (anchors/fan-out), a handler may run a third stage:
inspect its own findings + surface and dispatch **deep** tools ONLY where a
signal warrants. This is "in-depth yet efficient" â expensive tools fire
targeted, never blanket.

The L1/L2 split is the load-bearing decision: this engine handles the
**known** signalâtool mappings *deterministically* (evidence-grounded, Â§10, zero
token cost). The open-ended "what's interesting here, what should I try"
reasoning stays **L2** (`dispatch_l2_probe`, Phase 6). Do not move
deterministic escalation into L2, and do not encode open-ended reasoning as
escalation triggers.

Invariants:

1. **Signal-gated, not blanket.** A handler implements
   `asset.EscalationPlanner.PlanEscalation(target, surface, findings)`. It
   uses a per-asset `Trigger` table (`MatchFinding`/`MatchSurface` â
   args) via `EvalTriggers`, which dedups by (tool, target+service+port).
   Depth tools never fire without a matching signal.
2. **Bounded.** The dispatch set is capped by `TSENGINE_ESCALATION_MAX`
   (default 50 â the cost twin of `TSENGINE_FANOUT_MAX_URLS`) and each tool
   by `TSENGINE_TOOL_TIMEOUT`. A signal flood can't turn "depth" into
   "unbounded".
3. **Provenance.** Escalated dispatches carry `Dispatch.EscalatedFrom` (the
   trigger name) for logging/audit. Detection + escalation findings are
   normalized together.
4. **Current trigger tables** (signal â depth tool):
   - web: param URL â nuclei DAST/OAST (blind, interactsh); login URL â
     nuclei default-logins; thin surface â ffuf content discovery;
     WordPress surface (wp-login/wp-content/xmlrpc) â wpscan (CMS-specialist
     DAST â vulnerable plugins/themes, user enum, exposed wp-config).
   - ip: open auth port (22/3306/â¦) â hydra default-cred check.
   - api: spec ingested â kiterunner (shadow routes); `/graphql` â inql.
   - repository: semgrep injection finding â CodeQL on that language
     (taint); mobile-file finding â mobsfscan.
   Breadth tools that are unconditional (dnstwist, cosign) are NOT
   escalation â they're fan-out/anchor.

---

## 6. The L1 dashboard contract â `vulnerabilities.json`

The webappsec handoff. **This schema is load-bearing â every wrapper written before it's locked accrues drift.** Define and freeze it in Phase 0.

```jsonc
{
  "scan_id": "uuid",
  "asset": {
    "type": "web_application",
    "target": "https://...",
    "scope": { "scope_hosts": [...], "out_of_scope": [...] }
  },
  "started_at": "2026-05-28T10:00:00Z",
  "completed_at": "2026-05-28T10:15:00Z",
  "engine": {
    "version": "tsengine 0.4.2",
    "sandbox_image_digest": "sha256:..."
  },
  "corpus": {
    "nuclei": "v9.8.2",
    "semgrep_packs": ["p/web 1.45.0", "p/owasp-top-10 1.2.0"],
    "trivy_db": "2026-05-27T12:00:00Z",
    "kev_snapshot": "2026-05-27T00:00:00Z",
    "epss_snapshot": "2026-05-28T00:00:00Z",
    "compliance_corpus": "soc2-1.4.0+pci-4.0.0+hipaa-2024+cis-v8+nist-csf-2.0"
  },
  "anchors_fired": ["katana","nuclei","sqlmap_runner","..."],
  "registry_fired": ["wapiti"],
  "findings_raw": [
    {
      "id": "f-001",
      "rule_id": "nuclei::sqli-error-based",
      "tool": "nuclei",
      "severity": "high",
      "cwe": ["CWE-89"],
      "endpoint": "https://.../search?q=",
      "title": "...",
      "description": "...",
      "raw_output": { /* tool's native output verbatim */ },
      "mitre_techniques": ["T1190"],
      "corpus_version": "v9.8.2",
      "tool_args": { "-t": "cves/", "-u": "..." },
      "discovered_at": "2026-05-28T10:03:12Z"
    }
  ],
  "findings_enriched": [
    /* same shape + L1.5 annotations: surface_priority, exploitability,
       corroborated_by, threat_intel, compliance, code_provenance */
  ],
  "l15_audit_log": [
    {
      "finding_id": "f-007",
      "action": "demote",
      "from_severity": "high",
      "to_severity": "info",
      "rule": "fp_filter::nuclei::generic-tech-fingerprint",
      "reason": "..."
    }
  ],
  "attestation": {
    "sha256": "...",
    "signed_at": "...",
    "signer": "tsengine-prod-key-v1",
    "signature": "..."
  }
}
```

**Two views, both shipped.** Security-engineer audience reads `findings_raw`; compliance auditor reads `findings_enriched` + `attestation`; L2 reads `findings_enriched`.

**Cloud-to-Code** (`internal/cloudtocode`, `tsengine cloud-to-code --in <cloud-scan> --iac <tf-dir>`): `code_provenance` traces a runtime cloud finding (prowler) back to the Terraform resource + `file:line` that provisioned it. A dependency-free `.tf` resource indexer + a grounded matcher â a link requires BOTH a serviceâTF-type nexus (the prowler check-id prefix â the TF types that provision it) AND a concrete shared identifier (physical name / ARN tail / normalized logical name). No matched token â no link (never guessed, Â§10). Correlation glue â adds provenance, never findings (Â§13 holds). Residual: platform-runner auto-wiring (annotate a cloud scan with the tenant's connected-repo IaC tree).

---

## 7. Threat intel enrichment at L1

CVE/KEV/EPSS lookup is **L1 work, not only L2**. Compliance teams need KEV listing immediately (SLA clock starts); security teams need EPSS for patch priority. Both consume the dashboard, not the LLM's translation.

Hook: `threat_intel.enrich` fires in the L1.5 hook chain (Â§11) for every finding with a CVE. Adds:

* CVSS v3.1 base score
* KEV listing (Y/N + `date_added`)
* EPSS score + percentile + `as_of` date
* Vendor advisory URLs
* Known exploit availability (Metasploit, ExploitDB, GitHub PoCs)

**Sourced from authoritative OSINT feeds, not hand-curated.** `tsengine corpus refresh` (`internal/corpus/threatintel`) ingests **CISA KEV** (the actively-exploited signal) + **FIRST.org EPSS** (~336k CVEs, the patch-priority signal) + **Exploit-DB** (`exploitdb.go` â the "a public exploit/PoC EXISTS" overlay, the patch-priority rung between EPSS probability and KEV in-the-wild; best-effort so a fetch failure never blocks the KEV+EPSS refresh) â all free, no API key â into a versioned on-disk corpus (`threat_intel.json` + sidecar manifest). A CVE's `Exploits[]` refs (`exploitdb:EDB-<id>`) ride the finding's `ThreatIntel` and surface as `pub-exploit` in the L2 digest (`L15Summary`). **CVSS base vectors** are an OPT-IN 4th source (`nvd.go` â NVD CVE API/bulk 2.0 â CVEâ`{baseScore, vectorString}`, preferring v3.1âv3.0âv2): only fetched when `RefreshOptions.NVDURL` is set (NVD is large + paginated â wired to a bulk mirror / pager, never defaulted to a single live-API page), best-effort like ExploitDB. It populates the corpus's long-empty `CVSS` base score AND a new `CVSSVector` (AV/AC/PR/UI/S/C/I/A); the vector rides `ThreatIntel.CVSSVector` and surfaces as `av:network` in `L15Summary` (the strongest reachability signal â network-attackable, no local access). The hook loads it when `TSENGINE_THREAT_INTEL_CORPUS` points at it, else falls back to the small embedded snapshot (the checked-in default). The corpus dir is gitignored; refresh runs **out of band** (the L0 cron, Â§5), and each scan **pins the manifest version** into `vulnerabilities.json`'s `corpus` block â so it's OSINT-fresh yet pinned for the evidence pack (Â§10), NOT a live per-query API call. Scope now KEV+EPSS+ExploitDB+CVSS-vectors (NVD); Metasploit/nuclei exploit-refs are the documented next source.

**This corpus is GLOBAL, not per-tenant** â it's world-state reference intel (the same KEV/EPSS for everyone), stored once and shared, never duplicated per tenant; per-tenant data (findings, OSINT exposure, incidents) stays tenant-isolated (Â§18.2 inv-2). The two join at finding emission: a tenant's private finding Ã the global corpus â KEV/EPSS-enriched severity + SLA, pinned for the evidence pack. **Continuous refresh is in-process**: `scheduler.CorpusRefresher` (the GLOBAL twin of `scheduler.Scheduler`'s per-tenant clock) refreshes the shared corpus on `TSENGINE_CORPUS_REFRESH_INTERVAL` (default 24h; 0 disables â rely on the external `tsengine corpus refresh` cron). Best-effort (a failed fetch keeps the last good corpus, never blocks scans), restart-aware (skips the boot fetch when the on-disk manifest is younger than the interval), and disabled unless `TSENGINE_THREAT_INTEL_CORPUS` points at a corpus file. The refreshed file is picked up by the next scan's `threat_intel.enrich` hook (re-read per scan). A future cross-tenant network-effect feed (one tenant's anonymized, consented IOCs warning another) is deliberately gated on isolation + consent â never default.

L2 retains a separate `query_threat_intel` tool for the LLM to look up CVEs that aren't in current findings (chain reasoning across related CVEs). The two are complementary: L1.5 hook annotates emitted findings; L2 tool serves on-demand lookups during reasoning.

---

## 8. Compliance control mapping at L1

Every finding emitted at L1 carries a compliance annotation. Mapping is **annotation, not gate** â L1 emits the technical finding regardless of whether it maps to a control; the mapping just records which controls it affects.

Frameworks supported (22 â keys defined once in `grc.Frameworks`, mirrored by `pkg/types.Compliance`, the `compliance.json` crosswalk, `internal/tracer/hooks/compliance.go`'s `controlSet`, and `frontend/lib/frameworks.ts`; the `grc.frameworks_e2e_test.go` mirror-consistency + all-frameworks-end-to-end tests gate any drift):

* **Security & trust**: SOC 2 (Trust Services Criteria), CIS Controls v8, NIST CSF 2.0, ISO 27001:2022, ISO 22301:2019 (BCMS)
* **Sector & payments**: PCI-DSS v4.0, HIPAA Security Rule, SOX (IT general controls), GLBA Safeguards Rule
* **Privacy**: EU GDPR, ISO 27701:2019, CCPA/CPRA, India DPDP Act 2023, ISO 27018:2019 (cloud PII), PIPEDA (Canada)
* **Government**: NIST SP 800-53 r5, NIST SP 800-171 r2, FedRAMP Moderate, CMMC 2.0 (Level 2, 800-171-derived)
* **AI governance**: ISO 42001:2023, NIST AI RMF 1.0, EU AI Act (mapped only to the security-relevant AI controls â access, data governance, AI-system lifecycle security; most AI-governance + BCMS controls are procedural â attestation, surfaced honestly by the coverage layer)

Competitor parity (Sprinto/Vanta/Drata): the 22 named frameworks close the bulk of the gap; the remaining tail (CSA STAR, TISAX, C5, FFIEC, FERPA, regional regs) is best served by a custom/"bring-your-own-framework" capability (how Sprinto reaches 200+) â the documented next step, not more hard-coded entries.

A finding maps to a framework **only where the crosswalk has a real control nexus** (grounding Â§10) â e.g. an injection CWE cites NIST SI-10 and GDPR Art. 32; a data-exposure CWE additionally cites CCPA Â§1798.150 and SOX access-controls; a memory-safety CWE does not. Adding a framework is one entry in each of the four mirrors above; adding a control mapping is one key in `compliance.json`.

Hook: `compliance.map` fires in the L1.5 hook chain. Sourced from `compliance_corpus/` (versioned YAML), refreshed on cron. Same per-scan pinning as threat intel.

**Provenance of the CWEâcontrol crosswalk (`internal/tracer/hooks/data/compliance.json`, embedded):** unlike the threat-intel corpus (KEV/EPSS/ExploitDB/NVD â OSS feeds, Â§7), the crosswalk is **in-house hand-curated** reference data, synthesized from the published framework standards. That's architecturally fine â Â§13's wrap-OSS rule governs *detection*, and this is *annotation* (Â§8), whose discipline is grounding (Â§10: maps only where a real control nexus exists), not OSS-wrapping. There is no single authoritative OSS crosswalk for our 22 frameworks (the SaaS leaders keep theirs closed). What we DO have is an **auditable OSS cross-reference, on two axes**: (1) **controlâframework** â `internal/corpus/controlxref` cross-checks the crosswalk against the **Secure Controls Framework (SCF)** + **CSA Cloud Controls Matrix (CCM)**, the authoritative open control-cross-mapping catalogs that DO cover SOC2/HIPAA/GDPR/CCPA (the gap OpenCRE has). Both ship as a matrix export (row=meta-control, columns=frameworks, cells=that framework's control IDs); `controlxref.Parse` reads either via header-substring matching (per-source `Source` config) and `CrossReference` reports, per framework, how many of OUR control IDs the catalog corroborates (Â§10: a control counts only if the catalog actually lists it; the rest is reported missing, never assumed). The export FILE is operator-provided out-of-band (SCF is CC BY-ND, CCM free; no clean API) â the parser + cross-check are pure/tested. (2) **CWEâstandard** â `internal/corpus/opencre` cross-checks against **OpenCRE** (OWASP); OpenCRE maps a CWE â CRE *nodes* but doesn't cover SOC2/HIPAA/GDPR, so it's the secondary CWE-engineering-link axis (live keyless API). `tsengine corpus compliance-provenance [--scf <file>] [--ccm <file>] [--no-opencre] [--json]` runs all three and reports the OSS-corroborated vs in-house-only split per source (in-house-only = no nexus / a format difference, honest, not a defect). **MITRE ATT&CK is a different axis** (attacker techniques â on every finding's `mitre_techniques`), not a control crosswalk; **UCF** is best-in-class but commercial/non-redistributable â not embeddable. **OSCAL output is built**: `internal/grc/oscal.go` `OSCALComponentDefinition` emits the crosswalk's per-framework control coverage as a NIST OSCAL 1.1 component-definition (the format FedRAMP runs on â GRC-tool-/auditor-ingestible), deterministic (content-derived UUIDs â diffable) + self-contained; served at `GET /v1/compliance/oscal` (downloadable JSON) via `grc.GRC.OSCAL` over the `ControlUniverse`. Per-tenant findings-as-evidence (OSCAL Assessment-Results) is the documented next OSCAL artifact.

Example annotation:

```json
"compliance": {
  "soc2": ["CC6.1","CC6.6"],
  "pci": ["6.2.1","6.2.4"],
  "hipaa": ["164.312(a)(1)"],
  "cis_v8": ["7.5","16.11"],
  "nist_csf": ["PR.IP-12","DE.CM-8"]
}
```

No L1 tool **decides** whether something violates SOC2. The tool emits the technical finding; the mapping layer annotates.

**Five emission paths feed the framework set** (all grounded, all annotation-only) â keep them in sync when adding a framework or control:

1. **CWE crosswalk** â `internal/tracer/hooks/data/compliance.json` (the `compliance.map` hook) maps a finding's CWE â controls. Covers appsec/SAST/SCA findings.
2. **Identity findings** â `internal/operate/operate.go` annotates each check inline (MFA gaps, OAuth grants, email-auth, stale/over-privileged accounts, incomplete-offboarding: a *suspended* account that still holds an admin/super-admin role binding — standing privilege that survived the disable, the deprovisioning-completeness blind spot the active-account checks skip) â the non-tech / IdP posture.
3. **Cloud attack-paths** â `internal/cloudengine/compliance.go` (`pathCompliance`) maps an attack-path's characteristics (internet exposure, sensitive-data access, privilege/privesc, lateral movement) â controls.
4. **SaaS posture (SSPM)** â `internal/sspm` annotates each SaaS-config check inline (GitHub org: 2FA enforcement, repo perms, secret scanning, third-party apps, webhooks; Slack: 2FA/SSO, app governance, public sharing, guests, admin sprawl; Zoom: meeting passcode/waiting-room, recording protection; Atlassian: public Confluence spaces, SSO-bypassing API tokens; Salesforce: Experience-Cloud guest access, Modify-All-Data sprawl; **M365 (`m365.go`): the COLLABORATION/DATA-SHARING half â SharePoint/OneDrive anonymous & external sharing, Teams guest access + open federation, legacy(basic)-auth, mailbox-audit-disabled, anonymous calendar â DISTINCT from the M365 IDENTITY posture `operate` already does (MFA/OAuth/stale), closing the "we did M365's identity but not its SharePoint/Teams data-sharing" SSPM gap; M365 + Google Workspace are the two most-common SaaS estates; **Google Workspace (`gworkspace.go`): Drive public/external sharing, link-sharing default, less-secure-apps, third-party API access, Gmail external auto-forward, external calendar â the sibling data-sharing posture to M365**) â the SaaS-configuration posture, sibling to `operate`. Snapshot-driven, LLM-free, grounded (a hardened app yields zero findings). See ADR 0004. **Live driver: `POST /v1/saas/{provider}/snapshot`** (`internal/platformapi/saasposture.go`, provider ∈ github_org|slack|zoom|atlassian|salesforce|m365|google_workspace) decodes the provider snapshot, runs the matching `Assess*`, and stores the findings into the same store the rest of the platform reads â so SaaS misconfigs flow through issues/incidents/grc/hitl like any finding (mirrors the identity-events ingest). The admin-API fetcher (snapshot from the provider's API) is the credential-gated half; the posted-snapshot path works today with no external creds. **GitHub org now has a LIVE fetcher: `POST /v1/saas/github_org/sync`** (`internal/platformapi/saassync.go` + `sspm.FetchGitHubOrg`) builds the snapshot from the GitHub API reusing the already-onboarded GitHub connection's token (no new credential) â reads what `read:org` covers (org-wide 2FA, default repo permission, public-repo creation, GHAS secret-scanning default, org webhooks best-effort), runs the same `AssessGitHubOrg`, stores findings. Per-member 2FA / installed-app inventory / outside-collaborators need `admin:org` + heavy pagination, so those checks stay the posted-snapshot path's job (honestly gated, never invented â Â§10). Surfaced via the Settings "Sync posture" button on the GitHub connection.

5. **OSINT external exposure** â `internal/osint` annotates each open-source-intelligence finding inline (**stealer-log dark-web exposure** â a corporate credential harvested by infostealer malware, critical w/ plaintext password â GDPR Art. 33/34 + SOC2/PCI, the highest-severity OSINT signal; breached credentials â GDPR Art. 33/34 + SOC2/PCI; leaked secrets; internet-exposed hosts â SOC2 CC6.6/CC7.1 + CIS; data exposure â GDPR/CCPA; typosquats; subdomain takeover (a dangling DNS record pointing at a deprovisioned/unclaimed service — the canonical EASM finding; high, SOC2 CC6.1/6.6/7.1 + GDPR Art. 32 + NIST CM-8/SC-7); certificate posture from CT-log monitoring (unexpected-issuer cert = mis-issuance/phishing prep, + expired/expiring served certs); advisories). The attacker's-eye external footprint, snapshot-driven, LLM-free, grounded (a clean footprint yields zero findings). **Live driver: `POST /v1/osint/ingest`** (`internal/platformapi/osint.go`) decodes an OSINT snapshot (normalized from theHarvester/SpiderFoot/dnstwist/HIBP/taranis-ai), runs `osint.Assess`, and stores findings into the same store â so external exposure flows through issues/attack-paths/grc/hitl like any finding. `GET /v1/osint` + the `/osint` "External exposure" page. The live collectors (sandbox tools + HIBP/Shodan APIs) are the credential-gated half; the posted-snapshot path works today with no creds. See ADR 0011.

So a connected repo, Workspace/M365/Okta, cloud account, SaaS app (GitHub org), *or* an OSINT snapshot each contribute evidence to the full 14-framework set, not just the original six. A control maps only where a real nexus exists for that path (grounding Â§10).

---

## 9. The tool-replay API

The "dig deeper" capability webappsec exposes to security engineers. POSTs to the running tsengine instance:

```
POST /replay
{
  "scan_id": "uuid",         // the scan to extend
  "tool": "sqlmap_runner",   // anchor OR registry tool
  "target": "...",           // can override the scan target
  "args": { /* tool-specific custom args */ },
  "use_corpus_from": "scan_id"   // optional: re-use pinned corpus for reproducibility
}
â { "replay_id": "uuid", "findings": [...] }
```

Replay output appends to the original scan's `findings_raw` + `findings_enriched` with `discovery_method.replay_of: <replay_id>`. Audit-trail preserved.

Required for two use cases:

1. Security engineer in webappsec UI clicks "investigate" on a finding â invokes nuclei with custom template, sqlmap with `--tamper=...`, etc.
2. L2 LLM calls `dispatch_l2_probe(tool=..., args=...)` â routes through the same handler

The L2 path doesn't get a separate codepath â `dispatch_l2_probe` is a thin wrapper over `/replay`.

---

## 10. Evidence grounding (the LLM determines issues; tools back every claim)

> **Process-reproducibility is NOT an invariant here â it was removed.** The old
> "reproducibility invariant" (deterministic tool args, N=5 output equality, "any
> nondeterminism breaks the gate") pushed the engine toward a fixed deterministic
> spine with the LLM bolted on as a translator. That is the wrong shape. The AI
> security engineer is an **LLM agent that uses deterministic tools to access and
> assess resources and determine issues** (the VulnAgent model). The *reasoning* â
> which resources matter, how they chain, the blast radius, what to fix â is the
> LLM's job and is allowed to be non-deterministic.

What we require instead is **evidence grounding** â the LLM never asserts a fact it
could have *queried*, and never records an issue no tool supports:

| Rule | Mechanism |
|---|---|
| Every recorded issue cites tool evidence | A finding references the `resolve_access` / `find_paths` / prowler result that backs it. The LLM cannot record a vulnerability no tool supports â the anti-hallucination guard (VulnAgent's "no LLM hallucinations in syntax checking"). |
| Effective-permission claims come from the evaluator, never the model | "Can X do Y on Z?" is answered by a per-cloud evaluator, not the LLM's recollection: `cloudiam.Authorize` (AWS: identity â§ boundary â§ SCP â§ resource-policy â§ conditions), `gcpiam.Authorize` (GCP: hierarchy-inherited bindings â§ roleâperms â§ IAM-deny â§ conditions), `azureiam.Authorize` (Azure: hierarchy-inherited role-assignments â§ role-def Actions/NotActions â§ deny-assignments â§ ABAC). All three feed `cloudgraph.PruneUnauthorized`, which drops an over-approximated edge ONLY on a DEFINITIVE deny â AWS assume-role via the target's `trust_policy`, GCP SA-impersonation via `gcp_iam_policy`, Azure escalate via `azure_rbac_policy` â and KEEPS the edge on any missing/uncertain data (an unresolved condition / group / unknown custom role â conditional). So multi-cloud attack-path reasoning is now symmetric across AWS+GCP+Azure; the live per-cloud policy data is the sandbox-side ingest source's job to emit (the honest gate). Privesc-EDGE generation is also symmetric: `cloudiam.Techniques` (AWS, 21 Rhino/PMapper methods) + `gcpiam.Techniques` (GCP, the Rhino "Privilege Escalation in GCP" set — setIamPolicy, SA-key/token mint, actAs-deploy, Cloud Build, custom-role update) + `azureiam.Techniques` (Azure ARM, the RBAC privesc set — roleAssignments/write, elevateAccess, roleDefinitions/write, VM run-command/extension as managed-identity, automation runbook, Function/Web app as MI, Key Vault access-policy) each feed `DetectPrivesc` â a `privesc â admin` edge via `cloudgraph.AddPrivescEdges` (AWS) / `AddGCPPrivescEdges` (GCP) / `AddAzurePrivescEdges` (Azure). So privesc-edge generation is symmetric across all three clouds. The ingest builds the per-principal `can` predicate from the snapshot's IAM bindings (the honest gate, same as the Authorize side). The Azure AD/**Entra graph-plane** privesc catalog is now BUILT too (`azureiam.EntraTechniques` + `DetectEntraPrivesc`, `entra_privesc.go`): a DISTINCT authorization plane from ARM (§10 — never conflated), over Microsoft Graph application permissions + privileged directory roles (RoleManagement.ReadWrite.Directory → self-assign Global Admin; Application.ReadWrite.All / Application Administrator → add a secret to any privileged app; AppRoleAssignment.ReadWrite.All; GroupMember.ReadWrite.All; Privileged Authentication/Role Admin). `cloudgraph.AddAzureEntraPrivescEdges` adds an `Entra:`-labeled `privesc → admin` edge, so an attacker who owns the tenant via Entra (never touching an ARM role assignment) is no longer invisible. Same honest gate: the ingest builds the `can` predicate from the Entra snapshot's app-role assignments + directory-role memberships (`azureiam.EntraCanFromGrants`). The RELATIONSHIP half is BUILT too: `cloudgraph.AddEntraOwnershipEdges` — owning a PRIVILEGED service principal (or one that can itself escalate) lets you add a credential and act AS it, so the owner gets an `Entra:OwnerOfPrivilegedSP` `privesc → admin` edge (the canonical BloodHound "Owns → AZServicePrincipal" attack path). Grounded §10: an edge is added only when the owned node is really privileged (its `Node.Privileged` flag OR an existing privesc→admin edge — run it after `AddAzureEntraPrivescEdges` to inherit permission-escalating SPs); owning a non-privileged SP adds nothing. The ingest supplies the app/SP `owners` map (the honest gate). |
| Network reachability is evaluated, not assumed (REACHABILITY PRECISION) | "Is this actually reachable from the internet?" is answered by `cloudgraph` (`reachability.go`) from the resource's OWN security-group ingress rules, not from "it has a public IP". `InternetReachable(rules, port, proto)` tests whether a rule opens the service port to `0.0.0.0/0` (CIDR COVERAGE, not overlap — a corp-CIDR rule is NOT internet-open). `Snapshot.PruneUnreachable()` (the network twin of `PruneUnauthorized`, run right after it in `engine.go`) drops an `internet → resource` `network_reach` edge ONLY when the dst node's `Attrs["sg_ingress"]`(JSON `[]SGRule`)+`["service_port"]` DEFINITIVELY prove the SG blocks the internet to that port — so a path leads with *actually-reachable* exposure, separating theoretical from real (the agentic-cloud-security table-stakes signal). Absent/unparseable rule data → edge KEPT (never prunes a genuinely-reachable path; recall preserved). The live SG-rule ingest is the honest gated half. |
| Proposed fixes are verified before delivery | A remediation is re-checked through `cloudiam.Authorize` (does it cut the path?) and, for IaC, compiled (`terraform plan`) before a PR/ticket opens. |
| Mutations are human-gated (HITL) | The agent opens a PR/ticket and pauses for a human approval; its own cloud access stays read-only (`cloudsafety.Guard` + scoped STS). |
| Pinned context for the evidence pack | The inventory `snapshot_hash`, `corpus.*`, and `sandbox_image_digest` are recorded so an auditor can see exactly what state a finding was assessed against, and re-run the finding's evidence predicate against it. |
| Signed attestation | `attestation` block (SHA-256 of canonical JSON + ed25519) covers `snapshot_hash + findings + evidence`. Tamper-evident â it attests the *evidence*, never "the process was deterministic." |

So the compliance value (auditable, signed, pinned-context evidence) is kept; the
process-determinism mandate is gone. The deterministic components (`cloudiam`,
`cloudgraph`, the attack-path enumerator) are **tools the agent calls**, not the
agent itself.

---

## 11. The L1.5 hook chain â order matters

When the host tracer's `Add(finding)` is called, hooks fire in this order. Each can mutate or drop the finding:

```
1. pre_emission_fp_filter      â drops planted-decoy shapes, surfaces in l15_audit_log
1b. service_eol                â flags an nmap-detected service whose version is below a curated minimum-safe version (OpenSSH/Apache/nginx/OpenSSL/Exim/â¦); bumps infoâmedium + annotates upgrade guidance. Grounded: acts only on a real nmap product+version it can match + parse; runs early so the bump reaches surface_priority/exploitability/compliance
2. fp_filter.demote            â bumps severity per rule
3. surface_priority.annotate   â annotates surface_priority block
4. exploitability.annotate     â annotates exploitability block + may bump severity
5. corroborator_ledger.check   â cross-source agreement â attaches corroborated_by[]
6. threat_intel.enrich         â CVSS(+vector)/KEV/EPSS/advisories for CVE-bearing findings (Â§7). Annotation-only by default; opt-in KEV-driven severity escalation (TSENGINE_KEV_ESCALATE â a sub-high finding whose CVE is on CISA KEV is bumped to high per BOD 22-01, logged as a promote; grounded â acts only on a real KEV listing, never downgrades)
7. compliance.map              â SOC2/PCI/HIPAA/CIS/NIST control annotation (Â§8)
8. post_emit_verifier          â re-fires via tool-replay to upgrade pattern_match â verified (inert until L2.5)
9. cross_tool_merge            â cross-tool dedup
10. confidence                 â sets verification_status (pattern_match â corroborated when â¥1 independent tool agrees) + a 0â1 confidence scalar (per-tool base bumped by corroboration). Runs last so it sees the merged set (Â§7-style quality signal, strix parity)
11. tracer.Append              â persists to findings_enriched
```

`findings_raw` is captured **before** hook 1 â that's what the security engineer reads. `findings_enriched` is the post-hook view. Both ship.

**The chain runs on BOTH doors, not just the engine.** Engine-scanned findings (repo/container/web/
cloud/etc.) reach the host tracer via the sandbox sidecar (Sec 12.4), so the hooks fire on them by
construction. Findings that enter through the platform's OWN ingest paths -- identity events, OSINT
snapshots, SaaS posture, TPRM, device posture, cloud drift (config + CDR), TLS scan -- used to call
`Store.PutFinding` directly and land UN-enriched (no threat-intel, no exploitability, no confidence;
any CVE they carried never got KEV/EPSS). `platformapi.enrichFindings` (`internal/platformapi/enrich.go`)
closes that asymmetry: each ingest handler runs the batch through a host-side `tracer.New(DefaultPerFinding,
DefaultFinalize)` before storing, so a finding is enriched the same way no matter which door it came in.
Safe for posture/config classes: the `compliance.map` hook MERGES (never clobbers) the inline mapping
each detector already set, and threat_intel/service_eol/exploitability no-op without a CVE/product/
critical-CWE -- so a config finding keeps its inline compliance and gains corroboration+confidence, while
a CVE-bearing one also gains KEV/EPSS. Honors `TSENGINE_L15_DISABLED`. (Not yet wired: `cloudinvestigate.go`,
which builds a finding per L2 Issue inline -- the documented follow-on.)

If you add a new hook, **append it to this list in CLAUDE.md** so the order stays documented.

---

## 12. The host vs sandbox boundary â CRITICAL

**The part to get right from day 0.**

### 12.1 Two execution contexts

* **Host process** â `cmd/tsengine` Go binary. Orchestrates. Has no security tool binaries (by design).
* **Sandbox container** â `tsengine/sandbox:<digest>` Docker image. Has every OSS tool baked in. Runs `cmd/tool-server` as PID 1 exposing HTTP on a per-scan port.

### 12.2 The execution adapter

| File | Role |
|---|---|
| `internal/sandbox/client.go` | Host-side HTTP client â tool-server. Bearer-token auth from sandbox spawn |
| `cmd/tool-server/main.go` | Sandbox-side HTTP API. Receives POST `/execute`, dispatches to registered tool |
| `internal/tool/registry.go` | Global `Tool` registry (one per OSS tool wrapper). Each `Tool` declares `SandboxExecution() bool` |
| `internal/sandbox/runtime.go` | Container lifecycle. `Spawn(image, scan_id)` returns `SandboxInfo{port, token, digest}` |

### 12.3 The `Tool` interface â sandbox flag

```go
type Tool interface {
    Name() string
    SandboxExecution() bool   // false only for framework state mgmt (workflow, tracer, finish_scan)
    MITRETechniques() []string
    Run(ctx context.Context, args ToolArgs) (ToolResult, error)
}
```

Default for any new tool is `SandboxExecution() = true`. Opt-out only for host-only framework tools.

When the host calls `dispatcher.Dispatch(ctx, "nuclei", args)`:

1. Dispatcher reads tool's `SandboxExecution()`
2. If true â POST `/execute` to sandbox tool-server
3. Tool-server resolves the tool from its local registry, calls `Run`
4. The actual subprocess (or library call) fires **in the sandbox container**
5. Result returned via HTTP

### 12.4 Findings sidecar â sandbox tool â host tracer

Tools that call `tracer.Add(finding)` from inside their body would write to the **sandbox-side tracer** (hookless â L1.5 chain lives on host). The sidecar bridges:

```
sandbox tool calls tracer.Add(finding)
   â (writes to sandbox tracer)
tool-server snapshots tracer diff post-call
   â injects findings into ToolResult.SandboxEmittedFindings
[HTTP response]
host internal/sandbox.Client.Execute()
   â extracts SandboxEmittedFindings
   â host_tracer.Add(...)            â L1.5 hooks fire HERE
```

The sidecar key is stripped from the returned `ToolResult` before callers see it.

The propagation is best-effort â any failure during re-emission is logged + swallowed; it never crashes the execute path.

### 12.5 What's where

| Concern | Host | Sandbox |
|---|---|---|
| `cmd/tsengine` CLI | â | |
| Orchestrator (`internal/orchestrator`) | â | |
| L1.5 hook chain | â | |
| `internal/tool/registry` | â (host view: dispatch decisions) | â (sandbox view: executes tools) |
| OSS tool binaries (nuclei, sqlmap, semgrep, trivy, prowler, ...) | | â |
| HTTP client to tool-server | â | |
| `cmd/tool-server` HTTP API | | â |
| Findings store (host_tracer) | â (with hooks) | â (hookless; sidecar-shipped to host) |
| Workflow state singleton | â | (separate sandbox-side; not propagated) |

### 12.6 L2 offensive agents execute host-side (NOT via the sandbox)

The host/sandbox split above governs **L1 tool dispatch** -- the `Tool` interface,
`SandboxExecution()`, and the tool-server. The **L2 offensive agents run on the HOST and own
their own network I/O**, a separate execution model:

* `internal/webagent` (the `web-investigate` CLI -- the flag-pursuing web/API pentester, the XBOW
  driver) makes live HTTP straight from the host via its own `Requester` (`http.Client`); it does
  NOT go through `internal/sandbox` or the tool-server.
* `internal/cloudengine`'s cloud agent is the same shape.

Consequence for adding agent capabilities: an L2 agent TOOL (e.g. a headless browser via chromedp,
an OOB/interaction collector, **`ssh_exec` -- credential-based SSH lateral movement via
`golang.org/x/crypto/ssh`, `internal/webagent/ssh.go`**) is **host-side Go with a host-side dependency
-- it needs NO sandbox image rebuild** (that slow step is only for the sandboxed L1 OSS tools). The
agent is host-allowlist-scoped for safety (its `Requester`), not sandbox-isolated. Do not assume "new
agent capability => sandbox rebuild" -- check which layer owns the execution first.

`ssh_exec` is the EXPLOIT step for a leaked-credential finding: the agent discovers SSH creds over
HTTP (a source disclosure / config dump), but the flag/next hop lives behind SSH not HTTP -- so
`ssh_exec(user, password?|private_key?, command, host?, port?)` connects with the discovered creds
and runs ONE command, returning its real output (grounded, §10). Scope-guarded at HOST granularity
(`Requester.HostInScope` -- SSH:22 is a different port from the web app but the same authorized box)
so it can never touch a host the LLM invents; bounded (dial+handshake timeout, 12KB output cap). This
is the class-level fix that turns "I found creds" into a proven lateral-movement capture (XBEN-042).

`bola_probe` (`internal/webagent/bola.go`) is the same host-side shape for the ONE web-vuln class no
OSS scanner grounds -- broken object-level authorization (IDOR/BOLA), which is business logic. It is
the `apiauthz.Evaluate` model as an agent tool: `bola_probe(url, attacker_cookie, victim_cookie,
marker)` runs the victim's object through THREE isolated `Requester`s (a new `Requester.AllowHosts()`
keeps them same-scope with no cookie-jar cross-contamination) and sets the `bola_confirmed` indicator
ONLY on a three-leg differential -- (1) OWNERSHIP: the victim's own session reads it 2xx + the private
marker present; (2) VIOLATION: a DISTINCT attacker session reads that same victim-private marker 2xx;
(3) CONTROL: an unauthenticated request does NOT reveal the marker (proves access-controlled not
public; a nil control or <4-char marker refuses to ground). The LLM PROPOSES the two cookies + marker;
the deterministic predicate DISPOSES, so the model can never upgrade a finding itself (no LLM false
positives, §10). Wired `requiredIndicator[idor|bola|broken_object_level_authorization]=bola_confirmed`
so `record_finding` grounds it like any class. This is why a one-session "a different id returned
different data" heuristic was deliberately NOT shipped (FP-prone on public per-object endpoints + the
attacker's own object).

`privesc_probe` (`internal/webagent/privesc.go`) is the sibling for the FP-free SUBSET of BFLA:
self-privilege-escalation / mass-assignment (OWASP API #3 + #6, the IDOR/privesc-takeover shape).
`privesc_probe(session_cookie, verify_url, role_after, escalate{method,url,body})` runs a
before→escalate→after sequence on ONE session and sets `privesc_confirmed` ONLY when a high-privilege
marker was ABSENT in the session's own baseline read and PRESENT after the call that granted it -- an
OBSERVED transition of the session's OWN privilege (the before/after diff on the same page auto-excludes
a static marker), so it needs NO policy declaration. Wired
`requiredIndicator[mass_assignment|privilege_escalation|privesc]=privesc_confirmed`. The honest
boundary: GENERAL BFLA (a low-priv user calls an admin-only function affecting OTHERS) is NOT a webagent
tool -- "this function is privileged" is a policy fact unprovable from responses alone, so it stays
`apiauthz`'s job (the `api` asset, operator-declared `TestConfig`). A user promoting THEMSELVES is
unambiguously a vuln regardless of policy, which is exactly why the self-privesc slice CAN be grounded
FP-free while general BFLA cannot.

### 12.7 The ONE exception: `dispatch_oss` bridges the host-side agent to the sandbox OSS tools

Some vuln classes are a specialized OSS tool's job, NOT the agent's in-process HTTP + the in-scope
request budget: automated blind-SQLi EXTRACTION (sqlmap), WordPress/CVE (wpscan/nuclei), padding-oracle
decrypt+forge (padbuster), credential brute-force (hydra), content fuzzing at scale (ffuf). Rebuilding
those in the agent would violate Sec 13 and blow the budget. So the host-side `internal/webagent` gets
ONE gateway back into the sandbox:

* **`dispatch_oss(tool, args)`** (`internal/webagent/dispatch.go`) is the agent's single catalog slot
  that reaches the whole OSS registry -- mirroring the L2 Lead's `dispatch_l2_probe` (Sec 2.6 / Sec 9:
  one slot, many tools, so the LLM's tool list stays small). The curated registry today is 6 tools:
  **sqlmap, wpscan, nuclei, ffuf, hydra, padbuster**. This is the 14th webagent tool but it is the
  GATEWAY, not N per-tool slots -- it does NOT break the <=12-tool spirit (Sec 2.6).
* **`webagent.SandboxDispatcher`** (`internal/webagent/sandbox_dispatch.go`) adapts the SAME sandbox
  executor the L1 orchestrator uses (`Execute(ctx, tool, tool.Args) (tool.Result, error)`, satisfied by
  `*sandbox.Client`) to the agent's string `Dispatcher`. So it is ONE dispatch path (Sec 9) -- the
  offensive agent gets no second, divergent way to run OSS tools.
* **Honest gate (Sec 10):** the host-side agent has no sandbox of its own, so a run WIRES the Dispatcher
  (`web-investigate --oss-sandbox <image>`; `tsbench xbow --mode investigate` passes it through). When it
  is nil (standalone `web-investigate --target`), `dispatch_oss` degrades gracefully and SAYS the tools
  are unavailable -- it never pretends a tool ran.

**WIRING RULE for a new sandbox OSS tool** (learned the hard way): register it in **BOTH**
`internal/toolsbundle` (the host dispatch view -- so `cmd/tsengine`/`cmd/platform` resolve it) **AND**
`cmd/tool-server/imports.go` (the sandbox execution view -- so the tool-server can actually run it).
Miss the second and the tool-server 404s "unknown tool". Then add the binary to `docker/sandbox/Dockerfile`
and (if it should be agent-reachable) to the `dispatch_oss` `ossSpecialists` registry.

---

## 13. No new in-house detection engines

tsengine is **an orchestrator over community-maintained OSS security tools**, not a vulnerability-detection company.

When adding a new vulnerability category:

1. Identify the leading OSS tool (nuclei templates first, then specialized)
2. Add a wrapper under `internal/tool/<tool>/`
3. Register via `tool.Register()` with `SandboxExecution: true`
4. Add to the appropriate asset's anchor or registry tier (Â§3, Â§4) by editing the asset module under `internal/asset/<asset>/`

In-house code is reserved for orchestration logic only:

* Asset orchestrators (`internal/asset/<asset>/`)
* L1.5 enrichment hooks (`internal/tracer/hooks/`)
* L2 reasoning glue when L2 ships â chain narrative, customer prioritization (LLM does the reasoning, host commits via tool parameters)

**Adding a new in-house `scan_*` detection scanner requires an explicit architectural ADR** explaining why the leading OSS tool doesn't suffice. Default is no.

**AI-application security** (testing the customer's OWN LLM features — prompt injection, jailbreak, insecure output handling, the OWASP LLM Top 10) is genuine whitespace: tsengine covers AI *governance* (ISO 42001 / NIST AI RMF / EU AI Act, §8) + *inventory* (AI-BOM, WRD-1) today, but not AI-app vuln *detection*. The approach is fixed in [docs/adr/0012-ai-application-security.md](docs/adr/0012-ai-application-security.md) — a wrapped-OSS `ai_application` asset (anchor: **garak**; registry: promptfoo/PyRIT), active-by-nature so gated by the RoE Guard + consent + ownership-verification — NOT an in-house detector. Proposed/backlog; not built.

**Runtime protection (the Aikido /Protect pillar) is deliberately OUT OF SCOPE.** Delivering it means the customer embeds an in-app firewall (OSS Zen, `@aikido/firewall`) as an SDK/library in their own app, and us building+supporting a managed config-distribution layer across every language/runtime — an ongoing integration-support burden that isn't viable at this team's size (product decision, 2026-06-27; the `/Protect` posture surface + ADR 0013 were built then removed). What REMAINS is the passive, no-SDK-from-us signal: the `platform.RuntimeEvent` ingest (`POST /v1/runtime/events`) + `crossdetect.AnnotateRuntime`, which flags a finding `under active attack` IF a customer's runtime sensor happens to post events — an enrichment on issues/incidents, never a marketed "we protect you in production" claim.

**Install-time supply-chain gate (`internal/safechain`, Aikido "Safe Chain" parity):** the repository asset DETECTS a malicious dependency once it's in a committed lockfile; `safechain` moves the decision one step earlier — a per-package allow/block verdict the moment someone is about to install it, so a hostile package never runs. `Check(pkg, corpus)` / `CheckAll` reuse `supplychain.Scan` as the oracle (the SAME global malicious-package corpus — detection + gate can't drift). Grounded (§10): block ONLY on a real known-malicious match; an unknown package is ALLOWED (fail-open — a guard never blocks the ecosystem on absence of proof; a typosquat-distance heuristic is the next layer). `POST /v1/safechain/check` is the CI/pre-install gate (tenant-agnostic — the corpus is world-state); the npm/yarn/npx CLI shim that calls it is the gated half. NOT a new in-house detector — it's the existing detection re-pointed at install time.

### 13.1 SMB per-asset parity packages (ADR 0010)

To be THE SMB product per asset (coverage/depth + FP/FN accuracy vs the SMB category leader),
six deterministic, offline-tested cores were added â each closes a named gap, each pairs with an
honest credential/sandbox gate for live execution (full design + per-asset plan:
[docs/adr/0010-smb-per-asset-parity.md](docs/adr/0010-smb-per-asset-parity.md)):

| Package | Asset Â· gap (vs leader) | What it is |
|---|---|---|
| `internal/apiauthz` | **api** Â· BOLA/BFLA authz (vs Akto) | The Â§13 **no-OSS exception** (authz is business logic): a differential test â replay the victim's request as the attacker; `Evaluate` flags a bypass only on a proven 2xx-with-victim-data (BOLA) / undenied privileged call (BFLA), so a hit is `verification: verified`. Live prober gated (active + consent). |
| `internal/prbot` | **repository** Â· PR-inline review bot (vs Aikido/Snyk) | `Build(findings, changedFiles, blockAt)` â inline comments **only on PR-changed lines** + a check-run `success/neutral/failure`. CI entry point `POST /v1/ci/pr-check` (+ `docs/ci/github-action.yml`) runs the merge-gate from any CI via the check's exit code; live GitHub inline-post gated on the App PR scope. |
| `internal/webauth` | **web** Â· authenticated-scan reliability (vs Probely/Detectify) | `LoginFlow{form/token/recorded}` + `ValidateSession` ("am I authed?") + `IsLoginWall` ("session expired â re-auth") â the FN guard against silently scanning logged-out. Live replay gated (sandbox seed_auth). |
| `internal/registrywatch` | **container** Â· scan-on-push (vs Aikido/Snyk) | `Reconcile(current, seen)` digest-diff â scan only new/re-pushed images. Live registry listing gated (connector). |
| `internal/identitythreat` | **identity** Â· real-time ITDR (vs Nudge/Push) | `Detect(events)` rules: impossible_travel, privileged_grant, mfa_removed, password_spray, distributed_spray, mfa_fatigue, concurrent_session (two logins from different IPs within a tight window → session-token reuse, distinct from travel which needs different countries), mfa_removed_then_access (MFA disabled then a login from a new IP → the account-takeover sequence) â LLM-free, grounded. Live IdP-audit ingestion gated. |
| `internal/shadowit` | **SaaS posture** Â· shadow-IT discovery (vs Nudge/Wing) | `Inventory`/`Summarize` â SaaS-app inventory + portfolio summary; **wired live** via `operate.SaaSInventory(ws)` over the existing cross-IdP OAuth grants (no shadow-IT verdict without consent data â honest). |
| `internal/osint` | **OSINT** Â· external attacker's-eye exposure (vs SpiderFoot/Recon-ng/taranis-ai) | `Assess(Snapshot)` normalizes the leading OSINT OSS (theHarvester/SpiderFoot/dnstwist/HIBP/taranis-ai) into grounded findings: stealer-log (dark-web infostealer credential, critical), breached-credential, leaked-secret, exposed-host (a child-asset pivot target), data-exposure, typosquat-domain, subdomain-takeover (dangling-DNS, the canonical EASM finding), cert-posture (CT-log unexpected-issuer + expired/expiring), advisory â each with inline compliance + honest confidence (verified facts vs awareness signals). Feeds unified issues + correlation + posture (ADR 0011). **LIVE keyless collector**: `POST /v1/osint/scan` runs Certificate-Transparency (crt.sh) host-side over the tenant's domains â NO API key, NO sandbox (it's a public HTTPS JSON API, SSRF-screened like /v1/assess) â and pivots discovered own-domain hosts to monitored assets. **Continuous (not just manual)**: `runner.syncOSINT` runs the same crt.sh collector over the tenant's domain assets EVERY monitoring pass (wired via `Service.OSINTFetcher` in `cmd/platform`; nil â manual-scan-only), so a newly-exposed host becomes a finding the `Detector` turns into an incident â the EASM "new exposure â alert" promise, via the existing machinery. **GitHub code-search leak collector** (`internal/osint/github.go` â `CollectGitHubLeaks`/`ParseGitHubCodeSearch`): finds the org's secrets (AWS/GitHub/Slack/Google/Stripe keys, private keys) leaked in **THIRD-PARTY** public repos â a former employee's personal repo, a contractor's project â distinct from the repository asset's gitleaks/trufflehog (the org's OWN repos, whose owners are excluded). Feeds the existing `osint::leaked-secret` detector. Wired into `POST /v1/osint/scan` **reusing the onboarded GitHub connection's token** (no new credential â the SaaS-posture-sync pattern), gated + best-effort (no GitHub connection â skipped). GitHub code-search requires auth, so it's a keyed collector (the token is the gate; the query-builder + parser are pure/tested). Plus `POST /v1/osint/ingest` (posted snapshot) + `GET /v1/osint` + `/osint` UX (with a Run-scan button) + a `tsengine osint` CLI. The other keyed collectors (Shodan port-exposure, HIBP breach data) are the gated SUBSET â not OSINT as a whole. |

cloud_account's parity is the prior **ADR 0009** campaign (DSPM/CWPP/CIS-scoreboard/multi-cloud/
remediation). These cores feed the same unified-issues / auto-triage / consensus / grc-hitl
machinery; the per-asset live wiring + UX surfaces are the in-progress follow-on.

**Live wiring shipped so far** (each core's gated half is stated honestly):
- **SaaS posture** â fully end-to-end: `operate.SaaSInventory(ws)` â `GET /v1/saas-apps` (inventory
  + portfolio summary) â the `/saas-apps` frontend discovery page. Over the already-persisted
  cross-IdP OAuth grants; no shadow-IT verdict without consent data.
- **identity** â live via `POST /v1/identity/events`: an IdP-audit event stream â `identitythreat.Detect`
  â findings stored in the same store (flow through issues/incidents/grc). The IdP-audit connector is the gate.
- **container** â `POST /v1/registry/reconcile`: a connector posts current images + last-seen digests â
  `registrywatch.Reconcile` â the scan-on-push plan (stateless; the connector runs the sandbox scan).
- **repository** â `prbot.Submit` builds the GitHub PR-review + merge-gating check-run; the live POST is
  gated on the GitHub App PR-write scope. **cloud** â `connector.AWS.Apply` S3 block-public-access is now a
  **live, SDK-backed write path**: `internal/connector/awsremediate.S3Writer` (aws-sdk-go-v2 â the project's
  one cloud SDK, isolated in its own package so the core `connector` stays SDK-free) assumes a scoped
  cross-account WRITE role via STS and calls `PutPublicAccessBlock` (all four flags). Wired in `cmd/platform`
  only when `AWS_REMEDIATION_ROLE_ARN` (or `AWS_REMEDIATION_ENABLED=1`) is set â else `Apply` stays the honest
  stub; reached only after the HITL gate (Â§18.2 inv. 3). **GCP** has the parallel live path:
  `internal/connector/gcpremediate.GCSWriter` (cloud.google.com/go storage SDK, its own package) impersonates a
  scoped write SA and enforces GCS **Public Access Prevention** on a bucket; wired when
  `GCP_REMEDIATION_IMPERSONATE_SA` (or `GCP_REMEDIATION_ENABLED=1`) is set. The proposer
  (`remediate.liveCloudMutation`) emits `s3_block_public_access` (AWS) / `gcs_public_access_prevention` (GCP) /
  `azure_storage_disable_public_access` (Azure) on a public-bucket/storage finding. **Azure** completes the
  trio: `internal/connector/azremediate.StorageWriter` (azure-sdk-for-go armstorage, its own package) sets
  `AllowBlobPublicAccess=false` on a storage account via the platform's service principal
  (DefaultAzureCredential, scoped to the connection's subscription); wired when `AZURE_REMEDIATION_ENABLED=1`.
  So all three clouds now have a live, HITL-gated, SDK-backed public-storage remediation; each SDK is isolated
  in its own `*remediate` package so the core `connector` stays SDK-free. **api/web** â apiauthz/webauth live
  execution is active testing â behind the explicit-consent + sandbox gate.
- **THE CROSS-SURFACE WEDGE** ("connect code, cloud, SaaS -> one AI engineer finds the attack path across all
  three and fixes it") -- the homepage leads with it (`AttackPathHero`: a code-leaked-key + breached-SaaS-login
  graph bridging through cloud IAM to a `cloud root` crown; H1 "One leaked secret is all it takes to reach your
  cloud root"; two front doors kept -- `/scan` for founders, the attack path for security buyers). Its three
  integration halves: (1) **cloud fuel** -- `internal/connector/awsinventory.Build(RawAWS) -> cloudgraph.Inventory`
  (grounded mapper: trust edges only from real assume-role policies, internet-reach only when a SG actually opens
  the port via `cloudgraph.InternetReachable`, admin -> Privileged, sensitive bucket -> KindData; SDK isolated,
  live `describe-*` = gated half) feeds `POST /v1/cloud/inventory` (posted raw AWS state -> stored cloudsnap -> the
  AI cloud engineer/drift/search reason over the REAL account, mirroring `/v1/osint/ingest`). (2) **cloud "fixes
  it"** -- a leaked AWS key (the code->cloud entry point) gets `remediate`'s `aws_key_revoke` directive (revoke in
  cloud, then scrub code; key id via AKIA regex, grounded), gated like `iam_restrict` until a live IAM-write
  connector lands. (3) **the check in the PR** -- `POST /v1/ci/pr-check` + `docs/ci/github-action.yml` run
  `prbot.Build`'s merge-gate in CI (high+ finding on a changed line -> non-zero exit blocks the merge; disabled
  policy -> neutral), surfaced as a copy-paste snippet in the PR-bot settings panel; the live GitHub inline-post
  is the gated half. All three offline-tested cores ship; live AWS SDK fetch + live IAM/key write + live GitHub
  post are the honest credential/scope-gated halves.

**Config surfaces (the per-asset setup half, end-to-end UX + API)** â each stores its config + drives the
core; the live *execution* stays each core's gated half:
- **web** â `POST /v1/assets/{id}/login-flow` + the `/assets` "Authenticated scanning" modal: stores a
  `webauth.LoginFlow` (validated) so the scanner replays + validates the session each scan (the FN guard).
- **api** â `POST /v1/assets/{id}/authz-test` + the `/assets` "BOLA/BFLA test" modal (two identities +
  operations editor): stores an `apiauthz.TestConfig` (validated) for the differential authz test.
- **repository** â `platform.PRBotPolicy` on the Tenant via `GET/PUT /v1/settings/pr-bot` + the Settings
  "Pull-request review" panel (enable + merge-gating severity floor; `github_connected` honesty flag).
- **cloud_account** â `POST /v1/connections/{id}/cloud-remediation` + the Settings "Auto-remediation"
  control on each aws/gcp/azure connection: stores the customer's OWN cross-account write role on
  `Connection.Config` (`remediation_enabled` + `remediation_role_arn`/`region` for AWS,
  `remediation_impersonate_sa` for GCP; Azure = enable flag, subscription from the connection account).
  The connector's Apply uses it at remediation time (`connector.{AWS,GCP,Azure}.writerFor` â an injected
  per-tenant writer factory, keeping `package connector` SDK-free), falling back to the operator-default
  `Writer`. Non-secret identifiers (like `Account`) â stored plain, not sealed. Still HITL-gated; a wrong
  role surfaces honestly at Apply. This is the per-TENANT half; whether the deployment can do live cloud
  writes at all stays the operator's `*_REMEDIATION_*` env (Bucket C).
- **notifications** â `GET/PUT /v1/settings/notifications` + the Settings "Notifications" Slack control:
  stores the tenant's OWN Slack Incoming Webhook (sealed via `d.Vault` â a webhook URL is a bearer
  capability, so unlike the cloud role it MUST seal; GET reports only `has_slack_webhook`). The incident
  alerter is a `notify.TenantRouter` that routes each new incident to its OWN tenant's webhook (resolver
  opens the sealed ref) AND the operator-global `MultiAlerter` fallback â so incident heads-ups are
  multi-tenant, not one shared channel. Approval *buttons* stay the operator Slack app (those need its
  interactive endpoint). Operator-env channels (`TSENGINE_SLACK_WEBHOOK`/Teams/Discord/PagerDuty/webhook)
  remain the Bucket-C fallback.
- **ticketing (Jira)** â `GET/PUT /v1/settings/jira` + the Settings "Jira" control: stores the tenant's
  OWN Jira (`Tenant.Jira` â BaseURL/Email/Project plain, API token sealed via `d.Vault`; GET reports
  has_token only). `remediate.TenantFiler` (mirrors `notify.TenantRouter`) routes a `file_ticket`
  action to the tenant's own Jira (resolver opens the sealed token â `connector.NewJira`), falling
  back to the operator tracker (`JIRA_BASE_URL`/ServiceNow/Linear env â the Bucket-C fallback). So
  remediation tickets are multi-tenant, not one shared project.
- **escalation matrix (24Ã7-SOC parity)** â `GET/PUT /v1/settings/escalation` + the Settings
  "Escalation matrix" control: stores `Tenant.Escalation` (`platform.EscalationPolicy` â ordered
  tiers of `MinSeverity â Channels` + an `AckWindowMins`; channel names only, no secret â plain).
  Drives **two** runtime behaviours: (1) **severity routing** â `notify.PolicyRouter` (wraps a
  channel-nameâ`notify.Alerter` map + the per-tenant `TenantRouter` as `Default`) routes a new
  incident to the FIRST matching tier's channels, never-drop fallback to Default; wired as the
  incident alerter in `cmd/platform`. (2) **timed auto-escalation** â `Incident.Overdue(ackWindowMins,
  now)` (open + unacked + past window, â¤1 re-ping/window) drives `detect.Detector.EscalateOverdue`,
  called each pass by `runner.RescanTenant`; `POST /v1/incidents/{id}/ack` (a human takes ownership â
  `Overdue` goes false â stops) + the `/incidents` Acknowledge button. PagerDuty/Opsgenie parity.
- **remediation SLAs (MDR/vuln-mgmt parity)** â `GET/PUT /v1/settings/sla` + the Settings
  "Remediation SLAs" control: stores `Tenant.SLA` (`platform.SLAPolicy` â per-severity `AckHours` +
  `ResolveHours`; no secret â plain). `SLAPolicy.Evaluate(inc, now) â SLABreach` (ack/resolve breach
  grounded on the incident clocks `OpenedAt`/`AcknowledgedAt`/`ResolvedAt`; a met clock never
  breaches, 0-hours disables a clock). `GET /v1/incidents` annotates each incident with a TRANSIENT
  `SLABreach` (read-time via `Deps.annotateSLA`, never persisted); `/incidents` shows an "SLA
  breached" badge + count. Pure-compute, grounded, LLM-free.
- **maintenance windows (MDR change-freeze parity)** â `GET/POST/DELETE /v1/maintenance-windows` +
  the Settings "Maintenance windows" control: stores `Tenant.MaintenanceWindows`
  (`platform.MaintenanceWindow{Name, StartsAt, EndsAt}` + `Active(now)` / `Tenant.InMaintenance(now)`;
  no secret â plain). While a window is active, `detect.Detector` (via an injected `Suppressed`
  predicate wired in `cmd/platform` to `Tenant.InMaintenance`) opens NO new incidents and
  `EscalateOverdue` pages no one â but resolves still flow. `/incidents` shows an "in maintenance"
  banner. So a planned deploy doesn't trip the SOC.
- **SOC-performance reporting (MDR scorecard)** â `GET /v1/soc-metrics` (`internal/socmetrics.Compute`)
  + the `/incidents` scorecard: SLA-compliance % (resolved â historical outcome, open â current
  state), MTTA (openâack) + MTTR (openâresolve), open-incident aging buckets. Pure-compute over the
  incidents + SLA policy, grounded on real timestamps, LLM-free. The "how is the SOC performing" view.
- **on-call escalation roster (the PO's "escalation matrix with contact number")** â
  `GET/POST/DELETE /v1/contacts` + the Settings "Escalation contacts" control: stores `Tenant.Contacts`
  (`platform.Contact{Name, Role, Email, Phone, Order}`, ordered by escalation precedence; contact PII
  not a bearer secret â plain, like team-member emails). Names the real humans + numbers the
  escalation matrix reaches. Live SMS/voice paging stays the honest Bucket-C gate (needs an SMS
  connector); the roster + numbers are first-class.
- **CREDENTIAL SEALING (Â§18.2 inv. 6)** â the login-flow + authz-test configs carry secrets (passwords /
  tokens / auth headers), so the setters **seal the config blob via `d.Vault`** before it touches the store
  (`Asset.Meta["login_flow"]`/`["authz_test"]` hold a sealed ref, never plaintext); no vault â the setter
  refuses (400). Each configured asset row shows a reconfigure badge (rotate creds â overwrite). The
  PR-bot policy carries no secret, so it is stored plain.

---

## 14. Benchmark framework

Per-asset recall vs. neutral competitor leaderboards where possible:

| Asset | Bench harness | Headline metric | External comparison |
|---|---|---|---|
| web_application | `bench/wavsep` | Per-class Youden | Acunetix 87%, Netsparker 87%, Burp 78%, ZAP 56% (Shay Chen WAVSEP) |
| repository (SAST) | `bench/owasp_benchmark` | Per-CWE Youden | Veracode 51%, Checkmarx 47%, Fortify 35%, SonarQube 6% (OWASP Benchmark v1.2) |
| api | `bench/api_fixtures` (VAmPI + crAPI) | Must-find recall | None public â internal only |
| repository (SCA) | `bench/sca_lockfiles` | Must-find CVE recall | Snyk/Dependabot self-published |
| container_image | `bench/container_cves` | Must-find CVE recall | Trivy/Snyk/Anchore self-published |
| ip_address | `bench/ip_services` | Must-find recall | Tenable/Qualys â no scorecard |
| domain | `bench/recon_breadth` | Subdomain discovery rate | subfinder/amass published |
| cloud_account | `bench/cloud_baseline` | CIS recall vs. mock AWS account | Prowler/scout-suite self-published |
| cloud_account (offline) | `tsbench cloud-baseline` (`internal/cloudbench`) | CIS-control recall over a fixture account, prowler-only vs. tsengine (engine+DSPM/CWPP lift) â laptop/CI, no sandbox | Prowler/Scout (no neutral baseline exists) |
| L1.5 ablation | (any L1 bench) + `TSENGINE_L15_DISABLED=1` | Î-metric = L1.5 lift | Internal |
| L2 agent | `bench/agent` (scorer + `tsbench agent`); live targets `bench/webgoat_dual` + `bench/juiceshop_full` | detection_rate, **verified_rate** (PoC/evidence-grounded â the XBOW no-FP bar), completion_rate, FP-control | vs XBOW / strix / NodeZero (exploitation-verified) |
| Multi-trial | `bench/multi_trial` wrapper | median + p10/p90 over N=5 | â |

### 14.1 Ablation flags

* `TSENGINE_L15_DISABLED=1` â skip L1.5 hook chain. Findings land raw. Measures L1's contribution.
* `TSENGINE_L2_DISABLED=1` â `orchestrator.Run()` returns after anchor prepass. Measures pure L1 detection.

### 14.1.1 FP-control (false-positive specificity)

Recall (FN) is measured per-asset above; the **FP** half is measured by `metric:fp_rate` fixtures on **benign/clean targets**, where the correct answer is zero actionable findings. The gate is a **severity floor** â `Fixture.MaxSeverity` (e.g. `"high"`): any raw finding at or above it is a false positive (`Score.FalsePositiveCount`). This is robust where the old `max_findings:0` was brittle â a clean target may legitimately emit info-level notes, but must never raise a high/critical alarm. FP-control fixtures: `fixtures/container/alpine-clean` (runnable), `fixtures/repo/clean` (SAST/SCA â the noisiest class; runnable once repo-mount bench wiring lands). Pairs sensitivityâspecificity per asset (Youden = TPR + TNR â 1); FP bar tracks the XBOW "no false positives" standard.

### 14.2 Anti-overfit guards (mandatory on every new bench)

1. Source-grep test forbidding SUT-specific identifiers (juice-shop, bkimminich, vampi, crapi, etc.) in scoring code
2. Mandatory competitor citation in every bench report (enforced by render_report tests)
3. Multi-trial median + p10/p90
4. Per-layer ablation

---

## 15. Coding conventions (Go)

* Module path: `github.com/ClatTribe/tsengine` (placeholder â confirm before phase 0)
* `go.mod` Go version: 1.22+
* Errors: `errors.Is`/`errors.As`; wrap with `fmt.Errorf("%w", err)`. No string-based error matching
* Context: every public function takes `context.Context` as first arg; honor cancellation
* Concurrency: `golang.org/x/sync/errgroup` for fan-out; bounded semaphore (`chan struct{}`) for tool dispatch (default `TSENGINE_DISPATCH_CONCURRENCY=4`)
* Tests: `go test ./...` standard; integration tests under `tests/integration/` gated by `-tags=integration`
* Lint: `golangci-lint run` with the project `.golangci.yml`; `govulncheck` on every PR
* Iter naming: `iter-XX.Y` in commit messages, code comments, and test file names where relevant
* PRs: squash-merge via `gh pr merge <N> --squash --delete-branch`
* **Always update CLAUDE.md and arch.md when architecture changes**

---

## 16. Build phases â current status

> **Status note (2026-06-21):** phases 0â6 are **built + CI-green**; the platform layer
> (Â§18) is built on top. What remains is **live/scale verification gated on infra,
> credentials, or product decisions** â tracked in [docs/competitive-roadmap.md](docs/competitive-roadmap.md)
> (Tracks 1â3) and Â§18.3, not here. Concretely open: per-asset **live** benchmark numbers
> (need the sandbox image + deployed targets; SAST 0.387 Youden is the one measured so far),
> the L2 agent **live `verified_rate`** (needs a target + `LLM_API_KEY`), scale-grade infra
> (Postgres store, cloud-KMS vault, HA/sandbox-pool â all behind today's interfaces), and
> self-serve **billing**. (The per-tenant **LLM-config** is now live end-to-end â the UX seals the
> tenant's own key and `platformapi.Deps.resolveAgentLLM` drives the L2 agents with it, falling back to
> the operator-global model; the Â§18.5 "bring your own brain".)
>
> **Platform live-scanning works (PR #588 â was a silent bug, not an infra gap).** A real end-to-end run
> through the platform (`POST /v1/assets` a container â `/v1/rescan`) found that platform-driven scanning
> produced **0 findings for every tech asset since launch** â silently. Cause: a Handler resolves its
> anchor/recon tools from the **global tool registry**, populated by each wrapper's `init()` **on import**;
> `cmd/tsengine` blank-imports all 35 wrappers but `cmd/platform` imported **none** â empty registry â every
> handler planned 0 anchors â 0 dispatches â 0 findings. Fixed by a single registration source â
> **`internal/toolsbundle`** (blank-imports all wrappers; **every host binary that resolves handlers MUST
> import it**), imported by `cmd/platform`. Verified live: the platform now scans `alpine:3.18` and lands 27
> real findings (grype CVEs + dockle + license). Guarded by `cmd/platform`'s
> `TestPlatformRegistersScanToolsForEveryAsset` (PR #589) + `EngineRunner` per-scan `tools_fired` logging.
> So "live per-asset recall" below was **this bug**, not a missing target/infra â the engine always worked
> (the CLI finds 84 CVEs in the same image); only the platform's registry was empty.
>
> **Per-asset gate/bucket status** (what runs securely via Docker on one machine, what we fixed
> vs. what's customer-config vs. operator, and the honest credential-gated boundary):
> [docs/per-asset-gates.md](docs/per-asset-gates.md). Reproduce the no-creds proofs with
> `make demo-scan-asset` (container + repository + web_application + api/VAmPI).

| Phase | Scope | Status |
|---|---|---|
| **0. Foundation** | Repo skeleton, core types (`pkg/types`), `Tool`/`Handler` interfaces, L1 dashboard JSON schema, evidence/attestation grounding (Â§10), CI (go test + golangci-lint + govulncheck) | â built |
| **1. Sandbox + E2E** | Docker sandbox image (nuclei baked), `cmd/tool-server` HTTP API, host-side `internal/sandbox` client, run nuclei against one fixture target end-to-end | â built |
| **2. web_application asset** | Anchor + registry tiers, filter rules, WAVSEP fixture + scorer, tool-replay API | â built (live WAVSEP Youden pending a deployed target) |
| **3. Other 6 assets** | api, repo, container, ip, domain, cloud_account â anchor + registry tiers, per-asset filter, per-asset normalize | â built (8 assets incl. mobile; **platform live scan verified â PR #588** lands 27 real findings on a container; per-asset *recall benchmarks* still pending deployed targets) |
| **4. L1.5 + dashboard + threat intel + compliance** | Hook chain, vulnerabilities.json renderer, threat_intel.enrich, compliance.map | â built |
| **5. Template refresh + attestation** | Versioned corpora, pin-per-scan, cron refresh, delta-verify, signed evidence bundle | â built |
| **6. L2 layer** | LLM Lead agent over â¤12-tool catalog, OODA, bench rigs | â built (incl. ADR-0008 autonomous pentest; live `verified_rate` pending a target + LLM key) |

---

## 17. Where the strix lineage ends

tsengine inherits from strix:

* The L1/L2 audience-split mental model
* The host/sandbox boundary discipline
* The L1.5 hook chain order
* The sidecar findings bridge pattern
* The anti-overfit + bench discipline
* The â¤12-tool L2 cap
* The tool-existence principle

tsengine **diverges** from strix:

* Go, not Python â different idioms, library bindings where strix uses subprocess
* 8 assets, not 6 â adds `cloud_account` for the compliance audience and `mobile_application` for mobile-app teams
* Anchor + registry tier â strix has only anchors + a 99-tool legacy catalog flag
* Threat intel + compliance mapping happen at L1 emission (in addition to being L2 tools for arbitrary lookups)
* L1 dashboard JSON is a frozen schema spec'd in Phase 0, not implicit
* Evidence-grounded LLM agent with signed attestation â NOT a deterministic-process mandate (Â§10)
* No iter-Q5.* history â clean build phases (Â§16)

When in doubt, the strix design lineage at `/Users/ashish/Downloads/cowork/strix/` is reference reading, not authoritative â this file is authoritative.

---

## 18. The platform layer â autonomous security team (read before touching `cmd/platform`)

`tsengine` (the engine, Â§1âÂ§17) is the **detection brain**. The **platform** wraps it
into a continuous, multi-tenant, human-backstopped product â *"reuse the brain, build
the body"* (full design: [docs/autonomous-team.md](docs/autonomous-team.md); **operator
deploy/config guide: [docs/platform-operations.md](docs/platform-operations.md)** â env
matrix, per-provider OAuth setup, API reference). The platform is **purely additive**: it
must never change the engine's detection logic.

**Two front-ends, one API.** `internal/console` (Go `html/template`, zero-JS, at `/ui`) is
the lightweight built-in fallback. **`frontend/`** is the flagship **agentic command-center
UX** â a separate Next.js (App Router/RSC) app (dark, Linear/Vercel-grade) that consumes
the same `/v1` JSON API server-side (httpOnly-cookie auth, no CORS, engine untouched). See
[frontend/DESIGN.md](frontend/DESIGN.md) for the IA, design system, and build phases. Both
are presentation only â the gate, ledger, and engines are unchanged.

### 18.1 The packages

| Package | Role |
|---|---|
| `pkg/ledger` | the signed, replayable decision ledger (promoted from `internal/` so the platform imports it) |
| `pkg/platform` | multi-tenant domain model â Tenant, Connection, Asset, Engagement, Action, ControlState |
| `internal/store` | the tenant-scoped system-of-record (`Store` interface + Memory / File-snapshot / SQLite / Postgres impls, table-driven conformance suite — postgres:// DSN routes to the Postgres store for multi-node scale, e.g. Supabase/RDS/Neon); holds the **third-party app inventory** (`ReplaceThirdPartyApps`/`ListThirdPartyApps`, per operate scan) and the **issue-suppression rules** (`Put`/`List`/`DeleteIgnoreRule`, keyed by unified-issue dedup key â the ignore/accept-risk lifecycle) |
| `internal/connector` | external-system integrations (OAuth + Discover + Watch + Apply): GitHub + GitLab (tech SCM), Google Workspace + M365 + Okta (non-tech identity) |
| `internal/runner` | connectorâengineâstore glue; `ScanRunner` abstracts the engine, `EngineRunner` is the sandbox adapter; runs the full loop |
| `internal/hitl` | the human desk â the gate between *propose* and *apply* |
| `internal/remediate` | `Propose` (findingâAction; repoâPR, cloudâconfig, **workspaceâa per-rule identity runbook** `identity.go`) + **`ProposeBulk`** (`bulk.go` â "Bulk Fix": groups an asset's findings by fix unit â SCA package coordinate from `ToolArgs`, else rule id â and emits ONE PR per group of â¥2 repo findings, citing every finding it resolves via `Action.FindingIDs`; singletons/non-repo fall back to `Propose`; the runner's optional `ProposeBatch` supersedes per-finding `Propose` when set) + the **Respond breadth catalog** (`cloud_catalog.go` `cloudFixCatalog`: the common non-storage cloud-misconfig classes (IAM privesc, open security group, unencrypted-at-rest, public snapshot/DB, missing MFA, disabled logging, root access key, weak password policy) each get a machine-readable `remediation_type` + a SPECIFIC copy-pasteable runbook (the exact CLI cut) instead of a generic "review this" ticket. Grounded 10 (matches the finding's own text, targets its own resource) + promotable: a class upgrades to a live HITL-gated mutation with one catalog entry the moment its connector write lands, exactly like S3 block-public-access. Only public-storage is live-writable today, the honest gate; the runbook classes (`cloudRunbookRemediations`, derived from `cloudCatalog`) DELIVER as actionable tickets — `Deliverer.Apply` files a cloud ActApplyConfig carrying a runbook-only `remediation_type` via the `Filer` instead of calling `connector.Apply` (which would error "no live write path"), so an approved fix hands the human the exact steps not a spurious failure; a live-writable storage class + identity `account_suspend` are NOT in the set, so they still route to their real connector write) + `Deliverer` (apply via connector; routes to the action's own connection; `file_ticket` â a `Filer` e.g. Jira) |
| `internal/grc` | compliance control-state system-of-record + signed evidence pack + the auditor-facing **compliance report** (`Report` resolves each gap to its citing findings; `RenderMarkdown` is the attachable deliverable) + the customer-facing **VAPT/pentest report** (`VAPTReport`/`RenderVAPTMarkdown` â exec summary, scope, and every finding with severity/CWE/CVSS/exploit-status/evidence; grounded, served at `GET /v1/vapt/report`) + the **no-false-compliant coverage layer** (`Coverage`: `certifiable` always false, "X of Y technical controls assessed", `readiness` never says "Compliant") + **per-asset compliance** (`AssetCompliancePosture(assets, findings)` â the "is THIS asset compliant?" view: rolls each finding to the asset whose `Target` literally appears in its endpoint (longest wins, mirrors `crossdetect.datatier`), tallies per-asset gap-controls/frameworks/worst-severity; grounded Â§10 â unattributable assets (repo file:line endpoints) come back `attributed:false`, and the status line NEVER says a bare "compliant"; `GET /v1/compliance/by-asset` + a "By asset" section on `/compliance`) + **continuous evidence timeline** (`evidence_timeline.go` — the SOC 2 Type II / ISO-surveillance "prove it held ACROSS the window" artifact the point-in-time `EvidencePack` can't give: `CaptureEvidenceSnapshot` appends a timestamped posture snapshot per framework to `platform.ComplianceSnapshot` (an APPEND-ONLY store timeline, 6-place wired), change+heartbeat-gated (a real posture change captures immediately; an unchanged posture captures at most once per `evidenceHeartbeat`=24h — so a static estate doesn't bloat the timeline). `CaptureAllEvidence` is the continuous driver the **runner calls every monitoring pass** (after `Reconcile`); `EvidenceTimeline` reads it back with a grounded continuity summary (`FullyMetRatio` + a `Continuous` bit that's honest — it means every CAPTURED snapshot was fully met, NOT a claim about un-sampled instants). `GET /v1/compliance/{framework}/evidence-history` (timeline) + `POST /v1/compliance/{framework}/evidence/capture` (on-demand snapshot). Grounded §10: an un-monitored framework returns an empty, non-continuous timeline, never a fabricated "continuously compliant") |
| `internal/detect` | the continuous-monitoring backbone (deterministic detect half of detect-&-respond): `Detector.Reconcile` diffs a tenant's current findings against its open incidents â opens a `platform.Incident` for a new finding at/above a severity threshold (default high), resolves one when its issue (keyed `rule_id\|endpoint`) stops appearing. Signed into the ledger; LLM-free + grounded. `Reconcile` also takes an `attacked` key-set (ADR-0007 Phase 0b): a finding observed under attack in production opens an incident **regardless of the severity floor** + marks it `Incident.Attacked` (title prefixed `[under active attack]`); the runner computes it via `crossdetect.AttackedKeys(current, runtimeEvents)`. Driven by `runner.RescanTenant` each pass; opening a new incident fires an optional `Alerter` (Slack heads-up) so detectâalert happens in one pass |
| `internal/retest` | **fix-verification** — the answer to "60% don't retest after fixes; a fix that isn't verified is a fix taken on trust" (State-of-AI-in-Pentesting KF#4). The remediation-scoped twin of `detect.Reconcile`: when a remediation `Action` is APPLIED, `Verify(actions, current, now)` re-tests it against the next authoritative scan and records a grounded `platform.FixVerification` on the action — `fixed` ONLY when every finding key (`rule_id\|endpoint`, the SAME `detect.Key` so the two never drift) it claimed to resolve is provably absent, `still_present` when any remain (the fix didn't close it — reopen). Grounded (§10): the action carries `FindingKeys` stamped at propose time (`runner.stampFindingKeys`, stable across scans where finding IDs aren't); an action with no keys is never guessed at. `fixed` is terminal (a reappearance is a NEW incident, not a re-flip); `still_present` upgrades to `fixed` on a later clean scan. Wired into `runner.RescanTenant` right after `Detector.Reconcile` (both consume `current`); surfaced via `GET /v1/actions` (the list + a fix-verification roll-up: applied/verified/confirmed_fix/still_present, computed only over the verifiable set). Needs `Store.ListActions` (lists all of a tenant's actions, any status). LLM-free, evidence-backed |
| `internal/coverage` | **per-asset "what was actually tested"** — the answer to "52% of organizations don't have full visibility into what was tested" (State-of-AI-in-Pentesting). `Compute(assets, findings, engagements)` produces, per asset: the DECLARED anchor toolset for its type (`Toolset` map — the tools that fire on every scan of that type, §4.1, so it's what actually runs not a wish list), whether/when it was last scanned (latest completed `Engagement`), and which of those tools surfaced a finding (the rest ran clean). Grounded (§10): a never-scanned asset reads `scanned:false` (never "covered"); tools-with-findings comes only from real findings attributed by a literal target match (longest-wins, same as data-tier / per-asset compliance); registry-tier depth tools are excluded (on-demand). Deterministic + LLM-free. `GET /v1/coverage` + the `/coverage` "Test coverage" page (per-asset cards: scanned-when, tools-run chips with finding-surfacing ones highlighted, "all ran clean" vs "N findings from M tools"). |
| `internal/ownership` | **proof-of-asset-ownership challenge** — the control leaders named as a precondition for trusting AI testing ("proof of asset ownership", State-of-AI-in-Pentesting p35). For a standalone target a customer ADDS (a domain/web/IP they typed, vs an OAuth-connected system which already proves control), they prove control by publishing a per-asset token via a DNS TXT record (`_tsengine.<host>`) OR a well-known file (`/.well-known/tsengine-verification.txt`). `NewChallenge(target, token)` builds the instructions; `Verify(ctx, ch, resolver, fetch)` checks the LIVE target (DNS first, then file) and returns verified+method. Grounded (§10): owner-verified ONLY when the token is really found — a lookup error / absent token is unverified, never assumed. The file fetch is SSRF-screened (same guard as `/v1/assess`). `POST /v1/assets/{id}/ownership/challenge` (issue+store a 128-bit token on `Asset.Meta`) + `POST /v1/assets/{id}/ownership/verify` (live check → `Asset.Meta["ownership_verified"]`/`["ownership_method"]`/`["ownership_verified_at"]`). Gating active scanning on verification is the documented follow-on; the challenge/verify capability + the agent-controls trust claim work today. |
| `internal/clouddrift` | **continuous CONFIG-SNAPSHOT drift detection** — the third drift signal, complementing `cloudcdr` (audit-log-event drift) + `detect` (finding-diff drift). `Diff(prev, cur *cloudgraph.Snapshot)` compares two cloud inventory snapshots over time and emits grounded change-control findings for the security-relevant config changes: `resource-became-public`, `principal-became-privileged`, `new-privileged-principal`, `new-public-resource`, `new-internet-exposure` (a new internet→resource reach edge), `new-privilege-escalation`, `new-lateral-movement` (new secret_access edge). The SOC2/CIS change-control "detect unauthorized change to the environment" signal WITHOUT the audit-log stream. Deterministic + LLM-free + grounded (§10): each finding cites the changed node/edge + before→after, carries the change-control compliance nexus (SOC2 CC8.1, NIST CM-3/CM-6, CIS 4.2/8.5, ISO A.8.32), and an unchanged pair / nil baseline (first observation) yields ZERO findings. Live driver: `POST /v1/cloud/drift` (prev+cur inventory → findings into the same store → issues/incidents/grc/hitl). **Continuous DIFF-ON-INGEST is now wired** (`cloudinventory.go`): re-POSTing to `POST /v1/cloud/inventory` diffs the fresh snapshot against the tenant's STORED baseline BEFORE overwriting it → automatic drift findings on every re-ingest (the "connect once, detect change" promise), no separate `/v1/cloud/drift` call. Both paths share `persistDriftFindings` (enrich → store → GRC → incident) so they never diverge; grounded §10 (first ingest / unchanged re-ingest yield 0). A live scheduled FETCH into `/v1/cloud/inventory` (vs the customer/CI re-POST) stays the credential-gated half |
| `internal/cloudsearch` | **"search your cloud like a database"** (Aikido /Cloud parity) over the inventory the engine ALREADY builds (`cloudgraph.Inventory`). `Search(inv, Query)` filters resources by kind/type/region/public/privileged/sensitive/tag/free-text and returns each match with its immediate relationships (`Reaches`/`ReachedBy`, derived from the real reach/grant/trust/pass/privesc/runs-as/trigger edges — the "JOIN"). The attack-path engine builds this graph to reason about exposure; cloudsearch exposes it as a queryable surface so an operator can instantly answer "which storage is public?", "what can reach this DB?", "every privileged principal in us-east-1" without re-scanning. Pure + deterministic + grounded (§10): every result is a real resource/edge from the supplied inventory; an empty/unsatisfiable query yields nothing, never invented. `POST /v1/cloud/search` (posted inventory + query, same snapshot shape as `/v1/cloud/drift`); persisting each tenant's last inventory so it's queryable any time (no re-post) is the documented follow-on. |
| `internal/tprm` | **third-party / vendor risk management (TPRM)** — the Vanta-TPRM "finding issues" capability the engine lacked; the vendor portfolio is an asset class. `Assess(vendors []Vendor)` surfaces grounded vendor-risk findings: `vendor-uncertified` (a PII/sensitive-data vendor with no SOC 2 / ISO 27001 — high), `subprocessor-no-dpa` (a subprocessor without a data-processing agreement — GDPR Art. 28, high), `vendor-breach-history` (a vendor with a recorded breach + data access — high), `card-vendor-no-pci` (a cardholder-data vendor without PCI — PCI 12.8, high), `vendor-stale-review` (a critical/high-criticality vendor not reviewed within the window, default 365d — medium). Each carries the vendor-management compliance nexus (SOC 2 CC9.2, GDPR Art. 28, PCI 12.8, ISO A.5.19/5.20/5.22, NIST SR-3/SR-6). Snapshot-driven, LLM-free, grounded (§10) — a well-managed portfolio yields ZERO findings. Live driver: `POST /v1/tprm/ingest` (vendor inventory → findings into the same store → issues/incidents/grc/hitl); a live vendor-inventory connector (procurement/SSO sync) is the follow-on, the posted-inventory path works today |
| `internal/deviceposture` | **endpoint / device posture (MDM-lite)** — the Vanta device-monitoring "finding issues" capability; employee laptops/phones are an asset class. `Assess(devices []Device)` surfaces grounded device-posture findings: `disk-unencrypted` (high; SOC2 CC6.7, HIPAA 164.312(a)(2)(iv), NIST SC-28), `tampered` (jailbroken/rooted, high), `os-end-of-life` (high; SI-2), `no-screen-lock` (medium; AC-11), `firewall-off` (medium; SC-7), `no-edr` (medium; SI-3), `auto-update-off` (low). Snapshot-driven, LLM-free, grounded (§10) — a compliant fleet yields ZERO findings; a missing field never invents risk. Live driver: `POST /v1/devices/ingest`; a live MDM connector (Kandji/Jamf/Intune/Kolide) is the follow-on, the posted-inventory path works today |
| `internal/assetregistry` | shared `HandlerFor(assetType)` (so `cmd/tsengine` + `cmd/platform` don't duplicate routing) |
| `internal/crossdetect` | the **unified cross-detection** layer (orchestration glue over `correlate` + the flat finding list â adds no detection, Â§10/Â§13 hold). Six capabilities: (1) **attack paths** â buckets findings by inferred asset type so `correlate.Correlate` builds cross-surface chains (a finding bridging, via a real shared entity key/ARN/host/IP/bucket, to a crown jewel on another surface); `GET /v1/attack-paths` + `/attack-paths` page + dashboard banner. (2) **unified issues** (`UnifiedIssues`) â "one issue, many signals": collapses findings sharing a CVE (else rule\|endpoint) into one Issue carrying the worst severity + the distinct source scanners + `Confirmed` (â¥2 tools agree); `GET /v1/issues` + `/issues` page + dashboard noise-reduction banner. (3) **issue suppression** â `GET /v1/issues` hides issues with a `platform.IgnoreRule` (default) / `?show=ignored`; `POST /v1/issues/ignore`\|`/unignore` (ledger-recorded) + the `/issues` Active/Ignored toggle + per-row ignore/restore. (4) **custom exclusion rules** (`exclude.go` â Aikido "custom rules": exclude paths/packages/conditions) â `platform.ExclusionRule` (field â rule_id/package/path/cve/any + a `*`-glob `Pattern`); `ApplyExclusions` drops matching findings BEFORE `UnifiedIssues`, so excluded noise never becomes an issue (the `excluded` count rides on `GET /v1/issues`); `GET /v1/exclusions` + `POST /v1/exclusions`\|`/exclusions/delete` (ledger-recorded) + the `/issues` exclusion-rules manager. (5) **runtime correlation** (`runtime.go` â Runtime Protection, ADR-0007 Phase 0) â `platform.RuntimeEvent` is an in-app-firewall/RASP attack observation (the OSS "Zen" sensor streams its block events in); `AnnotateRuntime` flags any issue whose endpoint path matches a runtime event â `Attacked`/`AttackCount` = observed-in-the-wild (the strongest exploitability signal). tsengine consumes the signal, never blocks (Â§13). `POST /v1/runtime/events` (ingest, single or batch; body-tenant ignored for isolation) + `GET /v1/runtime/events` + the `attacked` count on `GET /v1/issues` + an "under attack" badge/stat on `/issues`. Phase 1 (the managed in-app sensor) stays ADR-0007-gated. (6) **data-tier prioritization** (`datatier.go` â the Synthesia "tier repos by customer-data exposure" idea) â an owner classifies each asset's data sensitivity (`platform.DataTier` 1=customer-data â¦ 3=low, stored in `Asset.Meta["data_tier"]`, default Standard; `POST /v1/assets/{id}/data-tier`, surfaced on `GET /v1/assets` as `data_tier`/`data_tier_label`, set via the `/assets` Data-tier control). `RiskWeight(severity, tier)` is the tier-adjusted priority (tier 1 +50%, tier 3 â40%; severity stays dominant within a tier, so a Medium on a customer-data asset can outrank a Medium on a low-sensitivity one or edge a Low on a standard one); `PrioritizeByDataTier` attributes each issue to a tiered asset (BEST-EFFORT + grounded, Â§10 â only when the asset's Target literally appears in the issue Endpoint; repo file:line endpoints stay Standard until a findingâasset link exists in the data model) and re-ranks `GET /v1/issues` so the highest-risk issues lead (no-op while every asset is Standard). Engine `surface_priority` is untouched (Â§18.2 inv 1) â this is a platform-layer reordering only |
| `internal/pentest` | the **productized AI-pentest** layer (Aikido "AI pentesting" parity; ADR 0006). `Engagement` lifecycle (draftâauthorizedârunningâreportingâcompleteâretesting/halted) + the **Rules-of-Engagement Guard** (`roe.go`): every agent action is gated by the runner â scope â budget â an **absolute destructive ban** â the **active-exploitation gate**. Active exploitation is **explicit-consent-based**: `RoE.ActiveAuthorized()` (the single source of truth) requires `AllowActive` + a named `AuthorizedBy` + a recorded `Consent` statement; `Authorize`, the runner `Check`, and `POST /v1/pentest` all refuse active mode without all three (400), and the consent text is signed into the ledger. The runner inverts control (agent **proposes** an `Attempt`, runner **disposes** via `RoE.Check` before any side effect), enforces the request budget + kill-switch. **Phase 0** runs the **`PassiveDriver`** over in-scope findings; **Phase 1 (built, ADR-0006 accepted)** is the **`ActiveDriver`** (`active.go`) â per-class playbooks (SSRF-canary, boolean-SQLi true/false differential, open-redirect canary-Location, reflected-XSS canary, IDOR-read), each a `Demonstration` of one or more benign `Probe`s + a **machine-checkable success predicate** over the responses, that upgrades a finding to `verification_status: verified` + a captured PoC **only** when its predicate holds (else the lead is reported unchanged). Benign-by-construction (canary probes, true/false differentials that extract no data, no writes/exfil). Live egress is `HTTPProber` (`httpprober.go` â bounded timeout, capped read, no redirect-follow so the 30x Location is the open-redirect proof), wired into `POST /v1/pentest/{id}/run` only when the engagement is active+consented AND the operator set `TSENGINE_ACTIVE_EXPLOIT=1` (else graceful passive fallback â never a falsely-confident exploit). **ModeDeep** (ADR-0008, the open-ended/XBOW path) runs the **long-horizon** `OpenEndedDriverIterative` (`iterative.go`) â a bounded per-finding **observeâproposeâvalidateârefine** loop (`TSENGINE_DEEP_MAX_ATTEMPTS`, default 3, floored 1 / capped 8) â with a per-finding **spec generator**: the deterministic `HeuristicSpecGen` (extended classes â blind/OOB, SSTI, CRLF) by default, OR â when `Deps.AgentLLM` is wired (`cloudengine.LLMFromEnv`: a cloud key OR a **local Ollama**) â the **`LLMSpecGen` "D-agent"** (`llmspec.go`), which asks the model to PROPOSE a benign `DemoSpec` (probes + a named library predicate + args) for a finding of ANY class. The model only proposes; `DemoFromSpec` re-validates with the deterministic predicate and the RoE Guard still gates scope/budget/destructive â so the LLM widens discovery but can NEVER upgrade a finding by itself, **even across attempts** (no LLM false positives, Â§10). The **refine loop is the XBOW long-horizon fix** (`RefiningSpecGenFor` + `LLMSpecGenRefine`): when a spec's predicate doesn't hold, the failed predicate(s) + probe results are threaded back so the D-agent proposes a DIFFERENT approach next attempt (AND the cross-finding **engagement memory** `env` — bounded, deduped failed attempts observed on OTHER findings of the same target, e.g. a uniform 403/WAF block — is threaded as a target-ENVIRONMENT signal, NOT an already-tried list, so the agent shares what it learned about the target across the whole engagement instead of re-discovering it per finding: the XBOW cross-finding-learning edge; `OpenEndedDriverIterative` accumulates it, the deterministic predicate still disposes so it never creates a false positive); the heuristic path has no second idea so it degrades to today's single pass (never a falsely-confident extra attempt). `SpecGenFor(llm)` layers LLMâheuristic fallback for the first attempt; this is how the open-ended XBOW-style agent plugs into the productized pentest while keeping "agent proposes, framework disposes". A portfolio scorecard (`ComputeStats`: exploitation-proven count, `verified_rate` = proven/total, high+ proven, the high-plus-found SLA gate) backs the "exploitation-proven, money-back if no High+" claim â grounded tallies, never estimates. API: `POST /v1/pentest` (create+authorize), `GET /v1/pentest[/{id}]`, `GET /v1/pentest/stats` (scorecard), `POST /v1/pentest/{id}/run`, `GET /v1/pentest/{id}/report` (per-engagement VAPT via `grc.ReportFromFindings`); UX: `/pentest` list+create (consent capture) + scorecard + `/pentest/{id}` detail with Run/Retest + recorded-consent + report download |
| `internal/scheduler` | continuous-monitoring loop â re-scans every tenant on a cadence (`TSENGINE_MONITOR_INTERVAL`); the "autonomous" heartbeat alongside event-driven webhook re-scans |
| `internal/platformapi` + `cmd/platform` | the multi-tenant HTTP API + server (incl. `POST /v1/tenants` onboarding). Also the **public, unauthenticated PLG lead-magnet** `GET /v1/assess?domain=` (`assess.go` + `assess_web.go` + `assess_fix.go`): a grounded, read-only **security-questionnaire-readiness** scan for the SOC2-founder ICP â email-auth (DMARC/SPF/DKIM via public DNS through `operate`) + web posture (one HTTPS GET: HTTPS-enforced/HSTS/CSP/clickjacking/security.txt) â never scans the target's servers (SSRF-hardened: refuses private IPs), rate-limited per IP. Reframed as "you'd fail N of M questionnaire checks"; every failing check carries a copy-paste **fix** (`checkFix`). The same public API is BOTH the inbound `/scan` lead-magnet AND the $0 outbound signal source (the separate `tsgtm` GTM repo scrapes it). Viral loop: `GET /v1/assess/badge?domain=` (`assess_badge.go`) serves an embeddable SVG grade badge (6h per-domain cache, only a cache-miss runs the probe) a founder puts on their site/trust-page â every render is a branded backlink to `/scan`. The `/scan` page is a shareable `?domain=` permalink (auto-runs) with an "Embed your badge" + "Fix it" UX |
| `internal/console` | the human-facing web dashboard + login under `/ui` â server-rendered HTML (`html/template`, zero JS). `GET /ui` shows risk rating + severity counts + top findings + pending approvals + compliance posture (cards link to the drill-down); `GET /ui/compliance/{framework}` is the per-control drill-down (gaps backed by their citing findings â the auditor view); `GET /ui/connect` is the first-run onboarding page (lists connectors + status) and `GET /ui/connect/{kind}` 302-redirects the browser into the provider OAuth consent (state = tenant id, reusing the API's `/v1/connect/{kind}/callback` exchange); `POST /ui/login` sets an httpOnly+SameSite=Strict session cookie (a browser can't send the bearer header on navigation); `POST /ui/approvals/{id}` Approve/Reject buttons drive the **same gated `hitl.Desk.Decide`** path as the API/Slack (tier rules + signed ledger still apply â the console is a UI onto the gate, not a second write path); a "Monitored assets" section (with last-scanned time) + a "Scan now" button (`POST /ui/rescan` / `POST /v1/rescan` â `RescanTenant`) give the owner visibility + manual control. Connection `SecretRef`s redacted before render |

### 18.2 Platform invariants (do not violate)

1. **The engine is untouched.** The platform consumes `orchestrator.Run` via `runner.ScanRunner`; no platform change may alter `asset/*`, the agents, `reachability`, `correlate`, or `gate`.
2. **Tenant isolation is the security boundary.** Every `Store` call is tenant-scoped; a tenant MUST NOT read another tenant's findings/connections/actions. Tests assert this at the store *and* the API.
3. **The only write path is `connector.Apply`, and it is reached only AFTER a HITL gate.** Tier 0/1 actions auto-apply; tier â¥ `platform.GateTier` (2) queue at the desk. `hitl.Desk` decides; `remediate.Deliverer` delivers. Never call `connector.Apply` directly.
4. **Every decision is signed.** Auto-apply and human verdicts both record into `pkg/ledger`; the GRC evidence pack uses the same ed25519-over-canonical-JSON scheme â one verifier covers ledger, evidence bundle, and evidence pack.
5. **Grounding holds end-to-end.** GRC marks a control "gap" only because a real finding cites it; remediations always carry `FindingID`. No platform layer asserts something the engine did not prove.
6. **Secrets never leave, and never sit in plaintext.** OAuth tokens are sealed by `internal/secret` (AES-256-GCM, key from `TSENGINE_SECRET_KEY`) at the OAuth callback *before* they touch the store; `Connection.SecretRef` holds only the sealed ref, resolved via `secret.Tokens` (`runner.Tokens`); the API redacts `SecretRef` before returning a connection.
7. **The kill-switch fails closed.** `Tenant.AgentsHalted` (the agentic-SMB spec OM-3 / TS-5 global kill-switch, toggled via `POST /v1/killswitch`) halts ALL autonomous action for a tenant: `hitl.Desk` refuses every apply (auto-applied AND human-approved alike â the switch wins over the verdict; queued actions wait) and `runner` pauses scanning. A read error on the flag is treated as NOT halted (opt-in; a transient error must not freeze a tenant). The one human "on the loop" can freeze the whole roster instantly; the toggle is signed into the ledger.

### 18.3 Status

Phases 0â3 + the wired loop are built (`store`/`platform`/`connector`/`runner`/`hitl`/
`remediate`/`grc`/`platformapi`/`cmd/platform`), all tested + CI-green. The store has a
dependency-free **file-backed persistent impl** (`store.OpenFile`, atomic snapshot;
`TSENGINE_PLATFORM_DB`) behind the `Store` interface â single-node-durable today. The
**Slack approval loop** is wired: `internal/notify` posts a queued action to Slack with
Approve/Reject buttons, and `POST /v1/slack/interactive` verifies Slack's v0 signature
(HMAC-SHA256, 5-min replay window) before driving `Desk.Decide`. OAuth tokens are
**encrypted at rest** (`internal/secret`, AES-256-GCM; `TSENGINE_SECRET_KEY`), sealed at
the callback before they reach the store. **Phase 4 (non-tech operate layer) has
started**: `internal/operate` is the identity/email posture engine â a Workspace
snapshot (IdP / Google Workspace / M365 export) â grounded findings (MFA gaps, weak
DMARC, risky OAuth grants, stale/over-privileged accounts), each citing the offending
user/domain/app, mapped to compliance controls so they flow into the same `grc`/`hitl`
loop. Snapshot-driven + LLM-free (mirrors `cloudengine`), so the logic is deterministic
and testable (a hardened workspace yields zero findings). `tsengine operate --snapshot`.
`operate` is wired into the platform as a `ScanRunner` for the `workspace` asset via
`runner.MuxRunner` (routes by asset type: workspace â operate, else â sandbox engine),
and a **live Google Workspace path** exists end to end: `connector.GWorkspace` (OAuth
onboarding â a `workspace` asset) + `operate.GWorkspace.Fetch` (Admin SDK directory â
snapshot) + `runner.LiveWorkspaceSource`/`CompositeSource` (snapshot-file first, else
live fetch). So a non-tech tenant connects **Google Workspace or Microsoft 365** â
posture findings flow through the same store/grc/hitl/ledger loop. `LiveWorkspaceSource`
holds a `Fetchers map[kind]Fetcher` so it serves multiple providers; `operate.M365`
fetches Microsoft Graph (`/users` + the auth-methods registration report, merged by UPN,
OData-paginated).

**The human UX layer is complete (`internal/console`, served at `/ui` by `cmd/platform`).**
The promised loop is now clickable end to end: provision a tenant (`POST /v1/tenants`) â
sign in (`/ui/login`, httpOnly+SameSite=Strict session cookie) â **connect a system**
(`/ui/connect` â provider OAuth â callback discovers + scans) â the **posture dashboard**
(risk rating, severity counts, top findings, connected systems) â **approve/reject fixes
in the browser** (drives the same gated `hitl.Desk.Decide` as Slack/API) â **compliance**
(posture cards â per-control drill-down with citing findings â signed Markdown report at
`GET /v1/compliance/{framework}/report`). Security + compliance, UX to backend, on the
untouched engine.

**Domain email-auth is live too** (`operate.EmailAuth`): the provider user-fetch only
yields accounts, so the live source now derives the org's sending domains from the user
emails (`operate.DomainsFromUsers`) and resolves DMARC/SPF/DKIM from public DNS
(`internal/runner.LiveWorkspaceSource.EmailAuth`, an injectable `Resolver` â `*net.Resolver`
in prod, fake in tests). Grounded (each field reflects a real TXT record or its documented
absence) and opt-in (nil enricher â today's snapshot-only behavior). So a connected
workspace now gets MFA posture *and* email-spoofing posture with zero extra config.

**Okta is wired** (`connector.Okta` OAuth onboarding â `workspace` asset + `operate.Okta`
fetcher: users paginated via the `Link` header, per-active-user MFA factors + admin roles,
statusâsuspended, lastLoginâstale; `OKTA_ORG_URL`/`OKTA_CLIENT_ID`/`OKTA_CLIENT_SECRET`).
So a non-tech tenant can connect **Google Workspace, Microsoft 365, or Okta** and get the
same grounded identity posture through the store/grc/hitl/ledger loop.

**Continuous monitoring now detects change, not just re-scans** (`internal/detect`): each
scheduled `RescanTenant` pass reconciles the tenant's current findings into durable
`Incident`s â opening one when a high+/critical issue is NEW since the last pass, resolving
it when the issue is fixed (keyed `rule_id|endpoint`, signed into the ledger, LLM-free).
Surfaced at `GET /v1/incidents` and a dashboard "New since last scan" section. This is the
deterministic **detect** half of detect-&-respond; the **respond** half is the existing
remediate + HITL path **plus the A-RSP incident-response slice**: when `Reconcile` opens a
**critical** incident, `runner` calls `remediate.ProposeIncidentResponse`, which prepares
**two** responses: (1) a **tier-2 gated containment** action (`proposeContainment` â
`ActFileTicket`, `remediation_type:containment`) â a class-specific runbook (identity â
suspend account + revoke sessions; cloud â restrict/quarantine resource; web/api â block the
endpoint) naming the affected entity (the endpoint half of the incident key), gated so a
human approves before it acts (carries a machine-readable `remediation_type`+`target` so a
future live containment connector can promote it to a real apply, like the Okta-suspend
promotion); and (2) a **T3 breach/disclosure communication** (`ActDraftNotification`) queued
for a **named human signature** â it can never auto-apply (the T3 invariant, Â§18.3), and a
signed draft files to the issue tracker for the human to actually send (the agent never sends
regulatory / customer comms itself). Both are grounded (cite the incident's rule + finding +
entity); the draft is explicit its claims are unverified until a human confirms them. The
deeper, open-ended **LLM-driven** SOC triage (forensics, multi-step playbooks) remains future.

**Identity findings now get specific fixes, not generic tickets** (`remediate/identity.go`):
each operate rule maps to a copy-pasteable runbook ticket naming the offending entity â
e.g. a DMARC finding carries the exact `_dmarc.<domain>` TXT record to publish, an
admin-without-MFA finding names the admin + the enforce action. They ride as tier-1
`file_ticket` actions (a ticket is reversible/informational â auto-delivers via the
`Filer`) and carry a machine-readable `remediation_type`+`target` so a future live Apply
has the fix ready. The first live identity *mutation* now exists: **`connector.Okta.Apply`
suspends a stale account** via the Okta user-lifecycle API (`POST
/api/v1/users/{id}/lifecycle/suspend`), reached only after the HITL gate (Â§18.2 inv. 3) and
tested against a fake org (injectable `HTTP` client). It needs the `okta.users.manage` scope
(onboarding scopes are read-only by design), so a real mutation requires an admin to grant
it â until then Okta answers 403 and `Apply` surfaces it as an error (never falsely "done").
**Google Workspace + Microsoft 365 now have the same live suspend path**: `connector.GWorkspace.Apply`
suspends a stale account (Admin SDK `PUT /admin/directory/v1/users/{key}` â `suspended:true`) and
`connector.M365.Apply` disables sign-in (Graph `PATCH /users/{id}` â `accountEnabled:false`), both
reached only after the HITL gate and tested against a fake server (injectable `HTTP`). Each needs
its IdP's write scope (`admin.directory.user` / `User.ReadWrite.All`) â read-only by onboarding
default â so a real mutation requires an admin to grant it; until then the provider answers 403 and
`Apply` surfaces it honestly. The other Okta/GW/M365 `remediation_type`s (oauth_revoke, etc.) remain
honest stubs pending their write path. **The operateâtier-2 wiring closes the loop end to
end** (`remediate.proposeIdentity` + `liveIdentityMutation`): when a remediation has a live,
reversible connector write path for the asset's provider â `account_suspend` on **Okta, Google
Workspace, or Microsoft 365** today â the proposer emits a **tier-2 `ActApplyConfig`** (gated)
instead of a tier-1 ticket, so a
stale-Okta-account finding flows finding â gated action â HITL approve â `connector.Okta.Apply`
suspend â signed ledger. Every other (remediation, provider) pair stays a tier-1 runbook
ticket (no falsely-confident auto-apply) until its connector `Apply` lands â promotion is one
line in `liveIdentityMutation`. The asset's provider is carried in `Asset.Meta["provider"]`
(set by the GWorkspace/M365/Okta connector `Discover`). The full loop is E2E-tested
(`remediate.TestNonTechLoop_StaleAccountGatedThenApprovedSuspends`: queues, does NOT
auto-apply, suspends only after approval).

**M365 OAuth grants are live too** (`operate.M365.fetchGrants`): Microsoft Graph
`oauth2PermissionGrants` (delegated scopes + admin-vs-per-user consent) joined to
`servicePrincipals` (app name + `verifiedPublisher`) â grounded `OAuthGrant`s, so the
critical `oauth-admin-scope` (shadow-admin third-party app) + `oauth-unverified-app`
checks run live for M365. **Google Workspace grants are live too** (`GWorkspace.fetchGrants`
over the Directory `users.tokens` API per active user â per-app grants; `AdminScope` from
admin-directory / cloud-platform scopes). Both best-effort (grant read needs an extra
consent; absent â degrades to no grants, never fails the posture fetch). Google's tokens
API exposes scopes but **not** publisher verification, so Google grants are marked
`Verified` (the `oauth-unverified-app` check stays M365/snapshot â we don't guess).
**Okta grants are live too** (`Okta.accumulateGrants` per active user via
`/users/{id}/grants?expand=scope` â the scope name is inlined; `AdminScope` from `.manage`
/ `okta.roles` scopes; app labels resolved best-effort from `/apps`; `Verified` true, as
Okta has no publisher-verification). **So OAuth-grant detection is live across all three
non-tech IdPs â Google Workspace, Microsoft 365, and Okta** â completing the operate
live-detection trio (users Â· email-auth Â· grants) everywhere.

**Single-box production hardening is in** (the "pure Docker, one box, reliable, but
architected to scale" track). Durable persistence: a dependency-free **SQLite `Store`**
(`store.OpenSQLite`, `modernc.org/sqlite` â no cgo, static binary; WAL, JSON-blob rows)
behind the same `Store` interface and the same table-driven conformance suite as the
memory/file impls â `TSENGINE_PLATFORM_DB=/data/platform.db` (a `.db`/`.sqlite` path) picks
it; a `.json` path still gets the snapshot file store. Async scans: **`internal/jobs`** is
a bounded in-process worker pool (back-pressure â 429) so `POST /v1/rescan` returns `202` +
a pollable `Job` (`GET /v1/jobs/{id}`, tenant-scoped) instead of blocking the request for a
minutes-long scan; `Jobs==nil` falls back to synchronous (test back-compat). Observability:
**`internal/obsv`** installs a structured **slog** default (text, or JSON via
`TSENGINE_LOG_FORMAT=json`; level via `TSENGINE_LOG_LEVEL`) â which also routes the existing
`log.Print` lines â and a Prometheus **`GET /metrics`** (request count/latency,
`tsengine_scan_jobs_inflight`, plus the free Go runtime collectors). A `Middleware` wraps
the platform mux for per-request metrics + an access log (SSE/`/metrics`/`/healthz`
excluded from skew/noise). All three sit behind today's interfaces so the scale-out
successors (Postgres store, durable queue, OTel) swap in without touching call sites.

Remaining is **next-phase breadth/scale, not core-loop gaps**: the identity-mutation `Apply`
write paths are now wired for all three IdPs (Okta suspend, GWorkspace suspend, M365 disable),
each gated on the customer granting its write scope (read-only by onboarding default), the
**open-ended LLM-driven** SOC reasoning (the deterministic
detect/incident backbone now exists in `internal/detect`; what's left is agentic triage/
response beyond the threshold rules), and the infra successors â a **Postgres `Store`** (the
SQLite single-box backend now exists) + a cloud-KMS `secret.Vault` (both behind today's
interfaces).

**Real per-user account auth is now built** (was the deferred "self-serve signup" item).
`internal/authn` hashes passwords with stdlib `crypto/pbkdf2` (PBKDF2-HMAC-SHA256, 600k
iters, per-password salt â no new dependency) and mints random session tokens.
`pkg/platform.User`/`Session` + Store `Put/Get/GetByEmail/ListUsers` and
`Put/Get/DeleteSession` persist them. `internal/platformapi/auth.go` serves
`POST /v1/auth/{signup,login,invite,password}` + `GET /v1/auth/{me,team}` + `POST /v1/auth/logout`.
The `auth` middleware accepts **either** the shared platform token (+`X-Tenant-ID`, for
operator `POST /v1/tenants` / Slack / tests) **or** a user session token â and for a session
the tenant comes FROM the session, so a spoofed `X-Tenant-ID` header cannot cross tenants.
Signup creates a workspace (tenant) + owner; an owner can invite members (one-time temp
password â email-based invites are the next step). **Forced first-login rotation is wired**:
an invited member's account carries `User.MustChangePassword`; while set, the `auth`
middleware blocks every app endpoint with `403 password_change_required` (the auth-mgmt
endpoints â me/logout/password â use `sessionAuth`, so they stay reachable), and
`POST /v1/auth/password` (verify current â set new â clear the flag) unlocks it. So the
owner-issued temp password can't remain the standing credential. Frontend: a top-level
`/change-password` route (outside the `(app)` group to avoid a redirect loop) + the `(app)`
layout redirect on `me.must_change_password`. `cmd/platform` `newID()` is a random hex id
(a restart-resetting counter previously overwrote tenants). Frontend: `/login`
(email+password), `/signup`, `/change-password`, Settings â Team. **Password reset is now built**:
`internal/email` (a `Mailer` interface + `SMTP` impl via `net/smtp` STARTTLS + `Noop`, wired from
`email.FromEnv` over `SMTP_*` env) carries a one-time reset link; `POST /v1/auth/forgot` (public,
no account enumeration, stores only the SHA-256 of the token + a 1h expiry on the `User`, emails the
link, logs it when no SMTP is configured) + `POST /v1/auth/reset` (constant-time token check, set new
password, clear the token + `MustChangePassword`). Frontend: `/forgot-password` + `/reset-password`
+ a "Forgot password?" link on `/login`, proxied via `/api/forgot` + `/api/reset`. The SMTP provider
is the operator-config gate. **Plan tiers are enforced** (`pkg/platform/plan.go` `Entitlements`): Free
is asset-capped + AI-off (no operator LLM spend, the economic gate in `resolveAgentLLM`),
Growth/Enterprise unlock AI; the `/pricing` page (INR, 3 tiers) mirrors it. **Still future:**
email-based member invites (the reset machinery is reusable), OAuth-SSO login, and a billing model.

**The product stack is containerized** (`docker compose up` / `make up`): `docker/platform/
Dockerfile` (the `cmd/platform` server, Go, ~108MB) + `frontend/Dockerfile` (Next.js
`output:"standalone"`, ~105MB) + `docker-compose.yml` (platform :8090 + frontend :3000,
`platform-data` volume, `.env`/`.env.example` for `TSENGINE_SECRET_KEY`). Defaults to
`NO_ENGINE` (operate/identity assets + the whole loop work; tech-asset scanning needs the
sandbox image + the commented Docker-socket mount). Both images build + run + sign-up E2E
verified. The detection **engine** has its own image (`docker/host/Dockerfile`, released to
GHCR by `release.yml`).

**Single-box production deployment is built + hardened** ([docs/production-single-box.md](docs/production-single-box.md)
â threat model + phased plan + runbook): `docker-compose.prod.yml` + `docker/caddy/Caddyfile`
run the whole product, **engine ON**, safely on one box. Hardening: per-scan sandboxes get
resource/PID/file limits + a writable tmpfs by default and opt-in read-only-rootfs/non-root/
isolated-network (`internal/sandbox.Hardening`, `TSENGINE_SANDBOX_*`); the platform reaches
the Docker API through a **docker-socket-proxy** (no raw socket = no host-root on compromise â
live-verified: container/image API allowed, `/info` denied) and spawns sandboxes on a
dedicated network reached by container IP (off the platform/frontend net); a **Caddy TLS edge**
is the only published surface (HTTPS + security headers; raw `:8090`/`:3000` unpublished);
secrets via the Docker-secret `*_FILE` convention; `scripts/backup.sh`/`restore.sh` for the
`platform-data` volume; one-command **`make deploy-prod`** (`scripts/deploy-single-box.sh`,
`--check` dry-run) + `make prod-validate`. Threats T1âT8 each have a shipped mitigation (#259â264).

**Still single-box, not scale-grade** (the multi-machine gaps, each behind an existing seam â
docs/production-single-box.md Â§6): single-node file/SQLite store (Postgres is the `store.Store`
successor), env/file secrets (cloud-KMS is the `secret.Vault` successor), no HA/multi-node
sandbox pool + durable queue, container (not microVM) isolation. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) + [docs/production-single-box.md](docs/production-single-box.md).

**The global kill-switch is built** (agentic-SMB spec OM-3 / TS-5 â the "one human, one pane,
kill-switch" operating-model primitive). `Tenant.AgentsHalted`, toggled by the owner via
`POST /v1/killswitch` (signed into the ledger), makes the platform **fail closed** for a
tenant: `hitl.Desk` refuses every apply (auto + human-approved; the switch beats the verdict,
actions queue) and `runner` pauses scanning. The frontend surfaces it on the single pane â a
Settings toggle (owner-gated) + a persistent halted banner across the app shell. This is the
**Â§18.2 invariant 7**. The design source is the (untracked) `sec_lifecycle_agentic_smb.md` â
the formal RFC-2119 spec for the fractional-autonomous-security-team-for-SMB product; the
implementation's reconciliation against it lives in [docs/personas-and-workflows.md](docs/personas-and-workflows.md)
Â§7. **The Warden's AI-BOM (WRD-1) is built**: `GET /v1/ai-bom` (`internal/platformapi/aibom.go`)
+ a Settings panel inventory what the autonomous agent can touch â every connection, its
granted scopes, and a least-privilege read/write classification (flagging the write-capable,
higher-risk surface) â plus the governance state (kill-switch + gate tier). Grounded in real
`Connection.Scopes`, no secrets. **Per-agent quarantine (WRD-4) + OM-5 fail-closed are also
built**: `POST /v1/connections/{id}/quarantine` sets `ConnQuarantined` (a per-connection
kill-switch â halt one connection's automation, not the whole roster), and the runner now
**skips any asset whose connection isn't `ConnActive`** (`connInactive`, permissive only on
missing data) so a revoked/degraded/quarantined connection is never acted on. **The T3
invariant is now enforced** (`platform.TierIrreversible`=3 + `Action.NeedsHumanSignature()`):
`hitl.Desk.apply` refuses an irreversible action that carries no named human approver
(`ErrNeedsHumanSignature`) â it never executes on `auto`, even if a future break-glass
auto-apply is added for lower tiers. *No flow emits a T3 action yet* (breach-notification /
customer-comms ride the future **A-RSP** incident-response capability), so this is
forward-compatible hardening: a T3 action is safe by construction the moment one is produced.
**With this the agentic-SMB spec is fully reconciled** â every OM/TS/AGT/WRD/ACC requirement
is built or, for A-RSP, explicitly future (see docs/personas-and-workflows.md Â§7).

### 18.4 The consulting top-layer â HITL judgment / legal / accountability

The platform automates detectionâfixâevidence; the **top layer** is the judgment, legal
independence, and named accountability a security/compliance **consultant** otherwise owns â
each built so the engine does the grounded prep and a **named human** makes the call that
can't be automated. Four capabilities, all ledger-signed, all behind the same store + API:

| Capability | Package(s) | What the engine does (grounded) | Where the human is in the loop (HITL) |
|---|---|---|---|
| **Risk register** (vCISO judgment) | `pkg/platform.Risk`, `internal/grc/risk.go`, `internal/platformapi/risks.go`, `/risks` | `CandidateRisks` clusters high+ findings by coarse category (CWEâcat, else tool), cites finding ids, sets a *starting* likelihood/impact. Seeded on-demand (`POST /v1/risks/seed`) AND **automatically after an L2-agent investigation** (cloud-investigate calls `Deps.seedRisks`) â so the agent's proven attack paths land candidate risks on the vCISO desk (agent proposes â named human disposes) | `POST /v1/risks/{id}/decision` â a named owner accepts/mitigates/transfers/avoids residual risk with a rationale; the agent never accepts risk |
| **Audit engagement** (legal attestation) | `pkg/platform.AuditEngagement`/`ControlAttestation`, `internal/grc/audit.go`, `internal/platformapi/audits.go`, `/audits` | seeds the controls-to-attest from the tenant's real posture for the framework | `POST /v1/audits/{id}/attest` â a named **external** auditor renders each control verdict; issue gated on all-attested + named auditor. "Audit-ready, not the audit" |
| **Pentest sign-off** (named accountability) | `internal/pentest.Signoff`, `internal/platformapi/pentest.go`, `/pentest/{id}` | produces the exploitation-proven VAPT report | `POST /v1/pentest/{id}/signoff` â a named human signs; the rendered report carries the signer line |
| **vCISO program** (policies) | `pkg/platform.Policy`/`PolicyAck`, `internal/grc/program.go`, `internal/platformapi/program.go`, `/program` | `StarterPolicies` seeds the standard SOC 2 policy set as drafts (idempotent) | `POST /v1/program/{id}/publish` â a named owner publishes; `â¦/ack` â each member acknowledges |

Invariants: the engine **proposes/seeds**, never **decides/publishes/attests/signs**; every
human act is required-by-API (400 without the named human) and recorded into `pkg/ledger`
(reuses Â§18.2 inv. 4). New store entities follow the 6-place wiring (types Â· Store iface Â·
Memory field+snapshot+orEmpty Â· File Put Â· SQLite table+Put/List Â· conformance isolation
test). Grounding (Â§10) holds: candidate risks cite findings, audit controls come from real
posture, policy templates are industry-standard names (not invented claims about the tenant).

### 18.5 The practitioner layer â who employs the human-in-the-loop (two GTM models, one engine)

The Â§18.4 HITL acts are performed by *a* human; the **practitioner layer** records **who that human
works for** â the only thing that differs between the two product GTM models. One engine serves both:

* `internal` â the tenant's own team (self-serve)
* `msp` â a partner firm's expert (the MSP runs our product; *their* expert does the HITL â the channel model)
* `managed` â our hired expert acting on the tenant's behalf (the founder-ICP managed-service model)

Pieces:

1. **Service model + practitioners of record** (`pkg/platform.Tenant.ServiceModel` +
   `Tenant.Practitioners[]` `{Name,Firm,Credential,Capacity,Email,Scope}`; `internal/platformapi/
   practitioners.go`; Settings "Service model & practitioners" panel). Tenant-scoped, stored on the
   Tenant (no secret), like `Contacts` â **no new store entity**.
2. **Capacity on every HITL artifact** (`practitionerCapacity` resolver matches the acting human
   against the roster by name/email â stamps `Capacity`+`Firm` on `Risk`, `pentest.Signoff`,
   `Policy`, and `ControlAttestation`). Â§10-grounded: unknown actor â `internal`, never guessed. The
   `CapacityBadge` surfaces it on `/risks`, `/pentest`, `/program`, `/audits`.
3. **The cross-tenant practitioner desk** (`internal/practitioner.Queue` + `GET
   /v1/practitioner/queue?practitioner=<email>`). The MSP's / our expert's single queue of every
   pending HITL item across their **assigned** client tenants. **This is an OPERATOR capability gated
   by the platform token (`d.platformAuth`), NOT a tenant session** â it reads ONLY tenants whose
   roster names the practitioner, so **Â§18.2 inv. 2 (tenant isolation) is preserved**: a tenant
   session still cannot cross tenants; only the operator-gated desk aggregates, and only over
   explicitly-assigned tenants (isolation-proof test in `practitioner_queue_test.go`). The
   `/practitioner` console UX needs an operator-auth frontend surface (the tenant app uses tenant
   sessions) â that surface is the documented follow-on; the desk is consumed via the platform token
   today.

4. **The operator console + auth** (`internal/platformapi/operator.go`, `pkg/platform.Operator`/
   `OperatorSession`, frontend `/operator`). A DELIBERATELY SEPARATE auth namespace from the tenant
   `User`/`Session` (own store maps, own `op_token` httpOnly cookie carrying NO tenant header, own
   `operatorAuth` middleware). Operator accounts are platform-token-provisioned (`POST /v1/operator`),
   not self-serve. `GET /v1/operator/queue` scopes to the authenticated operator's own book. So a
   tenant session can never reach an operator endpoint and vice-versa â isolation untouched.

5. **Act-on-behalf** (`internal/platformapi/operator_act.go`). The operator doesn't just VIEW the
   desk â they MAKE the call. All four top-layer HITL acts are dischargeable from the cross-tenant
   console: `POST /v1/operator/tenants/{tenant}/risks/{id}/decision` Â· `â¦/policies/{id}/publish` Â·
   `â¦/pentests/{id}/signoff` Â· `â¦/audits/{id}/attest`. **Isolation is the SAME rule as the queue**:
   every act is gated on `matchPractitioner` (the operator must be a practitioner of record on that
   tenant's roster) â else **403** and the tenant is never mutated (Â§18.2 inv. 2 holds; an operator
   acts only on their own book). The operator is the **named human** for the act; capacity/firm come
   from their **roster record** (grounded Â§10, not a typed string), and it's ledger-signed exactly
   like the tenant path. Each act shares ONE helper with its tenant-session handler
   (`applyRiskDecision`/`applyPolicyPublish`/`applyPentestSignoff`/`applyControlAttestation`) â the two
   paths differ ONLY in how capacity resolves (typed name vs roster record), so validation + gate +
   ledger are identical. `practitioner.Pending.ItemID` (+ `Controls` for audits) carries the real
   entity id so the desk can target a specific item. Isolation-proof tests in `operator_act_test.go`.
