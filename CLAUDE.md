# CLAUDE.md — tsengine architecture invariants

This file is loaded into every Claude turn working on this repo.
**Read this before proposing architectural changes.**

When you change something architectural, **update this file in the same PR**
so future turns see the new layout.

---

## 1. Repository identity

`tsengine` is a Go-native two-layer security + compliance engine. The
design lineage is strix (Python, `ClatTribe/strix`) — strix's architecture
docs are the source for the principles below — but tsengine shares **no
code** with strix. Fresh build.

Paired with `webappsec` (the SaaS wrapper that consumes tsengine output,
persists findings, renders the dashboard, and exposes the tool-replay UI
to security engineers).

**Direct push to `main` is blocked — always ship via PR.**

---

## 2. The L1 / L2 layer model — read before any architectural change

tsengine has **two layers serving three audiences**:

### 2.1 L1 — complete OSS vuln discovery for security + compliance

- **Audience**: security engineers + compliance auditors (peers, not subordinate)
- **Artifact**: `vulnerabilities.json` (the dashboard contract — §6) + signed evidence bundle
- **"Best-in-class" means**: per-tool recall equals the standalone OSS tool. If we drop findings the OSS tool would have found, L1 has failed regardless of what L2 does next.
- **What runs here**:
  - All OSS scanners (anchor tier always-fire; registry tier on-demand — §4)
  - L1.5 enrichment hooks (FP filter, surface_priority, exploitability, corroborator)
  - Threat intel enrichment at finding emission (§7)
  - Compliance control mapping at finding emission (§8)

### 2.2 L2 — AI security and compliance engineer

- **Audience**: developers, PMs, non-security teams who can't triage raw scanner output
- **Artifact**: prioritized findings, chain narrative, remediation patches, plain-English explanations, compliance evidence packs
- **What runs here**: LLM Lead agent over a ≤12-tool catalog tied to OODA (§2.6)
- L2 **cannot translate findings L1 didn't surface.** L2 is the translator, not the detector.

### 2.3 The 2×2

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

* No in-house detection scanners — §13 codifies this. The L1 layer **only** wraps OSS tools, because that's the only way to be "best-in-class" at detection.
* L1.5 hooks **add information for L2's translation job**, not mutate the L1 dashboard the security team sees. The L1 dashboard renders pre-L1.5 findings (`findings_raw`); L2's developer-facing output renders post-L1.5 findings (`findings_enriched`). Both ship.
* L1.5 demotions, dismissals, and merges must be **logged + recoverable** so the L1 audience can audit them. `l15_audit_log[]` in `vulnerabilities.json` is this audit log; webappsec exposes it to the security engineer for override.

### 2.6 The ≤12-tool cap (Invariant L2-CAP)

> For every asset type, the number of tools visible to the L2 Lead at any point in the scan is **≤ 12**. Past ~12, LLM tool-use accuracy degrades steeply.

The cap counts **what the LLM sees in the system prompt** — the minimal CORE tools + the per-asset specialist set. It does NOT count:

* Tools that fire deterministically in the L1 prepass (the LLM never sees them — they're always-on coverage)
* Tools that auto-fire inside `finish_scan` (compliance evidence, remediation plan — terminal artifacts)
* Tools reachable via the registry tier — those reach the LLM only via `dispatch_l2_probe(tool=...)`, not as direct catalog slots

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

Reasoning over data already in context, reformatting, and decisions encoded inline in the response are **not** tools — those happen in the LLM's response text. Reasoning *commits* (chain narrative, customer priority) ride as parameters on `create_vulnerability_report`.

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

The `cloud_account` asset is what makes tsengine usable for SOC2/PCI compliance teams. Without it, the engine only covers infrastructure surfaces. The `mobile_application` asset (single-stage, like `repository`: the bundle *is* the surface) covers the mobile-app-team audience competitors carve out as a separate offering — anchored on mobsfscan (mobile SAST) + gitleaks (hardcoded secrets) + trivy fs (bundled-dep SCA), all already in the sandbox image, so it adds reach without a new sandbox tool. Count invariant: `pkg/types.AllAssetTypes()` + its test pin the count (now 8).

For the per-asset anchor + registry tool lists, filter rules, and bench targets, see [arch.md](arch.md).

---

## 4. The anchor + registry tier model

Every asset's L1 catalog has **two tiers**:

### 4.1 Anchor tier
Tools that fire **deterministically on every scan** of the asset. Always-on coverage; the LLM never has to choose. Curated for: high recall, low false-positive, low cost, low destructive risk. CI-capped at ~12 per asset.

### 4.2 Registry tier
Tools that are **wrapped and available on-demand** but don't fire by default. Surfaced via the **tool-replay API** (§9) when:

* The security engineer drills into a finding in webappsec and asks for deeper investigation
* The L2 LLM dispatches via `dispatch_l2_probe(tool=..., args=...)`
* A scan config explicitly opts in via `scan.registry_opt_in=[...]`

### 4.3 Why two tiers

* The security engineer needs to "dig deeper" after seeing an anchor finding — without restarting the scan
* The "complete OSS coverage" promise can't be delivered with anchors alone; some tools are too noisy / slow / overlapping to fire by default but valuable on-demand
* The L2 LLM gets a small catalog (≤12) but can reach into the registry through one tool (`dispatch_l2_probe`) when it needs depth

Per-asset anchor + registry lists live in [arch.md](arch.md).

---

## 5. The detection layer model (L0 → L3)

| Layer | What runs | Where | Refresh cadence |
|---|---|---|---|
| **L0** | OSS signature corpora — nuclei templates, semgrep packs, sqlmap payloads, KEV list, EPSS scores, trivy DB, compliance control corpus | Sandbox | Cron-paged + delta-verified against L1 benches |
| **L1** | Deterministic anchor tools per asset (§3) | Sandbox | Per-scan |
| **L1.5** | Host-side enrichment hooks — FP filter, surface_priority, exploitability, corroborator, threat_intel.enrich, compliance.map, post_emit_verifier | Host | Per-finding |
| **L2** | LLM Lead — agent_loop with ≤12-tool catalog | Host drives sandbox tool calls | Per-scan, model-paced |
| **L2.5** | Verifier — re-fire L1 tool via tool-replay with benign-control payload to upgrade `pattern_match` → `verified` | Mixed | Per finding flagged for verification |
| **L3** | Portfolio-level (cross-scan dedup, multi-target correlation) | Host | Future |

### 5.1 The L1 recon → fan-out pipeline (deterministic, not LLM-driven)

Recon-capable assets run a **two-stage L1 flow** in the orchestrator —
discover the surface, then fan detection tools across it. Four assets are
recon→fan-out today: **web** (katana crawl), **ip_address** (naabu port
discovery → per-port nuclei routing), **domain** (subfinder+amass+crt.sh
enum → child-asset pivot), **api** (openapi_spec_ingest → per-method
routing). repository + container_image stay single-stage (the tree / image
is the whole surface). This is the L1 prepass, entirely deterministic; the
L2 LLM never drives it (strix's "model ignored the recon directive" class
of bug, §10, is structurally impossible here).

The contract — invariants, not implementation detail:

1. **Recon is a hard stage, not a prompt.** A `ReconHandler` exposes
   `Recon()`; if it returns tools they run first (`katana` crawls *in the
   sandbox*). `Result.DiscoveredURLs` → `CollectSurface` (dedupe,
   target-always-included, capped by `TSENGINE_FANOUT_MAX_URLS`=200). No
   recon tools → graceful fallback to single-target `PlanAnchors`.
2. **Fan-out shape is the tool's, not uniform.** `PlanFanout` decides:
   list-mode tools (`nuclei`, `httpx`) run **once** over the whole surface
   (`-list`); injection tools (`dalfox`, `sqlmap`) run **per-URL on
   param-bearing URLs only**. Running list-mode tools per-URL is the WAVSEP
   2h+ trap — don't.
3. **Surface filtration runs before fan-out.** Scope → static-asset drop →
   destructive-path drop → URL-shape dedup (`/items/1`≡`/items/N`). The cap
   + filtration are the guard against strix's unbounded fan-out (Q5.34l).
4. **Dispatch is wave-ordered, never flat-parallel when state-coupled.**
   `partitionWaves` (`internal/orchestrator/deps.go`) topo-sorts by a static
   dependency table: concurrent within a wave, sequential across. An
   all-independent batch collapses to one wave (zero overhead). The
   classifier landed **before** any state-coupled tool existed, so strix's
   Q4.2 unguarded-parallel-auth race is impossible by construction. When you
   add a tool that reads another's side-effect, **add the edge to
   `toolDependencies`** — do not rely on dispatch order.
5. **Authenticated scan = a `seed_auth` tool in wave 0.** When `Asset.Auth`
   is set, `PlanFanout` prepends a `seed_auth` dispatch (passthrough cookie,
   or form-login → captured `Set-Cookie`). The authed detectors depend on it
   in the table → it runs first; `executeWaves` threads the captured session
   (`Result.CapturedSession` — crosses the sandbox boundary but is **never**
   written to `vulnerabilities.json`) into the detectors' `args["cookie"]`,
   never clobbering an explicit cookie. Auth failure → no session →
   unauthenticated scan (graceful, never crashes).
6. **Recon dispatch shape is the handler's (`ReconPlanner`).** A handler may
   implement `PlanRecon(target)` to shape its recon dispatches (crawl depth,
   spec URL, bare apex) instead of the generic single-arg mapping — e.g. web
   crawls at depth 3 (depth 2 can't reach a real app's surface), domain
   passes the bare apex, api passes the base URL. Mirrors `PlanFanout`.

### 5.2 Cross-asset invariants (the strix-mistake guardrails)

These hold for **every** asset, recon or single-stage:

1. **Loopback rewrite at the host/sandbox boundary (C2).** The sandbox
   client rewrites loopback hosts (`localhost`, `127.0.0.1`, `0.0.0.0`) in
   URL/host args (`target`/`targets`/`login_url`/`url`/`urls`) to
   `host.docker.internal`, and the runtime always adds `--add-host
   host.docker.internal:host-gateway`. Without this, network probes hit the
   sandbox itself — strix watched ip_address recall collapse 1.0→0.0.
2. **Single timeout source of truth + opt-in per-tool cap (C3).** The host
   scan `--timeout` (propagated via request-ctx cancellation into the
   sandbox) is the only deadline — there is **no** fixed host client
   timeout, so strix's "timeout split-brain" can't occur.
   `TSENGINE_TOOL_TIMEOUT` is an opt-in per-tool wall-clock cap so one
   runaway tool can't starve the scan.
3. **Tool arg contracts are validated (C4).** Each wrapper declares
   `tool.ArgSpec.KnownArgs`; a CI test (`internal/asset/argcontract`)
   asserts every key a Handler dispatches is recognized. A mis-wired arg is
   a **loud build failure**, not strix's silent "unexpected keyword
   argument" recall drop.
4. **Per-asset routing table.** "Run the whole corpus everywhere" is the
   universal perf/noise trap — solved per asset: web per-URL, api per-method
   (`classifyOp`), ip per-port nuclei tags (~50× speedup), container
   base-layer skip, domain child-triage. Add the routing dimension when you
   add an asset's fan-out.
5. **Child-asset pivot is a first-class artifact (C5).** A handler may
   implement `ChildAssetExtractor.ChildAssets(findings)` → `Scan.ChildAssets`
   (domain subdomains → web/ip child targets) so webappsec spawns child
   scans instead of re-enumerating (strix's re-enumeration trap).
6. **Wrap OSS; never build in-house detectors (§13).** strix rebuilt IaC,
   CSPM, SCA, and taint analysis in-house and reverted each to OSS. Every
   asset wave here wraps an OSS tool. Where no OSS exists (API BOLA/BFLA
   authz logic), it's a **documented ADR/backlog item**, never a silent
   in-house build.

### 5.3 The escalation stage — conditional depth (deterministic, L1)

After detection (anchors/fan-out), a handler may run a third stage:
inspect its own findings + surface and dispatch **deep** tools ONLY where a
signal warrants. This is "in-depth yet efficient" — expensive tools fire
targeted, never blanket.

The L1/L2 split is the load-bearing decision: this engine handles the
**known** signal→tool mappings *deterministically* (evidence-grounded, §10, zero
token cost). The open-ended "what's interesting here, what should I try"
reasoning stays **L2** (`dispatch_l2_probe`, Phase 6). Do not move
deterministic escalation into L2, and do not encode open-ended reasoning as
escalation triggers.

Invariants:

1. **Signal-gated, not blanket.** A handler implements
   `asset.EscalationPlanner.PlanEscalation(target, surface, findings)`. It
   uses a per-asset `Trigger` table (`MatchFinding`/`MatchSurface` →
   args) via `EvalTriggers`, which dedups by (tool, target+service+port).
   Depth tools never fire without a matching signal.
2. **Bounded.** The dispatch set is capped by `TSENGINE_ESCALATION_MAX`
   (default 50 — the cost twin of `TSENGINE_FANOUT_MAX_URLS`) and each tool
   by `TSENGINE_TOOL_TIMEOUT`. A signal flood can't turn "depth" into
   "unbounded".
3. **Provenance.** Escalated dispatches carry `Dispatch.EscalatedFrom` (the
   trigger name) for logging/audit. Detection + escalation findings are
   normalized together.
4. **Current trigger tables** (signal → depth tool):
   - web: param URL → nuclei DAST/OAST (blind, interactsh); login URL →
     nuclei default-logins; thin surface → ffuf content discovery;
     WordPress surface (wp-login/wp-content/xmlrpc) → wpscan (CMS-specialist
     DAST — vulnerable plugins/themes, user enum, exposed wp-config).
   - ip: open auth port (22/3306/…) → hydra default-cred check.
   - api: spec ingested → kiterunner (shadow routes); `/graphql` → inql.
   - repository: semgrep injection finding → CodeQL on that language
     (taint); mobile-file finding → mobsfscan.
   Breadth tools that are unconditional (dnstwist, cosign) are NOT
   escalation — they're fan-out/anchor.

---

## 6. The L1 dashboard contract — `vulnerabilities.json`

The webappsec handoff. **This schema is load-bearing — every wrapper written before it's locked accrues drift.** Define and freeze it in Phase 0.

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

**Cloud-to-Code** (`internal/cloudtocode`, `tsengine cloud-to-code --in <cloud-scan> --iac <tf-dir>`): `code_provenance` traces a runtime cloud finding (prowler) back to the Terraform resource + `file:line` that provisioned it. A dependency-free `.tf` resource indexer + a grounded matcher — a link requires BOTH a service↔TF-type nexus (the prowler check-id prefix → the TF types that provision it) AND a concrete shared identifier (physical name / ARN tail / normalized logical name). No matched token → no link (never guessed, §10). Correlation glue — adds provenance, never findings (§13 holds). Residual: platform-runner auto-wiring (annotate a cloud scan with the tenant's connected-repo IaC tree).

---

## 7. Threat intel enrichment at L1

CVE/KEV/EPSS lookup is **L1 work, not only L2**. Compliance teams need KEV listing immediately (SLA clock starts); security teams need EPSS for patch priority. Both consume the dashboard, not the LLM's translation.

Hook: `threat_intel.enrich` fires in the L1.5 hook chain (§11) for every finding with a CVE. Adds:

* CVSS v3.1 base score
* KEV listing (Y/N + `date_added`)
* EPSS score + percentile + `as_of` date
* Vendor advisory URLs
* Known exploit availability (Metasploit, ExploitDB, GitHub PoCs)

**Sourced from authoritative OSINT feeds, not hand-curated.** `tsengine corpus refresh` (`internal/corpus/threatintel`) ingests **CISA KEV** (the actively-exploited signal) + **FIRST.org EPSS** (~336k CVEs, the patch-priority signal) — both free, no API key — into a versioned on-disk corpus (`threat_intel.json` + sidecar manifest). The hook loads it when `TSENGINE_THREAT_INTEL_CORPUS` points at it, else falls back to the small embedded snapshot (the checked-in default). The corpus dir is gitignored; refresh runs **out of band** (the L0 cron, §5), and each scan **pins the manifest version** into `vulnerabilities.json`'s `corpus` block — so it's OSINT-fresh yet pinned for the evidence pack (§10), NOT a live per-query API call. Scope today is KEV+EPSS; CVSS (NVD) + exploit-refs (ExploitDB/Metasploit/nuclei) are the documented next sources.

L2 retains a separate `query_threat_intel` tool for the LLM to look up CVEs that aren't in current findings (chain reasoning across related CVEs). The two are complementary: L1.5 hook annotates emitted findings; L2 tool serves on-demand lookups during reasoning.

---

## 8. Compliance control mapping at L1

Every finding emitted at L1 carries a compliance annotation. Mapping is **annotation, not gate** — L1 emits the technical finding regardless of whether it maps to a control; the mapping just records which controls it affects.

Frameworks supported (14 — keys defined once in `grc.Frameworks`, mirrored by `pkg/types.Compliance`, the `compliance.json` crosswalk, and `frontend/lib/frameworks.ts`):

* **Security & trust**: SOC 2 (Trust Services Criteria), CIS Controls v8, NIST CSF 2.0, ISO 27001:2022
* **Sector & payments**: PCI-DSS v4.0, HIPAA Security Rule, SOX (IT general controls)
* **Privacy**: EU GDPR, ISO 27701:2019, CCPA/CPRA, India DPDP Act 2023
* **Government**: NIST SP 800-53 r5, NIST SP 800-171 r2, FedRAMP Moderate

A finding maps to a framework **only where the crosswalk has a real control nexus** (grounding §10) — e.g. an injection CWE cites NIST SI-10 and GDPR Art. 32; a data-exposure CWE additionally cites CCPA §1798.150 and SOX access-controls; a memory-safety CWE does not. Adding a framework is one entry in each of the four mirrors above; adding a control mapping is one key in `compliance.json`.

Hook: `compliance.map` fires in the L1.5 hook chain. Sourced from `compliance_corpus/` (versioned YAML), refreshed on cron. Same per-scan pinning as threat intel.

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

**Four emission paths feed the framework set** (all grounded, all annotation-only) — keep them in sync when adding a framework or control:

1. **CWE crosswalk** — `internal/tracer/hooks/data/compliance.json` (the `compliance.map` hook) maps a finding's CWE → controls. Covers appsec/SAST/SCA findings.
2. **Identity findings** — `internal/operate/operate.go` annotates each check inline (MFA gaps, OAuth grants, email-auth, stale/over-privileged accounts) — the non-tech / IdP posture.
3. **Cloud attack-paths** — `internal/cloudengine/compliance.go` (`pathCompliance`) maps an attack-path's characteristics (internet exposure, sensitive-data access, privilege/privesc, lateral movement) → controls.
4. **SaaS posture (SSPM)** — `internal/sspm` annotates each SaaS-config check inline (GitHub org: 2FA enforcement, repo perms, secret scanning, third-party apps, webhooks; Slack: 2FA/SSO, app governance, public sharing, guests, admin sprawl; Atlassian/Zoom/Salesforce next) — the SaaS-configuration posture, sibling to `operate`. Snapshot-driven, LLM-free, grounded (a hardened app yields zero findings). See ADR 0004.

So a connected repo, Workspace/M365/Okta, cloud account, *or* SaaS app (GitHub org) each contribute evidence to the full 14-framework set, not just the original six. A control maps only where a real nexus exists for that path (grounding §10).

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
→ { "replay_id": "uuid", "findings": [...] }
```

Replay output appends to the original scan's `findings_raw` + `findings_enriched` with `discovery_method.replay_of: <replay_id>`. Audit-trail preserved.

Required for two use cases:

1. Security engineer in webappsec UI clicks "investigate" on a finding → invokes nuclei with custom template, sqlmap with `--tamper=...`, etc.
2. L2 LLM calls `dispatch_l2_probe(tool=..., args=...)` → routes through the same handler

The L2 path doesn't get a separate codepath — `dispatch_l2_probe` is a thin wrapper over `/replay`.

---

## 10. Evidence grounding (the LLM determines issues; tools back every claim)

> **Process-reproducibility is NOT an invariant here — it was removed.** The old
> "reproducibility invariant" (deterministic tool args, N=5 output equality, "any
> nondeterminism breaks the gate") pushed the engine toward a fixed deterministic
> spine with the LLM bolted on as a translator. That is the wrong shape. The AI
> security engineer is an **LLM agent that uses deterministic tools to access and
> assess resources and determine issues** (the VulnAgent model). The *reasoning* —
> which resources matter, how they chain, the blast radius, what to fix — is the
> LLM's job and is allowed to be non-deterministic.

What we require instead is **evidence grounding** — the LLM never asserts a fact it
could have *queried*, and never records an issue no tool supports:

| Rule | Mechanism |
|---|---|
| Every recorded issue cites tool evidence | A finding references the `resolve_access` / `find_paths` / prowler result that backs it. The LLM cannot record a vulnerability no tool supports — the anti-hallucination guard (VulnAgent's "no LLM hallucinations in syntax checking"). |
| Effective-permission claims come from the evaluator, never the model | "Can X do Y on Z?" is answered by `cloudiam.Authorize` (identity ∧ boundary ∧ SCP ∧ resource-policy ∧ conditions), not the LLM's recollection. |
| Proposed fixes are verified before delivery | A remediation is re-checked through `cloudiam.Authorize` (does it cut the path?) and, for IaC, compiled (`terraform plan`) before a PR/ticket opens. |
| Mutations are human-gated (HITL) | The agent opens a PR/ticket and pauses for a human approval; its own cloud access stays read-only (`cloudsafety.Guard` + scoped STS). |
| Pinned context for the evidence pack | The inventory `snapshot_hash`, `corpus.*`, and `sandbox_image_digest` are recorded so an auditor can see exactly what state a finding was assessed against, and re-run the finding's evidence predicate against it. |
| Signed attestation | `attestation` block (SHA-256 of canonical JSON + ed25519) covers `snapshot_hash + findings + evidence`. Tamper-evident — it attests the *evidence*, never "the process was deterministic." |

So the compliance value (auditable, signed, pinned-context evidence) is kept; the
process-determinism mandate is gone. The deterministic components (`cloudiam`,
`cloudgraph`, the attack-path enumerator) are **tools the agent calls**, not the
agent itself.

---

## 11. The L1.5 hook chain — order matters

When the host tracer's `Add(finding)` is called, hooks fire in this order. Each can mutate or drop the finding:

```
1. pre_emission_fp_filter      → drops planted-decoy shapes, surfaces in l15_audit_log
2. fp_filter.demote            → bumps severity per rule
3. surface_priority.annotate   → annotates surface_priority block
4. exploitability.annotate     → annotates exploitability block + may bump severity
5. corroborator_ledger.check   → cross-source agreement → attaches corroborated_by[]
6. threat_intel.enrich         → CVSS/KEV/EPSS/advisories for CVE-bearing findings (§7)
7. compliance.map              → SOC2/PCI/HIPAA/CIS/NIST control annotation (§8)
8. post_emit_verifier          → re-fires via tool-replay to upgrade pattern_match → verified (inert until L2.5)
9. cross_tool_merge            → cross-tool dedup
10. confidence                 → sets verification_status (pattern_match → corroborated when ≥1 independent tool agrees) + a 0–1 confidence scalar (per-tool base bumped by corroboration). Runs last so it sees the merged set (§7-style quality signal, strix parity)
11. tracer.Append              → persists to findings_enriched
```

`findings_raw` is captured **before** hook 1 — that's what the security engineer reads. `findings_enriched` is the post-hook view. Both ship.

If you add a new hook, **append it to this list in CLAUDE.md** so the order stays documented.

---

## 12. The host vs sandbox boundary — CRITICAL

**The part to get right from day 0.**

### 12.1 Two execution contexts

* **Host process** — `cmd/tsengine` Go binary. Orchestrates. Has no security tool binaries (by design).
* **Sandbox container** — `tsengine/sandbox:<digest>` Docker image. Has every OSS tool baked in. Runs `cmd/tool-server` as PID 1 exposing HTTP on a per-scan port.

### 12.2 The execution adapter

| File | Role |
|---|---|
| `internal/sandbox/client.go` | Host-side HTTP client → tool-server. Bearer-token auth from sandbox spawn |
| `cmd/tool-server/main.go` | Sandbox-side HTTP API. Receives POST `/execute`, dispatches to registered tool |
| `internal/tool/registry.go` | Global `Tool` registry (one per OSS tool wrapper). Each `Tool` declares `SandboxExecution() bool` |
| `internal/sandbox/runtime.go` | Container lifecycle. `Spawn(image, scan_id)` returns `SandboxInfo{port, token, digest}` |

### 12.3 The `Tool` interface — sandbox flag

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
2. If true → POST `/execute` to sandbox tool-server
3. Tool-server resolves the tool from its local registry, calls `Run`
4. The actual subprocess (or library call) fires **in the sandbox container**
5. Result returned via HTTP

### 12.4 Findings sidecar — sandbox tool → host tracer

Tools that call `tracer.Add(finding)` from inside their body would write to the **sandbox-side tracer** (hookless — L1.5 chain lives on host). The sidecar bridges:

```
sandbox tool calls tracer.Add(finding)
   ↓ (writes to sandbox tracer)
tool-server snapshots tracer diff post-call
   ↓ injects findings into ToolResult.SandboxEmittedFindings
[HTTP response]
host internal/sandbox.Client.Execute()
   ↓ extracts SandboxEmittedFindings
   ↓ host_tracer.Add(...)            ← L1.5 hooks fire HERE
```

The sidecar key is stripped from the returned `ToolResult` before callers see it.

The propagation is best-effort — any failure during re-emission is logged + swallowed; it never crashes the execute path.

### 12.5 What's where

| Concern | Host | Sandbox |
|---|---|---|
| `cmd/tsengine` CLI | ✓ | |
| Orchestrator (`internal/orchestrator`) | ✓ | |
| L1.5 hook chain | ✓ | |
| `internal/tool/registry` | ✓ (host view: dispatch decisions) | ✓ (sandbox view: executes tools) |
| OSS tool binaries (nuclei, sqlmap, semgrep, trivy, prowler, ...) | | ✓ |
| HTTP client to tool-server | ✓ | |
| `cmd/tool-server` HTTP API | | ✓ |
| Findings store (host_tracer) | ✓ (with hooks) | ✓ (hookless; sidecar-shipped to host) |
| Workflow state singleton | ✓ | (separate sandbox-side; not propagated) |

---

## 13. No new in-house detection engines

tsengine is **an orchestrator over community-maintained OSS security tools**, not a vulnerability-detection company.

When adding a new vulnerability category:

1. Identify the leading OSS tool (nuclei templates first, then specialized)
2. Add a wrapper under `internal/tool/<tool>/`
3. Register via `tool.Register()` with `SandboxExecution: true`
4. Add to the appropriate asset's anchor or registry tier (§3, §4) by editing the asset module under `internal/asset/<asset>/`

In-house code is reserved for orchestration logic only:

* Asset orchestrators (`internal/asset/<asset>/`)
* L1.5 enrichment hooks (`internal/tracer/hooks/`)
* L2 reasoning glue when L2 ships — chain narrative, customer prioritization (LLM does the reasoning, host commits via tool parameters)

**Adding a new in-house `scan_*` detection scanner requires an explicit architectural ADR** explaining why the leading OSS tool doesn't suffice. Default is no.

### 13.1 SMB per-asset parity packages (ADR 0010)

To be THE SMB product per asset (coverage/depth + FP/FN accuracy vs the SMB category leader),
six deterministic, offline-tested cores were added — each closes a named gap, each pairs with an
honest credential/sandbox gate for live execution (full design + per-asset plan:
[docs/adr/0010-smb-per-asset-parity.md](docs/adr/0010-smb-per-asset-parity.md)):

| Package | Asset · gap (vs leader) | What it is |
|---|---|---|
| `internal/apiauthz` | **api** · BOLA/BFLA authz (vs Akto) | The §13 **no-OSS exception** (authz is business logic): a differential test — replay the victim's request as the attacker; `Evaluate` flags a bypass only on a proven 2xx-with-victim-data (BOLA) / undenied privileged call (BFLA), so a hit is `verification: verified`. Live prober gated (active + consent). |
| `internal/prbot` | **repository** · PR-inline review bot (vs Aikido/Snyk) | `Build(findings, changedFiles, blockAt)` → inline comments **only on PR-changed lines** + a check-run `success/neutral/failure`. Live GitHub post gated on the App PR scope. |
| `internal/webauth` | **web** · authenticated-scan reliability (vs Probely/Detectify) | `LoginFlow{form/token/recorded}` + `ValidateSession` ("am I authed?") + `IsLoginWall` ("session expired → re-auth") — the FN guard against silently scanning logged-out. Live replay gated (sandbox seed_auth). |
| `internal/registrywatch` | **container** · scan-on-push (vs Aikido/Snyk) | `Reconcile(current, seen)` digest-diff → scan only new/re-pushed images. Live registry listing gated (connector). |
| `internal/identitythreat` | **identity** · real-time ITDR (vs Nudge/Push) | `Detect(events)` rules: impossible_travel, privileged_grant, mfa_removed, password_spray — LLM-free, grounded. Live IdP-audit ingestion gated. |
| `internal/shadowit` | **SaaS posture** · shadow-IT discovery (vs Nudge/Wing) | `Inventory`/`Summarize` → SaaS-app inventory + portfolio summary; **wired live** via `operate.SaaSInventory(ws)` over the existing cross-IdP OAuth grants (no shadow-IT verdict without consent data — honest). |

cloud_account's parity is the prior **ADR 0009** campaign (DSPM/CWPP/CIS-scoreboard/multi-cloud/
remediation). These cores feed the same unified-issues / auto-triage / consensus / grc-hitl
machinery; the per-asset live wiring + UX surfaces are the in-progress follow-on.

**Live wiring shipped so far** (each core's gated half is stated honestly):
- **SaaS posture** — fully end-to-end: `operate.SaaSInventory(ws)` → `GET /v1/saas-apps` (inventory
  + portfolio summary) → the `/saas-apps` frontend discovery page. Over the already-persisted
  cross-IdP OAuth grants; no shadow-IT verdict without consent data.
- **identity** — live via `POST /v1/identity/events`: an IdP-audit event stream → `identitythreat.Detect`
  → findings stored in the same store (flow through issues/incidents/grc). The IdP-audit connector is the gate.
- **container** — `POST /v1/registry/reconcile`: a connector posts current images + last-seen digests →
  `registrywatch.Reconcile` → the scan-on-push plan (stateless; the connector runs the sandbox scan).
- **repository** — `prbot.Submit` builds the GitHub PR-review + merge-gating check-run; the live POST is
  gated on the GitHub App PR-write scope. **cloud** — `connector.AWS.Apply` S3 block-public-access is now a
  **live, SDK-backed write path**: `internal/connector/awsremediate.S3Writer` (aws-sdk-go-v2 — the project's
  one cloud SDK, isolated in its own package so the core `connector` stays SDK-free) assumes a scoped
  cross-account WRITE role via STS and calls `PutPublicAccessBlock` (all four flags). Wired in `cmd/platform`
  only when `AWS_REMEDIATION_ROLE_ARN` (or `AWS_REMEDIATION_ENABLED=1`) is set — else `Apply` stays the honest
  stub; reached only after the HITL gate (§18.2 inv. 3). **GCP** has the parallel live path:
  `internal/connector/gcpremediate.GCSWriter` (cloud.google.com/go storage SDK, its own package) impersonates a
  scoped write SA and enforces GCS **Public Access Prevention** on a bucket; wired when
  `GCP_REMEDIATION_IMPERSONATE_SA` (or `GCP_REMEDIATION_ENABLED=1`) is set. The proposer
  (`remediate.liveCloudMutation`) emits `s3_block_public_access` (AWS) / `gcs_public_access_prevention` (GCP) /
  `azure_storage_disable_public_access` (Azure) on a public-bucket/storage finding. **Azure** completes the
  trio: `internal/connector/azremediate.StorageWriter` (azure-sdk-for-go armstorage, its own package) sets
  `AllowBlobPublicAccess=false` on a storage account via the platform's service principal
  (DefaultAzureCredential, scoped to the connection's subscription); wired when `AZURE_REMEDIATION_ENABLED=1`.
  So all three clouds now have a live, HITL-gated, SDK-backed public-storage remediation; each SDK is isolated
  in its own `*remediate` package so the core `connector` stays SDK-free. **api/web** — apiauthz/webauth live
  execution is active testing → behind the explicit-consent + sandbox gate.

**Config surfaces (the per-asset setup half, end-to-end UX + API)** — each stores its config + drives the
core; the live *execution* stays each core's gated half:
- **web** — `POST /v1/assets/{id}/login-flow` + the `/assets` "Authenticated scanning" modal: stores a
  `webauth.LoginFlow` (validated) so the scanner replays + validates the session each scan (the FN guard).
- **api** — `POST /v1/assets/{id}/authz-test` + the `/assets` "BOLA/BFLA test" modal (two identities +
  operations editor): stores an `apiauthz.TestConfig` (validated) for the differential authz test.
- **repository** — `platform.PRBotPolicy` on the Tenant via `GET/PUT /v1/settings/pr-bot` + the Settings
  "Pull-request review" panel (enable + merge-gating severity floor; `github_connected` honesty flag).
- **CREDENTIAL SEALING (§18.2 inv. 6)** — the login-flow + authz-test configs carry secrets (passwords /
  tokens / auth headers), so the setters **seal the config blob via `d.Vault`** before it touches the store
  (`Asset.Meta["login_flow"]`/`["authz_test"]` hold a sealed ref, never plaintext); no vault → the setter
  refuses (400). Each configured asset row shows a reconfigure badge (rotate creds → overwrite). The
  PR-bot policy carries no secret, so it is stored plain.

---

## 14. Benchmark framework

Per-asset recall vs. neutral competitor leaderboards where possible:

| Asset | Bench harness | Headline metric | External comparison |
|---|---|---|---|
| web_application | `bench/wavsep` | Per-class Youden | Acunetix 87%, Netsparker 87%, Burp 78%, ZAP 56% (Shay Chen WAVSEP) |
| repository (SAST) | `bench/owasp_benchmark` | Per-CWE Youden | Veracode 51%, Checkmarx 47%, Fortify 35%, SonarQube 6% (OWASP Benchmark v1.2) |
| api | `bench/api_fixtures` (VAmPI + crAPI) | Must-find recall | None public — internal only |
| repository (SCA) | `bench/sca_lockfiles` | Must-find CVE recall | Snyk/Dependabot self-published |
| container_image | `bench/container_cves` | Must-find CVE recall | Trivy/Snyk/Anchore self-published |
| ip_address | `bench/ip_services` | Must-find recall | Tenable/Qualys — no scorecard |
| domain | `bench/recon_breadth` | Subdomain discovery rate | subfinder/amass published |
| cloud_account | `bench/cloud_baseline` | CIS recall vs. mock AWS account | Prowler/scout-suite self-published |
| cloud_account (offline) | `tsbench cloud-baseline` (`internal/cloudbench`) | CIS-control recall over a fixture account, prowler-only vs. tsengine (engine+DSPM/CWPP lift) — laptop/CI, no sandbox | Prowler/Scout (no neutral baseline exists) |
| L1.5 ablation | (any L1 bench) + `TSENGINE_L15_DISABLED=1` | Δ-metric = L1.5 lift | Internal |
| L2 agent | `bench/agent` (scorer + `tsbench agent`); live targets `bench/webgoat_dual` + `bench/juiceshop_full` | detection_rate, **verified_rate** (PoC/evidence-grounded — the XBOW no-FP bar), completion_rate, FP-control | vs XBOW / strix / NodeZero (exploitation-verified) |
| Multi-trial | `bench/multi_trial` wrapper | median + p10/p90 over N=5 | — |

### 14.1 Ablation flags

* `TSENGINE_L15_DISABLED=1` — skip L1.5 hook chain. Findings land raw. Measures L1's contribution.
* `TSENGINE_L2_DISABLED=1` — `orchestrator.Run()` returns after anchor prepass. Measures pure L1 detection.

### 14.1.1 FP-control (false-positive specificity)

Recall (FN) is measured per-asset above; the **FP** half is measured by `metric:fp_rate` fixtures on **benign/clean targets**, where the correct answer is zero actionable findings. The gate is a **severity floor** — `Fixture.MaxSeverity` (e.g. `"high"`): any raw finding at or above it is a false positive (`Score.FalsePositiveCount`). This is robust where the old `max_findings:0` was brittle — a clean target may legitimately emit info-level notes, but must never raise a high/critical alarm. FP-control fixtures: `fixtures/container/alpine-clean` (runnable), `fixtures/repo/clean` (SAST/SCA — the noisiest class; runnable once repo-mount bench wiring lands). Pairs sensitivity↔specificity per asset (Youden = TPR + TNR − 1); FP bar tracks the XBOW "no false positives" standard.

### 14.2 Anti-overfit guards (mandatory on every new bench)

1. Source-grep test forbidding SUT-specific identifiers (juice-shop, bkimminich, vampi, crapi, etc.) in scoring code
2. Mandatory competitor citation in every bench report (enforced by render_report tests)
3. Multi-trial median + p10/p90
4. Per-layer ablation

---

## 15. Coding conventions (Go)

* Module path: `github.com/ClatTribe/tsengine` (placeholder — confirm before phase 0)
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

## 16. Build phases — current status

> **Status note (2026-06-21):** phases 0–6 are **built + CI-green**; the platform layer
> (§18) is built on top. What remains is **live/scale verification gated on infra,
> credentials, or product decisions** — tracked in [docs/competitive-roadmap.md](docs/competitive-roadmap.md)
> (Tracks 1–3) and §18.3, not here. Concretely open: per-asset **live** benchmark numbers
> (need the sandbox image + deployed targets; SAST 0.387 Youden is the one measured so far),
> the L2 agent **live `verified_rate`** (needs a target + `LLM_API_KEY`), scale-grade infra
> (Postgres store, cloud-KMS vault, HA/sandbox-pool — all behind today's interfaces), the
> per-tenant **LLM-config-in-UX**, and self-serve **billing**.

| Phase | Scope | Status |
|---|---|---|
| **0. Foundation** | Repo skeleton, core types (`pkg/types`), `Tool`/`Handler` interfaces, L1 dashboard JSON schema, evidence/attestation grounding (§10), CI (go test + golangci-lint + govulncheck) | ✅ built |
| **1. Sandbox + E2E** | Docker sandbox image (nuclei baked), `cmd/tool-server` HTTP API, host-side `internal/sandbox` client, run nuclei against one fixture target end-to-end | ✅ built |
| **2. web_application asset** | Anchor + registry tiers, filter rules, WAVSEP fixture + scorer, tool-replay API | ✅ built (live WAVSEP Youden pending a deployed target) |
| **3. Other 6 assets** | api, repo, container, ip, domain, cloud_account — anchor + registry tiers, per-asset filter, per-asset normalize | ✅ built (8 assets incl. mobile; live per-asset recall pending targets) |
| **4. L1.5 + dashboard + threat intel + compliance** | Hook chain, vulnerabilities.json renderer, threat_intel.enrich, compliance.map | ✅ built |
| **5. Template refresh + attestation** | Versioned corpora, pin-per-scan, cron refresh, delta-verify, signed evidence bundle | ✅ built |
| **6. L2 layer** | LLM Lead agent over ≤12-tool catalog, OODA, bench rigs | ✅ built (incl. ADR-0008 autonomous pentest; live `verified_rate` pending a target + LLM key) |

---

## 17. Where the strix lineage ends

tsengine inherits from strix:

* The L1/L2 audience-split mental model
* The host/sandbox boundary discipline
* The L1.5 hook chain order
* The sidecar findings bridge pattern
* The anti-overfit + bench discipline
* The ≤12-tool L2 cap
* The tool-existence principle

tsengine **diverges** from strix:

* Go, not Python — different idioms, library bindings where strix uses subprocess
* 8 assets, not 6 — adds `cloud_account` for the compliance audience and `mobile_application` for mobile-app teams
* Anchor + registry tier — strix has only anchors + a 99-tool legacy catalog flag
* Threat intel + compliance mapping happen at L1 emission (in addition to being L2 tools for arbitrary lookups)
* L1 dashboard JSON is a frozen schema spec'd in Phase 0, not implicit
* Evidence-grounded LLM agent with signed attestation — NOT a deterministic-process mandate (§10)
* No iter-Q5.* history — clean build phases (§16)

When in doubt, the strix design lineage at `/Users/ashish/Downloads/cowork/strix/` is reference reading, not authoritative — this file is authoritative.

---

## 18. The platform layer — autonomous security team (read before touching `cmd/platform`)

`tsengine` (the engine, §1–§17) is the **detection brain**. The **platform** wraps it
into a continuous, multi-tenant, human-backstopped product — *"reuse the brain, build
the body"* (full design: [docs/autonomous-team.md](docs/autonomous-team.md); **operator
deploy/config guide: [docs/platform-operations.md](docs/platform-operations.md)** — env
matrix, per-provider OAuth setup, API reference). The platform is **purely additive**: it
must never change the engine's detection logic.

**Two front-ends, one API.** `internal/console` (Go `html/template`, zero-JS, at `/ui`) is
the lightweight built-in fallback. **`frontend/`** is the flagship **agentic command-center
UX** — a separate Next.js (App Router/RSC) app (dark, Linear/Vercel-grade) that consumes
the same `/v1` JSON API server-side (httpOnly-cookie auth, no CORS, engine untouched). See
[frontend/DESIGN.md](frontend/DESIGN.md) for the IA, design system, and build phases. Both
are presentation only — the gate, ledger, and engines are unchanged.

### 18.1 The packages

| Package | Role |
|---|---|
| `pkg/ledger` | the signed, replayable decision ledger (promoted from `internal/` so the platform imports it) |
| `pkg/platform` | multi-tenant domain model — Tenant, Connection, Asset, Engagement, Action, ControlState |
| `internal/store` | the tenant-scoped system-of-record (`Store` interface + Memory / File-snapshot / SQLite impls, table-driven conformance suite); holds the **third-party app inventory** (`ReplaceThirdPartyApps`/`ListThirdPartyApps`, per operate scan) and the **issue-suppression rules** (`Put`/`List`/`DeleteIgnoreRule`, keyed by unified-issue dedup key — the ignore/accept-risk lifecycle) |
| `internal/connector` | external-system integrations (OAuth + Discover + Watch + Apply): GitHub + GitLab (tech SCM), Google Workspace + M365 + Okta (non-tech identity) |
| `internal/runner` | connector→engine→store glue; `ScanRunner` abstracts the engine, `EngineRunner` is the sandbox adapter; runs the full loop |
| `internal/hitl` | the human desk — the gate between *propose* and *apply* |
| `internal/remediate` | `Propose` (finding→Action; repo→PR, cloud→config, **workspace→a per-rule identity runbook** `identity.go`) + **`ProposeBulk`** (`bulk.go` — "Bulk Fix": groups an asset's findings by fix unit — SCA package coordinate from `ToolArgs`, else rule id — and emits ONE PR per group of ≥2 repo findings, citing every finding it resolves via `Action.FindingIDs`; singletons/non-repo fall back to `Propose`; the runner's optional `ProposeBatch` supersedes per-finding `Propose` when set) + `Deliverer` (apply via connector; routes to the action's own connection; `file_ticket` → a `Filer` e.g. Jira) |
| `internal/grc` | compliance control-state system-of-record + signed evidence pack + the auditor-facing **compliance report** (`Report` resolves each gap to its citing findings; `RenderMarkdown` is the attachable deliverable) + the customer-facing **VAPT/pentest report** (`VAPTReport`/`RenderVAPTMarkdown` — exec summary, scope, and every finding with severity/CWE/CVSS/exploit-status/evidence; grounded, served at `GET /v1/vapt/report`) |
| `internal/detect` | the continuous-monitoring backbone (deterministic detect half of detect-&-respond): `Detector.Reconcile` diffs a tenant's current findings against its open incidents — opens a `platform.Incident` for a new finding at/above a severity threshold (default high), resolves one when its issue (keyed `rule_id\|endpoint`) stops appearing. Signed into the ledger; LLM-free + grounded. `Reconcile` also takes an `attacked` key-set (ADR-0007 Phase 0b): a finding observed under attack in production opens an incident **regardless of the severity floor** + marks it `Incident.Attacked` (title prefixed `[under active attack]`); the runner computes it via `crossdetect.AttackedKeys(current, runtimeEvents)`. Driven by `runner.RescanTenant` each pass; opening a new incident fires an optional `Alerter` (Slack heads-up) so detect→alert happens in one pass |
| `internal/assetregistry` | shared `HandlerFor(assetType)` (so `cmd/tsengine` + `cmd/platform` don't duplicate routing) |
| `internal/crossdetect` | the **unified cross-detection** layer (orchestration glue over `correlate` + the flat finding list — adds no detection, §10/§13 hold). Six capabilities: (1) **attack paths** — buckets findings by inferred asset type so `correlate.Correlate` builds cross-surface chains (a finding bridging, via a real shared entity key/ARN/host/IP/bucket, to a crown jewel on another surface); `GET /v1/attack-paths` + `/attack-paths` page + dashboard banner. (2) **unified issues** (`UnifiedIssues`) — "one issue, many signals": collapses findings sharing a CVE (else rule\|endpoint) into one Issue carrying the worst severity + the distinct source scanners + `Confirmed` (≥2 tools agree); `GET /v1/issues` + `/issues` page + dashboard noise-reduction banner. (3) **issue suppression** — `GET /v1/issues` hides issues with a `platform.IgnoreRule` (default) / `?show=ignored`; `POST /v1/issues/ignore`\|`/unignore` (ledger-recorded) + the `/issues` Active/Ignored toggle + per-row ignore/restore. (4) **custom exclusion rules** (`exclude.go` — Aikido "custom rules": exclude paths/packages/conditions) — `platform.ExclusionRule` (field ∈ rule_id/package/path/cve/any + a `*`-glob `Pattern`); `ApplyExclusions` drops matching findings BEFORE `UnifiedIssues`, so excluded noise never becomes an issue (the `excluded` count rides on `GET /v1/issues`); `GET /v1/exclusions` + `POST /v1/exclusions`\|`/exclusions/delete` (ledger-recorded) + the `/issues` exclusion-rules manager. (5) **runtime correlation** (`runtime.go` — Runtime Protection, ADR-0007 Phase 0) — `platform.RuntimeEvent` is an in-app-firewall/RASP attack observation (the OSS "Zen" sensor streams its block events in); `AnnotateRuntime` flags any issue whose endpoint path matches a runtime event → `Attacked`/`AttackCount` = observed-in-the-wild (the strongest exploitability signal). tsengine consumes the signal, never blocks (§13). `POST /v1/runtime/events` (ingest, single or batch; body-tenant ignored for isolation) + `GET /v1/runtime/events` + the `attacked` count on `GET /v1/issues` + an "under attack" badge/stat on `/issues`. Phase 1 (the managed in-app sensor) stays ADR-0007-gated. (6) **data-tier prioritization** (`datatier.go` — the Synthesia "tier repos by customer-data exposure" idea) — an owner classifies each asset's data sensitivity (`platform.DataTier` 1=customer-data … 3=low, stored in `Asset.Meta["data_tier"]`, default Standard; `POST /v1/assets/{id}/data-tier`, surfaced on `GET /v1/assets` as `data_tier`/`data_tier_label`, set via the `/assets` Data-tier control). `RiskWeight(severity, tier)` is the tier-adjusted priority (tier 1 +50%, tier 3 −40%; severity stays dominant within a tier, so a Medium on a customer-data asset can outrank a Medium on a low-sensitivity one or edge a Low on a standard one); `PrioritizeByDataTier` attributes each issue to a tiered asset (BEST-EFFORT + grounded, §10 — only when the asset's Target literally appears in the issue Endpoint; repo file:line endpoints stay Standard until a finding→asset link exists in the data model) and re-ranks `GET /v1/issues` so the highest-risk issues lead (no-op while every asset is Standard). Engine `surface_priority` is untouched (§18.2 inv 1) — this is a platform-layer reordering only |
| `internal/pentest` | the **productized AI-pentest** layer (Aikido "AI pentesting" parity; ADR 0006). `Engagement` lifecycle (draft→authorized→running→reporting→complete→retesting/halted) + the **Rules-of-Engagement Guard** (`roe.go`): every agent action is gated by the runner — scope → budget → an **absolute destructive ban** → the **active-exploitation gate**. Active exploitation is **explicit-consent-based**: `RoE.ActiveAuthorized()` (the single source of truth) requires `AllowActive` + a named `AuthorizedBy` + a recorded `Consent` statement; `Authorize`, the runner `Check`, and `POST /v1/pentest` all refuse active mode without all three (400), and the consent text is signed into the ledger. The runner inverts control (agent **proposes** an `Attempt`, runner **disposes** via `RoE.Check` before any side effect), enforces the request budget + kill-switch. **Phase 0** runs the **`PassiveDriver`** over in-scope findings; **Phase 1 (built, ADR-0006 accepted)** is the **`ActiveDriver`** (`active.go`) — per-class playbooks (SSRF-canary, boolean-SQLi true/false differential, open-redirect canary-Location, reflected-XSS canary, IDOR-read), each a `Demonstration` of one or more benign `Probe`s + a **machine-checkable success predicate** over the responses, that upgrades a finding to `verification_status: verified` + a captured PoC **only** when its predicate holds (else the lead is reported unchanged). Benign-by-construction (canary probes, true/false differentials that extract no data, no writes/exfil). Live egress is `HTTPProber` (`httpprober.go` — bounded timeout, capped read, no redirect-follow so the 30x Location is the open-redirect proof), wired into `POST /v1/pentest/{id}/run` only when the engagement is active+consented AND the operator set `TSENGINE_ACTIVE_EXPLOIT=1` (else graceful passive fallback — never a falsely-confident exploit). A portfolio scorecard (`ComputeStats`: exploitation-proven count, `verified_rate` = proven/total, high+ proven, the high-plus-found SLA gate) backs the "exploitation-proven, money-back if no High+" claim — grounded tallies, never estimates. API: `POST /v1/pentest` (create+authorize), `GET /v1/pentest[/{id}]`, `GET /v1/pentest/stats` (scorecard), `POST /v1/pentest/{id}/run`, `GET /v1/pentest/{id}/report` (per-engagement VAPT via `grc.ReportFromFindings`); UX: `/pentest` list+create (consent capture) + scorecard + `/pentest/{id}` detail with Run/Retest + recorded-consent + report download |
| `internal/scheduler` | continuous-monitoring loop — re-scans every tenant on a cadence (`TSENGINE_MONITOR_INTERVAL`); the "autonomous" heartbeat alongside event-driven webhook re-scans |
| `internal/platformapi` + `cmd/platform` | the multi-tenant HTTP API + server (incl. `POST /v1/tenants` onboarding). Also the **public, unauthenticated PLG lead-magnet** `GET /v1/assess?domain=` (`assess.go`): a grounded, read-only email-auth score (DMARC/SPF/DKIM via public DNS through `operate`; never scans the target's servers) — rate-limited per IP, surfaced at the public `/scan` page |
| `internal/console` | the human-facing web dashboard + login under `/ui` — server-rendered HTML (`html/template`, zero JS). `GET /ui` shows risk rating + severity counts + top findings + pending approvals + compliance posture (cards link to the drill-down); `GET /ui/compliance/{framework}` is the per-control drill-down (gaps backed by their citing findings — the auditor view); `GET /ui/connect` is the first-run onboarding page (lists connectors + status) and `GET /ui/connect/{kind}` 302-redirects the browser into the provider OAuth consent (state = tenant id, reusing the API's `/v1/connect/{kind}/callback` exchange); `POST /ui/login` sets an httpOnly+SameSite=Strict session cookie (a browser can't send the bearer header on navigation); `POST /ui/approvals/{id}` Approve/Reject buttons drive the **same gated `hitl.Desk.Decide`** path as the API/Slack (tier rules + signed ledger still apply — the console is a UI onto the gate, not a second write path); a "Monitored assets" section (with last-scanned time) + a "Scan now" button (`POST /ui/rescan` / `POST /v1/rescan` → `RescanTenant`) give the owner visibility + manual control. Connection `SecretRef`s redacted before render |

### 18.2 Platform invariants (do not violate)

1. **The engine is untouched.** The platform consumes `orchestrator.Run` via `runner.ScanRunner`; no platform change may alter `asset/*`, the agents, `reachability`, `correlate`, or `gate`.
2. **Tenant isolation is the security boundary.** Every `Store` call is tenant-scoped; a tenant MUST NOT read another tenant's findings/connections/actions. Tests assert this at the store *and* the API.
3. **The only write path is `connector.Apply`, and it is reached only AFTER a HITL gate.** Tier 0/1 actions auto-apply; tier ≥ `platform.GateTier` (2) queue at the desk. `hitl.Desk` decides; `remediate.Deliverer` delivers. Never call `connector.Apply` directly.
4. **Every decision is signed.** Auto-apply and human verdicts both record into `pkg/ledger`; the GRC evidence pack uses the same ed25519-over-canonical-JSON scheme — one verifier covers ledger, evidence bundle, and evidence pack.
5. **Grounding holds end-to-end.** GRC marks a control "gap" only because a real finding cites it; remediations always carry `FindingID`. No platform layer asserts something the engine did not prove.
6. **Secrets never leave, and never sit in plaintext.** OAuth tokens are sealed by `internal/secret` (AES-256-GCM, key from `TSENGINE_SECRET_KEY`) at the OAuth callback *before* they touch the store; `Connection.SecretRef` holds only the sealed ref, resolved via `secret.Tokens` (`runner.Tokens`); the API redacts `SecretRef` before returning a connection.
7. **The kill-switch fails closed.** `Tenant.AgentsHalted` (the agentic-SMB spec OM-3 / TS-5 global kill-switch, toggled via `POST /v1/killswitch`) halts ALL autonomous action for a tenant: `hitl.Desk` refuses every apply (auto-applied AND human-approved alike — the switch wins over the verdict; queued actions wait) and `runner` pauses scanning. A read error on the flag is treated as NOT halted (opt-in; a transient error must not freeze a tenant). The one human "on the loop" can freeze the whole roster instantly; the toggle is signed into the ledger.

### 18.3 Status

Phases 0–3 + the wired loop are built (`store`/`platform`/`connector`/`runner`/`hitl`/
`remediate`/`grc`/`platformapi`/`cmd/platform`), all tested + CI-green. The store has a
dependency-free **file-backed persistent impl** (`store.OpenFile`, atomic snapshot;
`TSENGINE_PLATFORM_DB`) behind the `Store` interface — single-node-durable today. The
**Slack approval loop** is wired: `internal/notify` posts a queued action to Slack with
Approve/Reject buttons, and `POST /v1/slack/interactive` verifies Slack's v0 signature
(HMAC-SHA256, 5-min replay window) before driving `Desk.Decide`. OAuth tokens are
**encrypted at rest** (`internal/secret`, AES-256-GCM; `TSENGINE_SECRET_KEY`), sealed at
the callback before they reach the store. **Phase 4 (non-tech operate layer) has
started**: `internal/operate` is the identity/email posture engine — a Workspace
snapshot (IdP / Google Workspace / M365 export) → grounded findings (MFA gaps, weak
DMARC, risky OAuth grants, stale/over-privileged accounts), each citing the offending
user/domain/app, mapped to compliance controls so they flow into the same `grc`/`hitl`
loop. Snapshot-driven + LLM-free (mirrors `cloudengine`), so the logic is deterministic
and testable (a hardened workspace yields zero findings). `tsengine operate --snapshot`.
`operate` is wired into the platform as a `ScanRunner` for the `workspace` asset via
`runner.MuxRunner` (routes by asset type: workspace → operate, else → sandbox engine),
and a **live Google Workspace path** exists end to end: `connector.GWorkspace` (OAuth
onboarding → a `workspace` asset) + `operate.GWorkspace.Fetch` (Admin SDK directory →
snapshot) + `runner.LiveWorkspaceSource`/`CompositeSource` (snapshot-file first, else
live fetch). So a non-tech tenant connects **Google Workspace or Microsoft 365** →
posture findings flow through the same store/grc/hitl/ledger loop. `LiveWorkspaceSource`
holds a `Fetchers map[kind]Fetcher` so it serves multiple providers; `operate.M365`
fetches Microsoft Graph (`/users` + the auth-methods registration report, merged by UPN,
OData-paginated).

**The human UX layer is complete (`internal/console`, served at `/ui` by `cmd/platform`).**
The promised loop is now clickable end to end: provision a tenant (`POST /v1/tenants`) →
sign in (`/ui/login`, httpOnly+SameSite=Strict session cookie) → **connect a system**
(`/ui/connect` → provider OAuth → callback discovers + scans) → the **posture dashboard**
(risk rating, severity counts, top findings, connected systems) → **approve/reject fixes
in the browser** (drives the same gated `hitl.Desk.Decide` as Slack/API) → **compliance**
(posture cards → per-control drill-down with citing findings → signed Markdown report at
`GET /v1/compliance/{framework}/report`). Security + compliance, UX to backend, on the
untouched engine.

**Domain email-auth is live too** (`operate.EmailAuth`): the provider user-fetch only
yields accounts, so the live source now derives the org's sending domains from the user
emails (`operate.DomainsFromUsers`) and resolves DMARC/SPF/DKIM from public DNS
(`internal/runner.LiveWorkspaceSource.EmailAuth`, an injectable `Resolver` — `*net.Resolver`
in prod, fake in tests). Grounded (each field reflects a real TXT record or its documented
absence) and opt-in (nil enricher → today's snapshot-only behavior). So a connected
workspace now gets MFA posture *and* email-spoofing posture with zero extra config.

**Okta is wired** (`connector.Okta` OAuth onboarding → `workspace` asset + `operate.Okta`
fetcher: users paginated via the `Link` header, per-active-user MFA factors + admin roles,
status→suspended, lastLogin→stale; `OKTA_ORG_URL`/`OKTA_CLIENT_ID`/`OKTA_CLIENT_SECRET`).
So a non-tech tenant can connect **Google Workspace, Microsoft 365, or Okta** and get the
same grounded identity posture through the store/grc/hitl/ledger loop.

**Continuous monitoring now detects change, not just re-scans** (`internal/detect`): each
scheduled `RescanTenant` pass reconciles the tenant's current findings into durable
`Incident`s — opening one when a high+/critical issue is NEW since the last pass, resolving
it when the issue is fixed (keyed `rule_id|endpoint`, signed into the ledger, LLM-free).
Surfaced at `GET /v1/incidents` and a dashboard "New since last scan" section. This is the
deterministic **detect** half of detect-&-respond; the **respond** half is the existing
remediate + HITL path **plus the A-RSP incident-response slice**: when `Reconcile` opens a
**critical** incident, `runner` calls `remediate.ProposeIncidentResponse`, which prepares
**two** responses: (1) a **tier-2 gated containment** action (`proposeContainment` →
`ActFileTicket`, `remediation_type:containment`) — a class-specific runbook (identity →
suspend account + revoke sessions; cloud → restrict/quarantine resource; web/api → block the
endpoint) naming the affected entity (the endpoint half of the incident key), gated so a
human approves before it acts (carries a machine-readable `remediation_type`+`target` so a
future live containment connector can promote it to a real apply, like the Okta-suspend
promotion); and (2) a **T3 breach/disclosure communication** (`ActDraftNotification`) queued
for a **named human signature** — it can never auto-apply (the T3 invariant, §18.3), and a
signed draft files to the issue tracker for the human to actually send (the agent never sends
regulatory / customer comms itself). Both are grounded (cite the incident's rule + finding +
entity); the draft is explicit its claims are unverified until a human confirms them. The
deeper, open-ended **LLM-driven** SOC triage (forensics, multi-step playbooks) remains future.

**Identity findings now get specific fixes, not generic tickets** (`remediate/identity.go`):
each operate rule maps to a copy-pasteable runbook ticket naming the offending entity —
e.g. a DMARC finding carries the exact `_dmarc.<domain>` TXT record to publish, an
admin-without-MFA finding names the admin + the enforce action. They ride as tier-1
`file_ticket` actions (a ticket is reversible/informational → auto-delivers via the
`Filer`) and carry a machine-readable `remediation_type`+`target` so a future live Apply
has the fix ready. The first live identity *mutation* now exists: **`connector.Okta.Apply`
suspends a stale account** via the Okta user-lifecycle API (`POST
/api/v1/users/{id}/lifecycle/suspend`), reached only after the HITL gate (§18.2 inv. 3) and
tested against a fake org (injectable `HTTP` client). It needs the `okta.users.manage` scope
(onboarding scopes are read-only by design), so a real mutation requires an admin to grant
it — until then Okta answers 403 and `Apply` surfaces it as an error (never falsely "done").
The GWorkspace/M365 connector `Apply` (and the other Okta `remediation_type`s) remain honest
stubs pending admin-write creds. **The operate→tier-2 wiring now closes that loop end to
end** (`remediate.proposeIdentity` + `liveIdentityMutation`): when a remediation has a live,
reversible connector write path for the asset's provider — today only Okta `account_suspend`
— the proposer emits a **tier-2 `ActApplyConfig`** (gated) instead of a tier-1 ticket, so a
stale-Okta-account finding flows finding → gated action → HITL approve → `connector.Okta.Apply`
suspend → signed ledger. Every other (remediation, provider) pair stays a tier-1 runbook
ticket (no falsely-confident auto-apply) until its connector `Apply` lands — promotion is one
line in `liveIdentityMutation`. The asset's provider is carried in `Asset.Meta["provider"]`
(set by the GWorkspace/M365/Okta connector `Discover`). The full loop is E2E-tested
(`remediate.TestNonTechLoop_StaleAccountGatedThenApprovedSuspends`: queues, does NOT
auto-apply, suspends only after approval).

**M365 OAuth grants are live too** (`operate.M365.fetchGrants`): Microsoft Graph
`oauth2PermissionGrants` (delegated scopes + admin-vs-per-user consent) joined to
`servicePrincipals` (app name + `verifiedPublisher`) → grounded `OAuthGrant`s, so the
critical `oauth-admin-scope` (shadow-admin third-party app) + `oauth-unverified-app`
checks run live for M365. **Google Workspace grants are live too** (`GWorkspace.fetchGrants`
over the Directory `users.tokens` API per active user → per-app grants; `AdminScope` from
admin-directory / cloud-platform scopes). Both best-effort (grant read needs an extra
consent; absent → degrades to no grants, never fails the posture fetch). Google's tokens
API exposes scopes but **not** publisher verification, so Google grants are marked
`Verified` (the `oauth-unverified-app` check stays M365/snapshot — we don't guess).
**Okta grants are live too** (`Okta.accumulateGrants` per active user via
`/users/{id}/grants?expand=scope` → the scope name is inlined; `AdminScope` from `.manage`
/ `okta.roles` scopes; app labels resolved best-effort from `/apps`; `Verified` true, as
Okta has no publisher-verification). **So OAuth-grant detection is live across all three
non-tech IdPs — Google Workspace, Microsoft 365, and Okta** — completing the operate
live-detection trio (users · email-auth · grants) everywhere.

**Single-box production hardening is in** (the "pure Docker, one box, reliable, but
architected to scale" track). Durable persistence: a dependency-free **SQLite `Store`**
(`store.OpenSQLite`, `modernc.org/sqlite` — no cgo, static binary; WAL, JSON-blob rows)
behind the same `Store` interface and the same table-driven conformance suite as the
memory/file impls — `TSENGINE_PLATFORM_DB=/data/platform.db` (a `.db`/`.sqlite` path) picks
it; a `.json` path still gets the snapshot file store. Async scans: **`internal/jobs`** is
a bounded in-process worker pool (back-pressure → 429) so `POST /v1/rescan` returns `202` +
a pollable `Job` (`GET /v1/jobs/{id}`, tenant-scoped) instead of blocking the request for a
minutes-long scan; `Jobs==nil` falls back to synchronous (test back-compat). Observability:
**`internal/obsv`** installs a structured **slog** default (text, or JSON via
`TSENGINE_LOG_FORMAT=json`; level via `TSENGINE_LOG_LEVEL`) — which also routes the existing
`log.Print` lines — and a Prometheus **`GET /metrics`** (request count/latency,
`tsengine_scan_jobs_inflight`, plus the free Go runtime collectors). A `Middleware` wraps
the platform mux for per-request metrics + an access log (SSE/`/metrics`/`/healthz`
excluded from skew/noise). All three sit behind today's interfaces so the scale-out
successors (Postgres store, durable queue, OTel) swap in without touching call sites.

Remaining is **next-phase breadth/scale, not core-loop gaps**: the live identity-mutation
`Apply`
(`operate *.Apply` — the GWorkspace/M365 connector `Apply` are honest stubs pending live
admin-write creds), the **open-ended LLM-driven** SOC reasoning (the deterministic
detect/incident backbone now exists in `internal/detect`; what's left is agentic triage/
response beyond the threshold rules), and the infra successors — a **Postgres `Store`** (the
SQLite single-box backend now exists) + a cloud-KMS `secret.Vault` (both behind today's
interfaces).

**Real per-user account auth is now built** (was the deferred "self-serve signup" item).
`internal/authn` hashes passwords with stdlib `crypto/pbkdf2` (PBKDF2-HMAC-SHA256, 600k
iters, per-password salt — no new dependency) and mints random session tokens.
`pkg/platform.User`/`Session` + Store `Put/Get/GetByEmail/ListUsers` and
`Put/Get/DeleteSession` persist them. `internal/platformapi/auth.go` serves
`POST /v1/auth/{signup,login,invite,password}` + `GET /v1/auth/{me,team}` + `POST /v1/auth/logout`.
The `auth` middleware accepts **either** the shared platform token (+`X-Tenant-ID`, for
operator `POST /v1/tenants` / Slack / tests) **or** a user session token — and for a session
the tenant comes FROM the session, so a spoofed `X-Tenant-ID` header cannot cross tenants.
Signup creates a workspace (tenant) + owner; an owner can invite members (one-time temp
password — email-based invites are the next step). **Forced first-login rotation is wired**:
an invited member's account carries `User.MustChangePassword`; while set, the `auth`
middleware blocks every app endpoint with `403 password_change_required` (the auth-mgmt
endpoints — me/logout/password — use `sessionAuth`, so they stay reachable), and
`POST /v1/auth/password` (verify current → set new → clear the flag) unlocks it. So the
owner-issued temp password can't remain the standing credential. Frontend: a top-level
`/change-password` route (outside the `(app)` group to avoid a redirect loop) + the `(app)`
layout redirect on `me.must_change_password`. `cmd/platform` `newID()` is a random hex id
(a restart-resetting counter previously overwrote tenants). Frontend: `/login`
(email+password), `/signup`, `/change-password`, Settings → Team. **Still future:** email
invites / password reset, OAuth-SSO login, and a billing model.

**The product stack is containerized** (`docker compose up` / `make up`): `docker/platform/
Dockerfile` (the `cmd/platform` server, Go, ~108MB) + `frontend/Dockerfile` (Next.js
`output:"standalone"`, ~105MB) + `docker-compose.yml` (platform :8090 + frontend :3000,
`platform-data` volume, `.env`/`.env.example` for `TSENGINE_SECRET_KEY`). Defaults to
`NO_ENGINE` (operate/identity assets + the whole loop work; tech-asset scanning needs the
sandbox image + the commented Docker-socket mount). Both images build + run + sign-up E2E
verified. The detection **engine** has its own image (`docker/host/Dockerfile`, released to
GHCR by `release.yml`).

**Single-box production deployment is built + hardened** ([docs/production-single-box.md](docs/production-single-box.md)
— threat model + phased plan + runbook): `docker-compose.prod.yml` + `docker/caddy/Caddyfile`
run the whole product, **engine ON**, safely on one box. Hardening: per-scan sandboxes get
resource/PID/file limits + a writable tmpfs by default and opt-in read-only-rootfs/non-root/
isolated-network (`internal/sandbox.Hardening`, `TSENGINE_SANDBOX_*`); the platform reaches
the Docker API through a **docker-socket-proxy** (no raw socket = no host-root on compromise —
live-verified: container/image API allowed, `/info` denied) and spawns sandboxes on a
dedicated network reached by container IP (off the platform/frontend net); a **Caddy TLS edge**
is the only published surface (HTTPS + security headers; raw `:8090`/`:3000` unpublished);
secrets via the Docker-secret `*_FILE` convention; `scripts/backup.sh`/`restore.sh` for the
`platform-data` volume; one-command **`make deploy-prod`** (`scripts/deploy-single-box.sh`,
`--check` dry-run) + `make prod-validate`. Threats T1–T8 each have a shipped mitigation (#259–264).

**Still single-box, not scale-grade** (the multi-machine gaps, each behind an existing seam —
docs/production-single-box.md §6): single-node file/SQLite store (Postgres is the `store.Store`
successor), env/file secrets (cloud-KMS is the `secret.Vault` successor), no HA/multi-node
sandbox pool + durable queue, container (not microVM) isolation. See
[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md) + [docs/production-single-box.md](docs/production-single-box.md).

**The global kill-switch is built** (agentic-SMB spec OM-3 / TS-5 — the "one human, one pane,
kill-switch" operating-model primitive). `Tenant.AgentsHalted`, toggled by the owner via
`POST /v1/killswitch` (signed into the ledger), makes the platform **fail closed** for a
tenant: `hitl.Desk` refuses every apply (auto + human-approved; the switch beats the verdict,
actions queue) and `runner` pauses scanning. The frontend surfaces it on the single pane — a
Settings toggle (owner-gated) + a persistent halted banner across the app shell. This is the
**§18.2 invariant 7**. The design source is the (untracked) `sec_lifecycle_agentic_smb.md` —
the formal RFC-2119 spec for the fractional-autonomous-security-team-for-SMB product; the
implementation's reconciliation against it lives in [docs/personas-and-workflows.md](docs/personas-and-workflows.md)
§7. **The Warden's AI-BOM (WRD-1) is built**: `GET /v1/ai-bom` (`internal/platformapi/aibom.go`)
+ a Settings panel inventory what the autonomous agent can touch — every connection, its
granted scopes, and a least-privilege read/write classification (flagging the write-capable,
higher-risk surface) — plus the governance state (kill-switch + gate tier). Grounded in real
`Connection.Scopes`, no secrets. **Per-agent quarantine (WRD-4) + OM-5 fail-closed are also
built**: `POST /v1/connections/{id}/quarantine` sets `ConnQuarantined` (a per-connection
kill-switch — halt one connection's automation, not the whole roster), and the runner now
**skips any asset whose connection isn't `ConnActive`** (`connInactive`, permissive only on
missing data) so a revoked/degraded/quarantined connection is never acted on. **The T3
invariant is now enforced** (`platform.TierIrreversible`=3 + `Action.NeedsHumanSignature()`):
`hitl.Desk.apply` refuses an irreversible action that carries no named human approver
(`ErrNeedsHumanSignature`) — it never executes on `auto`, even if a future break-glass
auto-apply is added for lower tiers. *No flow emits a T3 action yet* (breach-notification /
customer-comms ride the future **A-RSP** incident-response capability), so this is
forward-compatible hardening: a T3 action is safe by construction the moment one is produced.
**With this the agentic-SMB spec is fully reconciled** — every OM/TS/AGT/WRD/ACC requirement
is built or, for A-RSP, explicitly future (see docs/personas-and-workflows.md §7).
