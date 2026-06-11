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

## 3. Asset types (7)

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

The `cloud_account` asset is what makes tsengine usable for SOC2/PCI compliance teams. Without it, the engine only covers infrastructure surfaces.

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
     nuclei default-logins; thin surface → ffuf content discovery.
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
       corroborated_by, threat_intel, compliance */
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

Frameworks supported day 1:

* SOC 2 (Trust Services Criteria)
* PCI-DSS v4.0
* HIPAA Security Rule
* CIS Controls v8
* NIST CSF 2.0
* ISO 27001:2022

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
| L1.5 ablation | (any L1 bench) + `TSENGINE_L15_DISABLED=1` | Δ-metric = L1.5 lift | Internal |
| L2 (future) | `bench/webgoat_dual` + `bench/juiceshop_full` | (detection_rate, completion_rate) | Internal |
| Multi-trial | `bench/multi_trial` wrapper | median + p10/p90 over N=5 | — |

### 14.1 Ablation flags

* `TSENGINE_L15_DISABLED=1` — skip L1.5 hook chain. Findings land raw. Measures L1's contribution.
* `TSENGINE_L2_DISABLED=1` — `orchestrator.Run()` returns after anchor prepass. Measures pure L1 detection.

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

| Phase | Scope | Status |
|---|---|---|
| **0. Foundation** | Repo skeleton, core types (`pkg/types`), `Tool`/`Handler` interfaces, L1 dashboard JSON schema, evidence/attestation grounding (§10), CI (go test + golangci-lint + govulncheck) | not started |
| **1. Sandbox + E2E** | Docker sandbox image (nuclei baked), `cmd/tool-server` HTTP API, host-side `internal/sandbox` client, run nuclei against one fixture target end-to-end | not started |
| **2. web_application asset** | Anchor + registry tiers, filter rules, WAVSEP fixture + scorer, tool-replay API | not started |
| **3. Other 6 assets** | api, repo, container, ip, domain, cloud_account — anchor + registry tiers, per-asset filter, per-asset normalize | not started |
| **4. L1.5 + dashboard + threat intel + compliance** | Hook chain, vulnerabilities.json renderer, threat_intel.enrich, compliance.map | not started |
| **5. Template refresh + attestation** | Versioned corpora, pin-per-scan, cron refresh, delta-verify, signed evidence bundle | not started |
| **6. L2 layer** | LLM Lead agent over ≤12-tool catalog, OODA, bench rigs | future |

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
* 7 assets, not 6 — adds `cloud_account` for the compliance audience
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
the body"* (full design: [docs/autonomous-team.md](docs/autonomous-team.md)). The
platform is **purely additive**: it must never change the engine's detection logic.

### 18.1 The packages

| Package | Role |
|---|---|
| `pkg/ledger` | the signed, replayable decision ledger (promoted from `internal/` so the platform imports it) |
| `pkg/platform` | multi-tenant domain model — Tenant, Connection, Asset, Engagement, Action, ControlState |
| `internal/store` | the tenant-scoped system-of-record (`Store` interface + in-memory impl) |
| `internal/connector` | external-system integrations (OAuth + Discover + Watch + Apply): GitHub + GitLab (tech SCM), Google Workspace + M365 + Okta (non-tech identity) |
| `internal/runner` | connector→engine→store glue; `ScanRunner` abstracts the engine, `EngineRunner` is the sandbox adapter; runs the full loop |
| `internal/hitl` | the human desk — the gate between *propose* and *apply* |
| `internal/remediate` | `Propose` (finding→Action; repo→PR, cloud→config, **workspace→a per-rule identity runbook** `identity.go`) + `Deliverer` (apply via connector; routes to the action's own connection; `file_ticket` → a `Filer` e.g. Jira) |
| `internal/grc` | compliance control-state system-of-record + signed evidence pack + the auditor-facing **compliance report** (`Report` resolves each gap to its citing findings; `RenderMarkdown` is the attachable deliverable) |
| `internal/detect` | the continuous-monitoring backbone (deterministic detect half of detect-&-respond): `Detector.Reconcile` diffs a tenant's current findings against its open incidents — opens a `platform.Incident` for a new finding at/above a severity threshold (default high), resolves one when its issue (keyed `rule_id\|endpoint`) stops appearing. Signed into the ledger; LLM-free + grounded. Driven by `runner.RescanTenant` each pass |
| `internal/assetregistry` | shared `HandlerFor(assetType)` (so `cmd/tsengine` + `cmd/platform` don't duplicate routing) |
| `internal/scheduler` | continuous-monitoring loop — re-scans every tenant on a cadence (`TSENGINE_MONITOR_INTERVAL`); the "autonomous" heartbeat alongside event-driven webhook re-scans |
| `internal/platformapi` + `cmd/platform` | the multi-tenant HTTP API + server (incl. `POST /v1/tenants` onboarding) |
| `internal/console` | the human-facing web dashboard + login under `/ui` — server-rendered HTML (`html/template`, zero JS). `GET /ui` shows risk rating + severity counts + top findings + pending approvals + compliance posture (cards link to the drill-down); `GET /ui/compliance/{framework}` is the per-control drill-down (gaps backed by their citing findings — the auditor view); `GET /ui/connect` is the first-run onboarding page (lists connectors + status) and `GET /ui/connect/{kind}` 302-redirects the browser into the provider OAuth consent (state = tenant id, reusing the API's `/v1/connect/{kind}/callback` exchange); `POST /ui/login` sets an httpOnly+SameSite=Strict session cookie (a browser can't send the bearer header on navigation); `POST /ui/approvals/{id}` Approve/Reject buttons drive the **same gated `hitl.Desk.Decide`** path as the API/Slack (tier rules + signed ledger still apply — the console is a UI onto the gate, not a second write path). Connection `SecretRef`s redacted before render |

### 18.2 Platform invariants (do not violate)

1. **The engine is untouched.** The platform consumes `orchestrator.Run` via `runner.ScanRunner`; no platform change may alter `asset/*`, the agents, `reachability`, `correlate`, or `gate`.
2. **Tenant isolation is the security boundary.** Every `Store` call is tenant-scoped; a tenant MUST NOT read another tenant's findings/connections/actions. Tests assert this at the store *and* the API.
3. **The only write path is `connector.Apply`, and it is reached only AFTER a HITL gate.** Tier 0/1 actions auto-apply; tier ≥ `platform.GateTier` (2) queue at the desk. `hitl.Desk` decides; `remediate.Deliverer` delivers. Never call `connector.Apply` directly.
4. **Every decision is signed.** Auto-apply and human verdicts both record into `pkg/ledger`; the GRC evidence pack uses the same ed25519-over-canonical-JSON scheme — one verifier covers ledger, evidence bundle, and evidence pack.
5. **Grounding holds end-to-end.** GRC marks a control "gap" only because a real finding cites it; remediations always carry `FindingID`. No platform layer asserts something the engine did not prove.
6. **Secrets never leave, and never sit in plaintext.** OAuth tokens are sealed by `internal/secret` (AES-256-GCM, key from `TSENGINE_SECRET_KEY`) at the OAuth callback *before* they touch the store; `Connection.SecretRef` holds only the sealed ref, resolved via `secret.Tokens` (`runner.Tokens`); the API redacts `SecretRef` before returning a connection.

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
remediate + HITL path. (The open-ended LLM-driven SOC reasoning remains future.)

**Identity findings now get specific fixes, not generic tickets** (`remediate/identity.go`):
each operate rule maps to a copy-pasteable runbook ticket naming the offending entity —
e.g. a DMARC finding carries the exact `_dmarc.<domain>` TXT record to publish, an
admin-without-MFA finding names the admin + the enforce action. They ride as tier-1
`file_ticket` actions (a ticket is reversible/informational → auto-delivers via the
`Filer`) and carry a machine-readable `remediation_type`+`target` so a future live Apply
has the fix ready. The actual identity *mutation* (enforce MFA, revoke a grant) still has
no live write path — the GWorkspace/M365/Okta connector `Apply` are honest stubs pending
admin-write creds.

Remaining is **next-phase breadth/scale, not core-loop gaps**: OAuth-grant live fetch
(grants are still snapshot), the live identity-mutation `Apply`
(`operate *.Apply` — the GWorkspace/M365 connector `Apply` are honest stubs pending live
admin-write creds), the **open-ended LLM-driven** SOC reasoning (the deterministic
detect/incident backbone now exists in `internal/detect`; what's left is agentic triage/
response beyond the threshold rules), and the infra successors — a sqlite/Postgres `Store`
+ a cloud-KMS
`secret.Vault` (both behind today's interfaces). Public per-tenant self-serve signup (vs
the operator-token `POST /v1/tenants`) needs a real identity/billing model and is a
deliberate future step, not part of the shared-token MVP.
