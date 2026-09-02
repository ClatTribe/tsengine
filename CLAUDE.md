# CLAUDE.md â tsengine architecture invariants

This file is loaded into every Claude turn working on this repo.
**Read this before proposing architectural changes.**

When you change something architectural, **update this file in the same PR**
so future turns see the new layout.

---

## 0. Prioritization principle — customer value first (read before ranking any roadmap)

**Rank work by what it is worth to the customer, done to the standard they will actually
trust — never by how hard or fast it is to build.** Effort and value are different axes;
a one-day build can be the highest-value thing on the list and a multi-week build can be
worth little. When you rank a backlog, competitive gap, or set of PRs, the first question
is *"what is this worth to the customer, done right?"*, and only then *"what does it
cost?"*. Sequencing may use cost as a tiebreak; the ranking itself is value-led.

**"Done right" is the customer's trust bar, not "compiles + passes CI."** For most
security/compliance work the small, mechanical version and the version a regulated buyer
will stake their audit on are far apart, and the gap between them *is* the value. A card
masker is a day; a redactor a healthcare CISO will run against production PHI — provably
complete, auditable, non-destructive of the evidence — is the actual deliverable. Scope
the unit of work as the trustworthy version.

**A shallow version that manufactures false confidence is worse than not building it.**
This is §10 grounding applied to the roadmap: a half-right sanitizer that misses one SSN,
or a root-cause dedup that collapses two real defects into one "fixed" banner, fails the
same way a hallucinated finding does — it tells the customer something is handled when it
is not. "Small to start, expensive to make trustworthy" is the honest description of most
of this backlog; do not let the first clause hide the second.

**Do not confuse catch-up with moat.** Closing a competitor's *claimed* capability
(often marketing, not verified) is worth less than deepening a lead a customer can feel
in an audit or an exploitation number. Weigh moat-widening above catch-up at equal cost,
and verify a competitor actually ships a thing before ranking work to match it.

Corollary for competitive analysis: **score against our own verified capability, never
against a claim.** Our column is checkable in this tree; theirs is their website. Rank
only the gaps confirmed absent here.

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

### 2.2.1 Product identity & the specialist taxonomy (naming invariant)

The L2 product is the **AI Security Engineer** — keep this umbrella name. It is
deliberately BROADER than any single domain, because the engine already spans
SIX security surfaces, not one. Naming the product after one surface ("AI Cloud
Security Engineer", "AI SOC", "AI AppSec") is a POSITIONING BUG: it caps the
perceived scope below what is built and misleads future design toward a
single-domain shape. Do not do it.

The architecture is **one Lead orchestrating domain SPECIALISTS** (the ≤12-tool
cap, §2.6, is why: no single agent can hold every surface's tools — split by
DOMAIN, never by task, since the tasks within a domain share one context: the
cloud graph, the repo tree). The specialists, each named as a security-team role
and each mapping to a benchmark family (docs/security-engineer-tasks-benchmarks.md):

| Specialist (sub-agent) | Code | Surface | Neutral benchmark family |
|---|---|---|---|
| **AI Cloud Security Engineer** | `internal/cloudagent` | cloud IAM attack-paths | CloudGoat / IAM-Vulnerable |
| **AI AppSec Engineer** | repository/container/api assets + `remediate`/`backport` | code/deps/images/APIs | OWASP-Bench / SEC-bench / BackportBench |

**PROACTIVE code discovery is wired** (`POST /v1/code/sweep`, `internal/codesweep` â which was complete, tested and had NO caller). `/v1/code/investigate` is REACTIVE: it triages findings a scanner already reported, so a vulnerability no scanner flagged is invisible to it. The sweep starts from the code instead â decompose into many small questions, answer them in parallel, dispose the ungrounded ones. Grounding (Â§10) is the whole design, because an LLM proposing vulnerabilities from source is exactly the shape that manufactures false confidence: the model PROPOSES and the disposer refuses anything whose cited location does not exist (refusals are COUNTED and returned, never swallowed); what that proves is BOUNDED, so a candidate lands as `pattern_match` and never `verified` â in this codebase verified means a predicate RAN, and nothing here executed anything; and a CAPPED sweep emits an `asset.CoverageRulePrefix` disclosure, because a partial sweep rendered as a result list reads as "we looked at your repository" when we looked at part of it. A COMPLETE sweep declares nothing (asserted by test). On demand, never automatic â it costs a model call per task. An OPT-IN `"panel": true` runs `internal/consensus` (an odd panel of independently-personaed jurors, majority wins) over each surviving candidate before it is recorded, and every DROPPED candidate rides back with the panel's reasoning and its vote, not merely a count â a count says something was removed without letting anyone see WHAT or disagree, and Â§2.5 requires a dismissal to be logged and RECOVERABLE. That applies with more force here than to a deterministic filter, because this is a panel of language models deleting a candidate finding; `consensus.Decision.Rationales` exists to be that audit trail and the first wiring discarded it. A 2-1 removal and a unanimous one are different grounds for trusting it, so the vote is recorded too. This is the ONE place in the pipeline where a consensus vote may DROP something, and it is legitimate exactly because a sweep candidate is NOT tool-grounded: it is one model's proposal, so a panel disagreeing is a second opinion on an opinion, not an LLM overruling a scanner. Everywhere else an LLM verdict ANNOTATES and never suppresses (the Detection Skill triage is annotation-only for the same reason), and a general consensus FP-filter over tool-grounded findings was considered and NOT built for that reason â it would spend jurors Ã findings of model calls to produce an opinion that correctly could not change anything. Fails OPEN: a tie or a wholly-failed panel KEEPS the candidate, because a deadlocked panel is not evidence of absence.
| **AI Identity/SaaS Engineer** | `internal/operate` + `internal/sspm` | IdP posture + SaaS config | CISA SCuBA (ScubaGear/ScubaGoggles) |
| **AI SOC Analyst** | `internal/detect` + A-RSP | detect → triage → respond | ExCyTIn-Bench / SecRespond / SIR-Bench |
| **AI Compliance Engineer** | `internal/grc` | 22-framework evidence | OpenCRE / SCF / CSA CCM (crosswalk corroboration) |
| **AI EASM/OSINT Engineer** | `internal/osint` | external attacker's-eye exposure | SpiderFoot/taranis parity |

**FOCUS DECISION (2026-08-17) — be best-in-breed in CLOUD + OFFENSE + COMPLIANCE.**
Those three have a measured lead or a structural advantage nobody else pairs, and together
they form one coherent product: find the cross-surface attack path, prove it by
exploitation, produce the audit evidence. The other three specialists ship as
**capabilities, not claims** — honest about depth, never described as best-in-breed. Three
deep specialists beat six shallow ones; the failure mode this prevents is spreading across
all six and leading in none. Gap sizing, the deferred items (AppSec patch agent, SOC
investigation agent, identity/SaaS parity, EASM benchmark) and the review triggers live in
[docs/specialist-roadmap.md](docs/specialist-roadmap.md) — read it before starting work on
a non-focus specialist, because several of those gaps are XL and blocked on a product
decision, not on effort.

**Design rules to keep in mind for future work:**
1. **New security capability → a SPECIALIST under the umbrella, or a tool a
   specialist calls — never a rename of the whole product to that domain.**
2. **Split agents by DOMAIN (shared substrate), not by TASK** (discover/triage/
   remediate within a domain are phases of ONE investigation loop — §5.3 / the
   cloudagent enumerate→verify→record→fix loop; task-split re-loads context and
   breaks continuity).
3. **Integrations are SHARED across specialists** — the GitHub connection serves
   AppSec + SSPM + OSINT-leak-search; an IdP serves Identity + SOC; the cloud
   role serves Cloud + Compliance evidence. So "go comprehensive" costs almost
   no new integration surface (§18.1 connector set). When adding a specialist,
   REUSE an existing connection before adding a new connector.
4. Market-legible single label, if one is forced: **"AI Security Engineer"** >
   any single-domain name — it is what a mid-market ICP without a security team
   is actually hiring for, and it does not undersell the six surfaces.


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

## 3. Asset types (7 — the focus set)

**The product is sold on SIX surfaces: cloud, code, identity, web, api, container.** That is the
launch claim and the list every roadmap, page and benchmark should be read against.

The seven asset TYPES below are how the engine models scan targets, and the two lists are not the
same shape — `identity` is a surface delivered through the `workspace` asset plus the SaaS/identity
ingest paths rather than through a scanned asset type, and `ip_address`/`domain` are the recon
surface underneath web and api rather than separate things we sell. Say "six surfaces" to a
customer and "seven asset types" to the engine, and do not let either list quietly become the other.

**`ai_application` HAS NOT STARTED.** The garak wrapper has been REMOVED — it was the only registered
tool with zero callers (no handler, no agent, no dispatcher), so it shipped a large ML dependency set
in every image for a capability nobody could invoke. It returns when the asset does. There is no asset
type, so nothing can be pointed at it. It is not a supported surface, it is not on the launch list,
and no page may imply otherwise (§13's AI-application note carries the detail).

**KUBERNETES IS NOT A SUPPORTED SURFACE EITHER** — no cluster scanner is wrapped (no kube-bench /
kubescape / kube-hunter), and a live cluster is not a scannable asset. prowler/kics/checkov touch
k8s only as IaC text. Recorded here because an audit read the absence as a gap; it is a scope
decision, and the two are different claims.

New asset-facing work targets the six surfaces; do not add or revive an asset type without an ADR.

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

The `cloud_account` asset is what makes tsengine usable for SOC2/PCI compliance teams. Without it, the engine only covers infrastructure surfaces. Count invariant: `pkg/types.AllAssetTypes()` + its test pin the focus-set count (7). `mobsfscan` still fires as a *repository* escalation on mobile source files in a connected repo (§5.3) — that capability is orthogonal to the deprecated standalone asset noted below.

> **Deprecated — `mobile_application` (descoped, pending code removal).** The standalone mobile-bundle
> asset is **descoped from the focus set** and receives no asset-facing work. Reason: it cannot scan a
> *built* APK/IPA today (no apktool/jadx decompile prepass), has no dynamic pass, and the
> mobile-app-team audience is outside the current ICP. `internal/asset/mobile`, the apkid wrapper,
> `pkg/types.AssetMobileApplication`, and the mobile bench targets remain in the tree; removing them
> (and dropping the code-level count 8→7) is a follow-on cleanup, so until then `AllAssetTypes()` may
> still enumerate it. Do not build on it. The marketing page is already honest about the live
> capability — `frontend/lib/asset-marketing.ts` states "Source only; we do not decompile a built
> APK or IPA" — and `TOOLSET=mobile` (docker/sandbox/Dockerfile) now gates apkid out of every default
> sandbox build.

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
5. **Coverage disclosure is a first-class artifact.** A handler may implement
   `asset.CoverageReporter.CoverageGaps(target, findings)` â the orchestrator
   calls it AFTER normalization (so it sees the scan's final findings, not the
   interim detection view) and appends whatever it returns. What a scan could
   NOT check is part of its result: rendered as nothing, a skipped check is
   indistinguishable from a clean one, and the customer reads "we looked and it
   was fine" for something nobody looked at. A coverage finding asserts an
   ABSENCE OF TESTING, never a vulnerability, and is INFORMATIONAL by
   construction â a check that did not run has no evidence for a severity, and
   inventing one is the same overclaim as a green tick on unscanned scope,
   pointed the other way. First implementation: `common.ThreatInformedGaps` on
   the web + ip handlers (exploited CVEs matching observed software that nuclei
   ships no template for â Â§7.1). **The `asset.CoverageRulePrefix` (`coverage::`)
   namespace IS the contract**: `internal/coverage` surfaces anything carrying it as
   `AssetCoverage.DeclaredGaps` and EXCLUDES it from `FindingsCount` /
   `ToolsWithFindings` â without that exclusion, admitting a gap would RAISE the
   numbers describing how well an asset was covered, so being honest would make the
   asset look MORE scanned. `crossdetect.UnifiedIssues` drops it too: in a list titled
   "issues" a disclosure reads as one, with CVE ids in its title, inviting exactly the
   conclusion its own text refuses to make. A new CoverageReporter gets all of this by
   using the prefix. `DeclaredGaps` is DISTINCT from `UntestedClasses` â the latter
   is a standing limitation of the asset TYPE (knowable before any scan), the former a
   fact about one run against one target; merged, a standing caveat absorbs a live one.
   Rendered on `/coverage` with the disclosure text VERBATIM, since the "not a
   vulnerability" caveat lives in the wording and a summary is where it would be lost.
6. **Child-asset pivot is a first-class artifact (C5).** A handler may
   implement `ChildAssetExtractor.ChildAssets(findings)` â `Scan.ChildAssets`
   (domain subdomains â web/ip child targets) so webappsec spawns child
   scans instead of re-enumerating (strix's re-enumeration trap).
7. **Wrap OSS; never build in-house detectors (Â§13).** strix rebuilt IaC,
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

### 5.4 SCA reachability triage is multi-language (Go + JS/TS + Python)

`internal/reachability` turns dependency-scanner noise into a finding: *"a
scanner says this dep has a vulnerable function — does THIS code actually call
it, from an entrypoint?"* The **solver + graph model are language-agnostic;
only extraction is per-language** — so it's an `Extractor` interface
(`Lang`/`Detect`/`Extract` → the shared `Graph`), `GoExtractor` wrapping the
stdlib `go/parser` path unchanged, plus pure-Go host-side `JSExtractor` +
`PythonExtractor`. Two **fidelity tiers stamped on every verdict** (§10
honesty): `call_graph` (resolved intra-repo calls — Go) vs `import_use`
(import + call-site, no cross-file dynamic dispatch — JS/Python), so a
coarse-tier "not reachable" is a SOFT negative, never a precise one.
`BuildGraphs` + `TriageMulti` route each SCA finding to its ecosystem's graph
(npm/pip/go); an unroutable ecosystem is `unknown_ecosystem`, never silently
safe. Importers carry the ecosystem (Dependabot `package.ecosystem`, Snyk
`packageManager`); `tsengine reachability`/`gate --sca` drive it. The
`call_graph`-tier upgrade per non-Go language (wrap Jelly/PyCG/WALA as sandbox
tools) is the documented follow-on. See [ADR 0015](docs/adr/0015-multi-language-reachability.md).

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
* Vendor advisory URLs — the reference links CISA publishes with each KEV entry (`notes`). These were PARSED AND DISCARDED until now, the third instance of that exact bug in this one feed after vendorProject/product and dueDate/ransomware-use, while this line claimed the capability. All 1,673 entries carry them (3,023 URLs live). Only real http(s) URLs are kept — a fragment of prose stored as an advisory link puts something in front of a responder that does not resolve, which is worse than the empty list it replaces, because an empty list is honestly empty. Those links then reached exactly ONE renderer — `query_threat_intel`, the agent's on-demand lookup for CVEs that are NOT among the findings — so on the finding that actually carried them, nobody could see them. The field was declared in the frontend type the whole time and never read. It is now rendered on the finding page (real http(s) links only, for the same reason the ingest filters them), guarded by `internal/uicheck` so it cannot silently regress. `L15Summary` deliberately does NOT tag it, and the exemption is stated in the code: that line RANKS, every KEV entry has an advisory, and six URLs would cost the agent context while saying nothing about what to do first.
* Known exploit availability (Metasploit, ExploitDB, GitHub PoCs)

**Sourced from authoritative OSINT feeds, not hand-curated.** `tsengine corpus refresh` (`internal/corpus/threatintel`) ingests **CISA KEV** (the actively-exploited signal) + **FIRST.org EPSS** (~336k CVEs, the patch-priority signal) + **Exploit-DB** (`exploitdb.go` â the "a public exploit/PoC EXISTS" overlay, the patch-priority rung between EPSS probability and KEV in-the-wild; best-effort so a fetch failure never blocks the KEV+EPSS refresh) â all free, no API key â into a versioned on-disk corpus (`threat_intel.json` + sidecar manifest). A CVE's `Exploits[]` refs (`exploitdb:EDB-<id>`) ride the finding's `ThreatIntel` and surface as `pub-exploit` in the L2 digest (`L15Summary`). **CVSS base vectors** are an OPT-IN 4th source (`nvd.go` â NVD CVE API/bulk 2.0 â CVEâ`{baseScore, vectorString}`, preferring v3.1âv3.0âv2): only fetched when `RefreshOptions.NVDURL` is set (NVD is large + paginated â wired to a bulk mirror / pager, never defaulted to a single live-API page), best-effort like ExploitDB. It populates the corpus's long-empty `CVSS` base score AND a new `CVSSVector` (AV/AC/PR/UI/S/C/I/A); the vector rides `ThreatIntel.CVSSVector` and surfaces as `av:network` in `L15Summary` (the strongest reachability signal â network-attackable, no local access). **That feed had no caller until now** — `NVDURL` had zero non-test setters, so on any deployment using a REFRESHED corpus (the documented production path) nothing populated `CVSS` at all and every entry scored 0. Wired as `TSENGINE_NVD_URL` / `tsengine corpus refresh --nvd-url`, URL-only with no boolean twin because NVD publishes no canonical archive to default to — a switch that turned it on with nowhere to fetch from would be a switch that does nothing. The cost was concentrated in ONE place: the L2 digest printed `CVSS %.1f` unconditionally, so `query_threat_intel` told the agent Log4Shell scores **0.0** — a real CVSS value meaning no impact, the strongest de-prioritisation signal there is, asserted for every CVE. It now reports the score as UNAVAILABLE rather than as zero. Note which surfaces were already correct: the finding page renders the score only when `> 0` and the VAPT report likewise, so the human was protected and the agent was not — the exact inverse of the `weapon_rank` gap. A signal is not wired until BOTH consumers have it, in both directions. The hook loads it when `TSENGINE_THREAT_INTEL_CORPUS` points at it, else falls back to the small embedded snapshot (the checked-in default). The corpus dir is gitignored; refresh runs **out of band** (the L0 cron, Â§5), and each scan **pins the manifest version** into `vulnerabilities.json`'s `corpus` block â so it's OSINT-fresh yet pinned for the evidence pack (Â§10), NOT a live per-query API call. **Metasploit is now the 5th source** (`metasploit.go` â the module metadata cache msfconsole itself ships, free/keyless/one GET, best-effort like ExploitDB). It is a DISTINCT RUNG, not a louder ExploitDB: a PoC usually targets one build and needs a shellcode swap or an offset recalculated, whereas a module is use/set/run â usable by an operator who could not write the exploit and does not need to understand it. That is the difference between "someone capable could" and "anyone can, tonight". Only `exploit` modules count (`auxiliary` is scanners/fuzzers, `post` runs after you already have a session â counting either would put version detection on the same rung as RCE), and a reference must be a CVE ID rather than a URL containing one (else a module is credited with every CVE in a blog post it links to). Refs ride the SAME `Entry.Exploits` list (self-describing prefixes, so the dashboard contract gains nothing to version) and surface in `L15Summary` as `weaponized` ALONGSIDE `pub-exploit`, never instead of it, and never as KEV â weaponized says an operator can run it tonight, not that anyone has. Metasploit's own RANK rides along (`weaponized:excellent` … `weaponized:manual` in `L15Summary`, `ThreatIntel.WeaponRank`): a module that never crashes the service and one needing hand-holding are both "a module exists", and it discriminates in practice rather than sitting at the top — live: 1,383 excellent / 261 great / 429 normal / 134 average / 78 manual, with EternalBlue GREAT and Log4Shell EXCELLENT. Best rank per CVE, not average: an attacker uses the most reliable module they have, so averaging would describe the arsenal rather than the threat. Metasploit's scale and names, never one we invented on top of their numbers. Verified against the live feed: 2,525 CVEs. Scope now KEV+EPSS+ExploitDB+Metasploit+CVSS-vectors (NVD); **Nuclei template availability is now the 6th source** (`nuclei.go` â the nuclei-templates project's own `cves.json` index, free/keyless/one GET, streamed line-by-line, best-effort). It is a DIFFERENT KIND OF FACT from the other five: they describe the world (how likely, has anyone, is there a weapon), this one describes US â can we actually check for it. It closes a silent bug in `threatinformed.Plan`, which set `TemplateID = cve` because that is how nuclei names CVE templates. True for the ~4.3k CVEs that HAVE one; for the rest of a ~250k corpus `-id CVE-â¦` matches nothing, and since the plan is CAPPED each such probe DISPLACED one that would have run. `PlanWithGaps` now returns the untestable set alongside the plan and `Plan` keeps its signature for dispatch-only callers â the split matters because a KEV CVE matching observed software that simply vanishes is how a clean probe report comes to mean "we checked everything" instead of "we checked what we could". Degradation is explicit: a corpus carrying NO template data (older, or a refresh that could not reach the index) falls back to the old assume-testable behaviour rather than reading "we know nothing" as "nothing is testable", which would turn a missing feed into zero probes. `Entry.NucleiTemplate` needs its `json:"nuclei_template"` TAG â Go field matching is case-insensitive but not underscore-insensitive, so without it the field stays empty forever and the planner silently reverts (pinned by `TestEntryDecodesTheCorpusFile`). Verified live: 4,326 templates â and CVE-2017-0144 (EternalBlue: KEV, ransomware-linked, two Metasploit modules) has NO template, because nuclei is HTTP-focused and that is SMB. Scope now KEV+EPSS+ExploitDB+Metasploit+nuclei-availability+CVSS-vectors (NVD). **CISA Vulnrichment (SSVC) is the 7th source** (`vulnrichment.go` — the ADP programme's per-CVE decision points, free/keyless, streamed from the repo tarball, OPT-IN via `RefreshOptions.VulnrichmentURL` because the archive is ~300k files, best-effort like the rest). It is the only feed carrying CISA's own DECISION assessment rather than a fact about the world or about us, and its **Automatable** point is the signal none of the other six provides: whether an attacker can automate steps 1–4 of the kill chain, which separates a vulnerability exploited by hand against one target from one that can be driven across an estate. KEV is binary and covers ~1,700 CVEs; SSVC reaches ones KEV never lists, so a defender comparing two CVEs with identical CVSS and neither on KEV finally has something to separate them — from the authority that publishes KEV. Only the `CISA-ADP` container counts: the same file carries a `CVE` container from the CNA, and crediting that to CISA would attribute someone else's judgement to the authority (pinned by a test using a real record where the two disagree). It also DRIVES probe selection, not only annotation: `threatinformed.Plan`'s signal gate was `!kev && epss < MinEPSS && !pub`, so a CVE **CISA says is being exploited right now** but has not catalogued in KEV failed every clause and was never probed for — absence of evidence in OUR feeds read as evidence of absence, against the authority that publishes KEV. `SSVCActive` now qualifies (only `active`; `poc` would double-count the exploit feeds and `none` is the absence of a signal), and ranks +75 — below KEV's +100 because a KEV entry additionally carries a federal remediation mandate and a stricter cataloguing bar. `SSVCAutomatable` adds +20, twice a public exploit's +10. The dispatch PROVENANCE names the signals that actually selected the batch (`threat-intel→nuclei(N templates: 2 KEV, 1 SSVC-active)`), strongest first. It was a fixed "KEV/EPSS-targeted" string, which became wrong the moment SSVC joined the gate: a probe grounded in CISA's assessment that exploitation is ACTIVE was attributed to two signals that had said nothing about it. Â§5.3 keeps `EscalatedFrom` for logging and audit, and a label that misnames why the probe budget was spent is worse than a vague one; a batch whose signal is somehow unrecorded says exactly that rather than claiming one: a weapon that must be hand-driven reaches one target, one an attacker can automate reaches an estate. It reaches BOTH consumers by construction: `threat_intel` (hook 6) attaches it to every CVE-bearing finding, `L15Summary` tags it for the L2 agent (`ssvc-automatable:yes|no`, `ssvc-exploitation:` only when beyond "none", `ssvc-impact:total`), and the finding page states it to the reader. Automatable is surfaced even when the answer is NO, because between two CVEs with identical CVSS and neither on KEV that negative is exactly what separates them. Wiring both at once was deliberate: `weapon_rank` reached the L2 digest for months while the human triaging the finding saw the same sentence either way, and shipping a second signal down only the agent path would repeat that. The decision points are recorded VERBATIM and no SSVC *decision* is computed from them — that needs the defender's own mission and deployment context, which we do not have and would have to invent. In the running platform it is switched on by `TSENGINE_SSVC=1` (or `TSENGINE_SSVC_URL` pinning a tarball), threaded `cmd/platform` → `scheduler.CorpusRefresher.VulnrichmentURL` → `RefreshOptions`; the CLI equivalent is `tsengine corpus refresh --ssvc`. That wiring was ABSENT when the feed first landed, so the parser, corpus field, hook, digest tag, finding badge and probe gate were all reachable only from tests — the same built-but-unreachable shape this campaign keeps finding, authored by it. `CorpusRefresher.refreshOptions` exists as a named seam so the wiring is asserted in microseconds instead of via a stub that reaches the live internet for the other six feeds. **Two KEV fields were being PARSED AND DISCARDED and are now retained** (the same class of bug as vendorProject/product before them, in the same feed, needing no new integration): `knownRansomwareCampaignUse` → `KEVStatus.Ransomware`, and `dueDate` → `KEVStatus.DueDate`. Ransomware use is a STRICTLY STRONGER claim than KEV listing — exploited in the wild vs exploited by crews who encrypt the estate — so the two are kept separate and only the literal `"Known"` counts (CISA writes `"Unknown"` for the majority, and treating any non-empty value as a yes would label most of the catalog ransomware-linked). Both surface in `L15Summary` as `RANSOMWARE` (alongside `KEV`, never instead of it) and `cisa-due:<date>`.

**This corpus is GLOBAL, not per-tenant** â it's world-state reference intel (the same KEV/EPSS for everyone), stored once and shared, never duplicated per tenant; per-tenant data (findings, OSINT exposure, incidents) stays tenant-isolated (Â§18.2 inv-2). The two join at finding emission: a tenant's private finding Ã the global corpus â KEV/EPSS-enriched severity + SLA, pinned for the evidence pack. **Continuous refresh is in-process**: `scheduler.CorpusRefresher` (the GLOBAL twin of `scheduler.Scheduler`'s per-tenant clock) refreshes the shared corpus on `TSENGINE_CORPUS_REFRESH_INTERVAL` (default 24h; 0 disables â rely on the external `tsengine corpus refresh` cron). Best-effort (a failed fetch keeps the last good corpus, never blocks scans), restart-aware (skips the boot fetch when the on-disk manifest is younger than the interval), and disabled unless `TSENGINE_THREAT_INTEL_CORPUS` points at a corpus file. The refreshed file is picked up by the next scan's `threat_intel.enrich` hook (re-read per scan). A future cross-tenant network-effect feed (one tenant's anonymized, consented IOCs warning another) is deliberately gated on isolation + consent â never default.

L2 retains a separate `query_threat_intel` tool for the LLM to look up CVEs that aren't in current findings (chain reasoning across related CVEs). The two are complementary: L1.5 hook annotates emitted findings; L2 tool serves on-demand lookups during reasoning.

---

### 7.1 Threat-informed DISCOVERY (intel decides what to look for)

The corpus above was long used at only ONE point: annotation (plus opt-in KEV
severity escalation). Nothing in the DISCOVERY path consulted it — probe
selection was static/hardcoded (`"api,graphql,jwt,oauth"`, a port→tags map), so
the engine could know a CVE was exploited in the wild against Apache httpd,
detect Apache httpd, and still never probe for it.

**`internal/threatinformed`** closes that loop: `Plan(corpus, observed, opts)`
takes the technology recon ACTUALLY observed (nmap/httpx `ToolArgs["product"]`/
`["version"]` — the same grounded signal `service_eol` consumes) and returns
ranked, bounded CVE probes. Ranking is by real exploitation evidence: KEV
listing (in-the-wild) dominates, then EPSS probability, then a public exploit,
and a product match outranks the same evidence without one. Wired as a
deterministic ESCALATION trigger (§5.3) via
`common.ThreatInformedEscalation`, which batches the selected templates into ONE
nuclei run (`-id` takes a comma-separated list). Enabling data fix: the KEV
ingest was DISCARDING `vendorProject`/`product`; they are now retained on
`types.KEVStatus` (optional/`omitempty` — dashboard contract + embedded corpus
snapshot stay byte-compatible), because they are what makes tech→CVE targeting
possible.

Invariants: **grounded** (§10) — a probe is emitted only for a CVE really in the
pinned corpus with a real exploitation signal, matched via the corpus's OWN KEV
vendor/product strings; no signal → no probe (absence of evidence is not a
reason to spend budget); no CVE id is ever synthesized. **Bounded** —
`TSENGINE_THREAT_PROBE_MAX` (default 25; `Plan`'s own default 50), with a
separate sub-cap for speculative intel-only breadth that is OFF by default.
**Deterministic + LLM-free** — identical inputs yield an identical ordered plan,
so it works today at zero token cost. **Graceful** — no corpus / unreadable
corpus / no observed product → no-op, never a scan failure. Same env var as the
hook (`TSENGINE_THREAT_INTEL_CORPUS`) so annotation and targeting always agree
on the world-state. Wired for **ip** (nmap product+version), **web** and **domain** — domain is the RICHEST observation surface and was the one missing: `PlanFanout` runs httpx across every discovered subdomain at once, so one scan fingerprints the whole estate (dozens of hosts, several distinct products) while web and ip see one target each. Not duplicative of the child-asset pivot: `ChildAssets` spawns web/ip children that each get their own pass LATER and only once the platform spawns them; this is what the scan can say NOW. **`api` is deliberately NOT wired and wiring it would be a NO-OP** — its anchor tier is `["nuclei"]` alone, nothing fingerprints the server, so `ObservationsFromFindings` returns empty and no probe could ever be grounded; **That anchor now exists and api IS wired.** `httpx` joined the api anchor set, so the asset observes what the server runs (`ToolArgs["webserver"]`, a shape `ObservationsFromFindings` already honoured) and `common.ThreatInformedEscalation` consumes it â end-to-end tested: an API served by software with a KEV-listed CVE now plans a nuclei probe for it, where before the engine could know the CVE, be pointed at that server, and never look. Cheap (one request; httpx was already an anchor on web and domain) and grounded: no corpus or no observation is still a no-op. (httpx webserver +
-tech-detect; httpx now emits these STRUCTURED in ToolArgs, not only inside the
title). **container_image is deliberately NOT wired**: grype/trivy already emit
CVE-keyed findings (`grype::CVE-...`) and the `threat_intel.enrich` hook extracts
the CVE from rule_id, so KEV/EPSS already lands on every container finding --
the intel loop is closed there by construction, and a nuclei probe has no live
target inside an image. (An SBOM-x-KEV cross-check for packages grype's DB
missed would need affected-VERSION-RANGE data the corpus does not carry;
guessing from a product-name match alone would be FP-prone, so it is NOT done
-- Sec 10.) **Investigated 2026-08-22 and the reason is stronger than "the corpus lacks ranges".** OSV.dev does publish them free and keyless, but NOT where a by-CVE ingest would look: verified live, the `CVE-2021-44228` record carries ONE affected entry with no package and only GIT commit ranges â the ecosystem data (Maven `org.apache.logging.log4j:log4j-core`, 2.13.0â2.15.0) lives in the aliased GHSA record. So the naive ingest yields package-less records and an SBOM cross-check that matches nothing, reading as "no KEV packages in your SBOM". The deeper reason not to build it: MATCHING a version against those ranges needs per-ecosystem ordering (Maven vs npm semver vs PEP 440 vs Go), and a hand-rolled comparator is the Sec 13 in-house engine, wrong in the direction of telling a customer they are affected when they are not. `osv-scanner` â which we already wrap â does it correctly, and its findings DO reach KEV/EPSS: `preferCVE` rewrites a GHSA-primary id to its CVE alias so `threat_intel`'s rule_id pattern can read it. That four-line function was UNTESTED and is now pinned; simplifying it to `return id` would have silently stripped all threat intel from every GHSA-primary dependency finding, Log4Shell included.

**5th touchpoint — the OFFENSIVE face (ADR 0019, built + wired).** The six feeds above index the
DEFENDER's face of a CVE (how bad / exploited / does a weapon exist — by reference). The offensive
agent needs the ATTACKER's face: the request that triggers the bug. `internal/corpus/threatintel`'s
`exploit_intel.json` sidecar carries, per CVE, a request SKELETON + a conservative candidate predicate,
built by going one level deeper on a feed we already fetch — nuclei template BODIES
(`BuildExploitIntel` streams the nuclei-templates `.tar.gz`; a dependency-free YAML-subset decoder,
`nuclei_yaml.go`, resolves the ADR's one open decision toward hand-parsing per repo convention). It is
a SEPARATE file (never `Entry` fields — the dashboard `corpus` block stays byte-stable), OPT-IN +
best-effort (`RefreshOptions.ExploitIntelURL`, `tsengine corpus refresh --exploit-intel`; a failure
never blocks the KEV+EPSS refresh), and GLOBAL world-state like the rest of the corpus. It is WIRED to
the L2 ModeDeep D-agent: `pentest.ExploitIntelForFinding` (installed by `platformapi`) feeds
`RenderExploitContext` into `specPrompt` as reference material to ADAPT. In the running platform the
sidecar is built by `scheduler.CorpusRefresher` when `TSENGINE_EXPLOIT_INTEL=1` (or
`TSENGINE_EXPLOIT_INTEL_URL` pins a tarball) — off by default, one env var to fuel it; without it the
offensive face is dormant and the checker reads only the defender face. Grounded §10 — the record is
INPUT TO THE PROPOSE STEP ONLY: the skeleton is a payload the model adapts and the matcher is framed as
a fingerprint (NOT the proof), while `specEmbedsCanary` + `DemoFromSpec` still dispose, so a wrong/stale
record widens what the agent TRIES, never what it marks true (zero new FP surface). Phases 2/3
(Metasploit/Exploit-DB bodies) are the documented enrichment.

**4th touchpoint — KEV drives the remediation CLOCK.** Two tiers now: `SLAPolicy.RansomwareResolveHours`
sits *below* `KEVResolveHours` for a CVE CISA marks as ransomware-used, and **CISA's own published
`dueDate` is used VERBATIM as an ABSOLUTE deadline** (`Incident.KEVDueAt`, `SLABreach.CISADeadline`) —
deliberately not a window from `OpenedAt`, because a KEV CVE catalogued six months ago is already past
its deadline and computing a fresh window would silently restart a clock the authority already ran out,
telling a customer they have a fortnight when the government's answer is that they are months late. All
three clocks can only TIGHTEN. `SLAPolicy.KEVResolveHours`
applies the CISA BOD 22-01 deadline to any incident whose opening finding carries
a real KEV listing, REGARDLESS of severity tier (exploited-in-the-wild is itself
the deadline). The flag rides on `Incident.KEV`, stamped in `detect.Reconcile`
from `ThreatIntel.KEV.Listed` (same pattern as Verification/Confidence/Attacked).
It can only TIGHTEN (stricter of severity-target vs KEV window wins), applies even
with no severity target, and sets `SLABreach.KEVAccelerated` so the UI can say WHY
the clock is short. Grounded (§10): disabled policy / no real KEV flag → no
override; a resolved incident never breaches.


Per-task benchmark map:
[docs/security-engineer-tasks-benchmarks.md](docs/security-engineer-tasks-benchmarks.md).

L2 retains a separate `query_threat_intel` tool for the LLM to look up CVEs that aren't in current findings (chain reasoning across related CVEs). The two are complementary: L1.5 hook annotates emitted findings; L2 tool serves on-demand lookups during reasoning.

---

---


## 8. Compliance control mapping at L1

Every finding emitted at L1 carries a compliance annotation. Mapping is **annotation, not gate** â L1 emits the technical finding regardless of whether it maps to a control; the mapping just records which controls it affects.

Frameworks supported (25 â keys defined once in `grc.Frameworks`, mirrored by `pkg/types.Compliance`, the `compliance.json` crosswalk, `internal/tracer/hooks/compliance.go`'s `controlSet`, and `frontend/lib/frameworks.ts`; the `grc.frameworks_e2e_test.go` mirror-consistency + all-frameworks-end-to-end tests gate any drift):

* **Security & trust**: SOC 2 (Trust Services Criteria), CIS Controls v8, NIST CSF 2.0, ISO 27001:2022, ISO 22301:2019 (BCMS)
* **Sector & payments**: PCI-DSS v4.0, HIPAA Security Rule, SOX (IT general controls), GLBA Safeguards Rule
* **Privacy**: EU GDPR, ISO 27701:2019, CCPA/CPRA, India DPDP Act 2023, ISO 27018:2019 (cloud PII), PIPEDA (Canada)
* **Government**: NIST SP 800-53 r5, NIST SP 800-171 r2, FedRAMP Moderate, CMMC 2.0 (Level 2, 800-171-derived)
* **India regulatory**: CERT-In Directions 2022 (Annexure I reportable-incident categories — the
  six-hour reporting duty itself is `internal/certin`, an INCIDENT-level obligation, not a CWE
  crosswalk), RBI Cyber Security Framework (Annex I baseline controls), SEBI CSCRF 2024
  (CSF-structured categories). Mapped by DERIVATION from each CWE's already-curated NIST 800-53
  family, so every India control ref traces to an existing nexus rather than a fresh guess;
  CERT-In is deliberately narrow (only the breach/unauthorised-access categories), because its
  other Directions (NTP sync, KYC records, log retention) are procedural duties with no
  per-finding nexus and mapping them would be exactly the false-compliance §8/§10 forbid.
* **AI governance**: ISO 42001:2023, NIST AI RMF 1.0, EU AI Act (mapped only to the security-relevant AI controls â access, data governance, AI-system lifecycle security; most AI-governance + BCMS controls are procedural â attestation, surfaced honestly by the coverage layer)

Competitor parity (Sprinto/Vanta/Drata): the 25 named frameworks close the bulk of the gap; the remaining tail (CSA STAR, TISAX, C5, FFIEC, FERPA, regional regs) is best served by a custom/"bring-your-own-framework" capability (how Sprinto reaches 200+) â **BUILT** (`internal/grc/custom.go`), not more hard-coded entries. This line called it "the documented next step" for some time after it shipped, which is the inverse of the usual doc drift and just as misleading: a capability we HAVE, described as one we plan.

A finding maps to a framework **only where the crosswalk has a real control nexus** (grounding Â§10) â e.g. an injection CWE cites NIST SI-10 and GDPR Art. 32; a data-exposure CWE additionally cites CCPA Â§1798.150 and SOX access-controls; a memory-safety CWE does not. Adding a framework is one entry in each of the four mirrors above; adding a control mapping is one key in `compliance.json`.

Hook: `compliance.map` fires in the L1.5 hook chain. Sourced from `compliance_corpus/` (versioned YAML), refreshed on cron. Same per-scan pinning as threat intel.

**A CVE-bearing finding with no CWE now reaches this hook with one.** The crosswalk is keyed on CWE and `compliance.Apply` returns early without one — and grype and osv-scanner never set a CWE (only trivy does). So a KEV-listed, ransomware-linked CVE in a container image was getting NO control mapping at all, invisibly: an empty annotation looks identical to a CWE with no control nexus. CISA publishes the CWEs for 89% of the KEV catalog in the feed we already fetch, and they were being parsed and discarded. `threat_intel` (hook 6) backfills it so `compliance.map` (hook 7) picks it up in the same pass — which is exactly why the order in §11 is documented rather than incidental. Grounded §10: fills an EMPTY field only, never overwrites, because the scanner looked at the actual package while CISA describes the CVE in general, and trading specific evidence for generic is the wrong direction. Logged as `threat_intel::kev-cwe-backfill`, so a value the scanner did not report is visible as ours. **The REST of them are now covered too.** That backfill only reaches CVE-bearing findings; `internal/cweattrib` is the triage tier for the others and had NO caller â `Attribute`/`Fill` were reachable only from their own tests, so a measured, carefully-constrained analyser sat inert while the mapping it exists to enable stayed empty. Wired as `runner.Service.AttributeCWEs` (`platformapi.Deps.CWEAttributor`), running BEFORE the chain for the same reason the KEV backfill runs in hook 6 rather than hook 8: hook 7 is what turns a CWE into controls, so a CWE arriving after it is one nobody maps. Gated three ways, all failing toward doing nothing â no tenant model is a no-op (inheriting `resolveAgentLLM`'s plan gate, so Free spends nothing), the allowed set is the crosswalk's OWN keys so an unmappable class is DISCARDED rather than annotated with a veneer of authority, and it is bounded per scan by `TSENGINE_CWE_ATTRIBUTION_MAX` (default 25). **Every attribution is LOGGED to the scan's `l15_audit_log`** (`cweattrib::model-attributed-cwe`), because the class it adds DRIVES the control mapping: without the entry a class a model proposed is indistinguishable from one the scanner reported, and a SOC 2 control shows as affected on evidence nobody can trace. The KEV backfill one hook away set that precedent (`threat_intel::kev-cwe-backfill`) and Â§2.5 requires L1.5 changes to be logged and recoverable â the first wiring of this tier missed both, which is the same defect the tier exists to prevent. REFUSALS are deliberately not logged: a model that declined changed nothing, and a log of non-events buries the entries that record a real change.

**Provenance of the CWEâcontrol crosswalk (`internal/tracer/hooks/data/compliance.json`, embedded):** unlike the threat-intel corpus (KEV/EPSS/ExploitDB/NVD â OSS feeds, Â§7), the crosswalk is **in-house hand-curated** reference data, synthesized from the published framework standards. That's architecturally fine â Â§13's wrap-OSS rule governs *detection*, and this is *annotation* (Â§8), whose discipline is grounding (Â§10: maps only where a real control nexus exists), not OSS-wrapping. There is no single authoritative OSS crosswalk for our 22 frameworks (the SaaS leaders keep theirs closed). What we DO have is an **auditable OSS cross-reference, on two axes**: (1) **controlâframework** â `internal/corpus/controlxref` cross-checks the crosswalk against the **Secure Controls Framework (SCF)** + **CSA Cloud Controls Matrix (CCM)**, the authoritative open control-cross-mapping catalogs that DO cover SOC2/HIPAA/GDPR/CCPA (the gap OpenCRE has). Both ship as a matrix export (row=meta-control, columns=frameworks, cells=that framework's control IDs); `controlxref.Parse` reads either via header-substring matching (per-source `Source` config) and `CrossReference` reports, per framework, how many of OUR control IDs the catalog corroborates (Â§10: a control counts only if the catalog actually lists it; the rest is reported missing, never assumed). The export FILE is operator-provided out-of-band (SCF is CC BY-ND, CCM free; no clean API) â the parser + cross-check are pure/tested. (2) **CWEâstandard** â `internal/corpus/opencre` cross-checks against **OpenCRE** (OWASP); OpenCRE maps a CWE â CRE *nodes* but doesn't cover SOC2/HIPAA/GDPR, so it's the secondary CWE-engineering-link axis (live keyless API). `tsengine corpus compliance-provenance [--scf <file>] [--ccm <file>] [--no-opencre] [--json]` runs all three and reports the OSS-corroborated vs in-house-only split per source (in-house-only = no nexus / a format difference, honest, not a defect). **MITRE ATT&CK is a different axis** (attacker techniques â on every finding's `mitre_techniques`), not a control crosswalk; **UCF** is best-in-class but commercial/non-redistributable â not embeddable. **OSCAL output is built**: `internal/grc/oscal.go` `OSCALComponentDefinition` emits the crosswalk's per-framework control coverage as a NIST OSCAL 1.1 component-definition (the format FedRAMP runs on â GRC-tool-/auditor-ingestible), deterministic (content-derived UUIDs â diffable) + self-contained; served at `GET /v1/compliance/oscal` (downloadable JSON) via `grc.GRC.OSCAL` over the `ControlUniverse`. **Per-tenant findings-as-evidence is now BUILT too** (`internal/grc/oscal_ar.go` `OSCALAssessmentResults` + `grc.GRC.OSCALAssessmentResults`, `GET /v1/compliance/oscal/assessment-results`): the tenant's live control posture rendered as an OSCAL 1.1 assessment-results doc — each assessed control an OSCAL finding with satisfied/not-satisfied status, every not-satisfied control citing an OSCAL observation built from the security finding that PROVED the gap (grounded §10 — a gap's observations come only from its `EvidenceRefs`; nothing asserted without a backing finding). Tenant-scoped, deterministic (content-derived UUIDs → diffable). So the OSCAL story is complete: the component-definition says what the engine CAN assess; the assessment-results say what it assessed on THIS tenant + the evidence.

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

**The security questionnaire (`internal/grc/questionnaire.go` + `questionnaire_corpus.go`) has TWO
evidence tiers, and keeping them apart is what lets it grow.** A questionnaire answer is an
attestation to someone else's procurement team, and the file's own history is the warning: answers
were once derived from control GAPS alone, so a tenant with nothing connected answered "Yes" to
every question including "is MFA enforced?". The fix — a "Yes" requires the EVIDENCE SOURCE to be
connected, else "Not assessed" — is what the OBSERVED tier still enforces.

**Why the corpus is 52 questions and not 261.** CAIQ v4 has 261 and SIG Lite around 300, and
importing one wholesale is the obvious move that makes the deliverable WORSE: most of those ask
about things no scanner can see (HR screening, physical security, BCM rehearsals, legal terms), so
a wholesale import turns ten unanswered rows into two hundred and thirty. The proportion answered
does not improve; the honesty layer just prints more of the same admission. So the corpus grows
along BOTH axes instead — **OBSERVED** (35) expands to everything the engine genuinely evidences
(identity, cloud, endpoints, SaaS, vendors, external exposure, detection and response were all
already assessed and none were being asked about), and **ATTESTED** (17) covers what no scan can
reach, answered by a NAMED HUMAN via `POST /v1/questionnaire/attest/{id}` and rendered as theirs.

The tiers are NOT interchangeable, mirroring `internal/ctoreadiness` which had to make the same
distinction: **an OBSERVED question is never answered by someone typing** (the attest endpoint
REFUSES one — a typed answer would replace an observation with an opinion in a document a buyer
relies on) and **an ATTESTED question is never inferred from findings** (its control mapping exists
so the answer can cite what it speaks to, not as a route to inferring it; letting a finding decide
"have your employees had background checks?" would invent an observation out of an unrelated one).
Both refusals are mutation-verified. `AnswerNo` exists because a questionnaire that could not say
no would be a form with one possible answer, and a vendor honestly reporting a gap is giving the
buyer exactly what they asked for. `AnswerNeedsYou` is deliberately DISTINCT from `AnswerNotAssessed`:
one is fixed by connecting a system and the other by a person sitting down to answer, and merged,
the reader is told to fix the wrong thing — so the rendered document carries the two admissions as
SEPARATE notes above the table. No single percentage is emitted, for `ctoreadiness`'s reason: a
figure mixing "a scanner confirmed this" with "somebody typed yes" would RISE as a customer
connected less and asserted more. An attested row renders "stated by <name> on <date>" — the name
is what stops an assertion reading as something we established, and the date because the age of an
attestation is part of what it is worth. `Tenant.QuestionnaireAttestations` is a SEPARATE map from
`ReadinessAttestations` (distinct id namespaces — a readiness practice and a questionnaire question
can both be "BC-1" — and merging them would let an answer given for one purpose silently answer the
other). A question earns an OBSERVED slot only when a detector in this tree really produces the
signal; adding one for a capability we lack would sit at "Not assessed" forever while implying a
check exists.

**Five emission paths feed the framework set** (all grounded, all annotation-only) â keep them in sync when adding a framework or control:

1. **CWE crosswalk** â `internal/tracer/hooks/data/compliance.json` (the `compliance.map` hook) maps a finding's CWE â controls. Covers appsec/SAST/SCA findings.
2. **Identity findings** â `internal/operate/operate.go` annotates each check inline (MFA gaps, OAuth grants, email-auth, stale/over-privileged accounts, incomplete-offboarding: a *suspended* account that still holds an admin/super-admin role binding — standing privilege that survived the disable, the deprovisioning-completeness blind spot the active-account checks skip) â the non-tech / IdP posture.
3. **Cloud attack-paths** â `internal/cloudengine/compliance.go` (`pathCompliance`) maps an attack-path's characteristics (internet exposure, sensitive-data access, privilege/privesc, lateral movement) â controls.
4. **SaaS posture (SSPM)** â `internal/sspm` annotates each SaaS-config check inline (GitHub org: 2FA enforcement, repo perms, secret scanning, third-party apps, webhooks; Slack: 2FA/SSO, app governance, public sharing, guests, admin sprawl; Zoom: meeting passcode/waiting-room, recording protection; Atlassian: public Confluence spaces, SSO-bypassing API tokens; Salesforce: Experience-Cloud guest access, Modify-All-Data sprawl; **M365 (`m365.go`): the COLLABORATION/DATA-SHARING half â SharePoint/OneDrive anonymous & external sharing, Teams guest access + open federation, legacy(basic)-auth, mailbox-audit-disabled, anonymous calendar â DISTINCT from the M365 IDENTITY posture `operate` already does (MFA/OAuth/stale), closing the "we did M365's identity but not its SharePoint/Teams data-sharing" SSPM gap; M365 + Google Workspace are the two most-common SaaS estates; **Google Workspace (`gworkspace.go`): Drive public/external sharing, link-sharing default, less-secure-apps, third-party API access, Gmail external auto-forward, external calendar â the sibling data-sharing posture to M365**) â the SaaS-configuration posture, sibling to `operate`. Snapshot-driven, LLM-free, grounded (a hardened app yields zero findings). See ADR 0004. **Live driver: `POST /v1/saas/{provider}/snapshot`** (`internal/platformapi/saasposture.go`, provider ∈ github_org|slack|zoom|atlassian|salesforce|m365|google_workspace) decodes the provider snapshot, runs the matching `Assess*`, and stores the findings into the same store the rest of the platform reads â so SaaS misconfigs flow through issues/incidents/grc/hitl like any finding (mirrors the identity-events ingest). The admin-API fetcher (snapshot from the provider's API) is the credential-gated half; the posted-snapshot path works today with no external creds. **GitHub org now has a LIVE fetcher: `POST /v1/saas/github_org/sync`** (`internal/platformapi/saassync.go` + `sspm.FetchGitHubOrg`) builds the snapshot from the GitHub API reusing the already-onboarded GitHub connection's token (no new credential) â reads what `read:org` covers (org-wide 2FA, default repo permission, public-repo creation, GHAS secret-scanning default, org webhooks best-effort), runs the same `AssessGitHubOrg`, stores findings. Per-member 2FA / installed-app inventory / outside-collaborators need `admin:org` + heavy pagination, so those checks stay the posted-snapshot path's job (honestly gated, never invented â Â§10). Surfaced via the Settings "Sync posture" button on the GitHub connection.

5. **OSINT external exposure** â `internal/osint` annotates each open-source-intelligence finding inline (**stealer-log dark-web exposure** â a corporate credential harvested by infostealer malware, critical w/ plaintext password â GDPR Art. 33/34 + SOC2/PCI, the highest-severity OSINT signal; breached credentials â GDPR Art. 33/34 + SOC2/PCI; leaked secrets; internet-exposed hosts â SOC2 CC6.6/CC7.1 + CIS; data exposure â GDPR/CCPA; typosquats; subdomain takeover (a dangling DNS record pointing at a deprovisioned/unclaimed service — the canonical EASM finding; high, SOC2 CC6.1/6.6/7.1 + GDPR Art. 32 + NIST CM-8/SC-7); certificate posture from CT-log monitoring (unexpected-issuer cert = mis-issuance/phishing prep, + expired/expiring served certs); advisories). The attacker's-eye external footprint, snapshot-driven, LLM-free, grounded (a clean footprint yields zero findings). **Live driver: `POST /v1/osint/ingest`** (`internal/platformapi/osint.go`) decodes an OSINT snapshot (normalized from theHarvester/SpiderFoot/dnstwist/HIBP/taranis-ai), runs `osint.Assess`, and stores findings into the same store â so external exposure flows through issues/attack-paths/grc/hitl like any finding. `GET /v1/osint` + the `/osint` "External exposure" page. The live collectors (sandbox tools + HIBP/Shodan APIs) are the credential-gated half; the posted-snapshot path works today with no creds. See ADR 0011.

So a connected repo, Workspace/M365/Okta, cloud account, SaaS app (GitHub org), *or* an OSINT snapshot each contribute evidence to the full 25-framework set, not just the original six. A control maps only where a real nexus exists for that path (grounding Â§10).

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

**Two doors, both now enriched (Â§11).** `platformapi.handleReplay` (the tenant path) has always run `l15.Enrich`; `internal/replay` (the CLI/standalone engine, mounted at `/replay` by `internal/server`) returned RAW tool output until 2026-08-22 â so the same "investigate deeper" action produced an annotated finding through one door and a bare one through the other, and the bare one went to the security engineer driving the engine directly, who is exactly the audience Â§2.1 says prioritises by exploited-in-the-wild. **The append below is still aspirational for the CLI door**: it returns findings in the response and appends to no scan file. arch.md now says so rather than describing the intent as the behaviour.

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
| Effective-permission claims come from the evaluator, never the model | "Can X do Y on Z?" is answered by a per-cloud evaluator, not the LLM's recollection: `cloudiam.Authorize` (AWS: identity â§ boundary â§ SCP â§ resource-policy â§ conditions), `gcpiam.Authorize` (GCP: hierarchy-inherited bindings â§ roleâperms â§ IAM-deny â§ conditions), `azureiam.Authorize` (Azure: hierarchy-inherited role-assignments â§ role-def Actions/NotActions â§ deny-assignments â§ ABAC). All three feed `cloudgraph.PruneUnauthorized`, which drops an over-approximated edge ONLY on a DEFINITIVE deny â AWS assume-role via the target's `trust_policy`, GCP SA-impersonation via `gcp_iam_policy`, Azure escalate via `azure_rbac_policy` â and KEEPS the edge on any missing/uncertain data (an unresolved condition / group / unknown custom role â conditional). So multi-cloud attack-path reasoning is now symmetric across AWS+GCP+Azure; the live per-cloud policy data is the sandbox-side ingest source's job to emit (the honest gate). Privesc-EDGE generation is also symmetric: `cloudiam.Techniques` (AWS, 21 Rhino/PMapper methods) + `gcpiam.Techniques` (GCP, the Rhino "Privilege Escalation in GCP" set — setIamPolicy, SA-key/token mint, actAs-deploy, Cloud Build, custom-role update) + `azureiam.Techniques` (Azure ARM, the RBAC privesc set — roleAssignments/write, elevateAccess, roleDefinitions/write, VM run-command/extension as managed-identity, automation runbook, Function/Web app as MI, Key Vault access-policy) each feed `DetectPrivesc` â a `privesc â admin` edge via `cloudgraph.AddPrivescEdges` (AWS) / `AddGCPPrivescEdges` (GCP) / `AddAzurePrivescEdges` (Azure). So privesc-edge generation is symmetric across all three clouds. The ingest builds the per-principal `can` predicate from the snapshot's IAM bindings (the honest gate, same as the Authorize side). The Azure AD/**Entra graph-plane** privesc catalog is now BUILT too (`azureiam.EntraTechniques` + `DetectEntraPrivesc`, `entra_privesc.go`): a DISTINCT authorization plane from ARM (§10 — never conflated), over Microsoft Graph application permissions + privileged directory roles (RoleManagement.ReadWrite.Directory → self-assign Global Admin; Application.ReadWrite.All / Application Administrator → add a secret to any privileged app; AppRoleAssignment.ReadWrite.All; GroupMember.ReadWrite.All; Privileged Authentication/Role Admin). `cloudgraph.AddAzureEntraPrivescEdges` adds an `Entra:`-labeled `privesc → admin` edge, so an attacker who owns the tenant via Entra (never touching an ARM role assignment) is no longer invisible. Same honest gate: the ingest builds the `can` predicate from the Entra snapshot's app-role assignments + directory-role memberships (`azureiam.EntraCanFromGrants`). The RELATIONSHIP half is BUILT too: `cloudgraph.AddEntraOwnershipEdges` — owning a PRIVILEGED service principal (or one that can itself escalate) lets you add a credential and act AS it, so the owner gets an `Entra:OwnerOfPrivilegedSP` `privesc → admin` edge (the canonical BloodHound "Owns → AZServicePrincipal" attack path). Grounded §10: an edge is added only when the owned node is really privileged (its `Node.Privileged` flag OR an existing privesc→admin edge — run it after `AddAzureEntraPrivescEdges` to inherit permission-escalating SPs); owning a non-privileged SP adds nothing. The ingest supplies the app/SP `owners` map (the honest gate). **A "conditional" allow is now THREE distinct states, not one** (`gcpiam.scanBindings` → `PermitsGrantedButGated`), because collapsing them was a real defect in both directions: (a) a KNOWN role granting the permission to a CERTAIN member, gated only by an IAM condition — we know exactly WHAT and WHO, only WHEN is open; (b) an unknown custom role; (c) an unresolvable group — in both of which the grant ITSELF is in doubt. Privesc derivation refuses (b) and (c) (**the firm-allow rule** — "an escalation inferred from a role definition we do not have is not evidence, it is the absence of it"; without it one unknown custom role makes every principal appear able to escalate twenty ways) but REPORTS (a) marked config-possible. Measured before the fix: a member holding `roles/resourcemanager.projectIamAdmin` under a condition satisfied *today* produced ZERO privescs, so the attack-path page said there was no route to admin. Dropping it silently is itself a claim and a worse one — §10 permits saying "we could not resolve this", never silence. `cloudgraph.PermitFunc` (`func(perm) (allowed, conditional bool)`) carries both bits across the GCP/Azure/Entra bridges for the same reason a single bool could not: it forces a choice between over-claiming and vanishing. `cloudgraph.Unconditional` adapts a source whose grants genuinely carry no conditions (Entra app-role assignments), so that claim is made explicitly at the call site rather than by omission. |
| CI/CD identity transitions are evaluated, never assumed | "Can a workflow in this repository assume this cloud role?" is answered by evaluating the REAL trust document against the claims the provider would really mint — `ghoidc.CanAssume` through `cloudiam.Authorize` (AWS, via the new `Federated` principal), and `gcpwif` reading the pool provider's attribute condition TOGETHER with the service account's binding (GCP splits the decision across two objects, and neither half is sufficient alone). Grounded §10 in both: a Federated principal match is config-possible and only the sub/aud conditions decide; a context too thin to render a subject is REFUSED rather than guessed at; an unparseable trust policy is not assessed and certainly not safe; and in BOTH, a federation to an issuer we do not model is DECLARED rather than dropped. **`ghoidc` is now WIRED**: it had NO caller â `Assess` was reachable only from its own tests, so every finding this analyser can produce was invisible to the product, and the CI-identity surface was unreachable in exactly the way that motivated building it. `platformapi.ciIdentityFindings` runs it on every posted AWS inventory (`POST /v1/cloud/inventory`), whose `RawIAMRole.TrustPolicyJSON` was already in hand and already parsed for trust principals â a wiring gap, not a data gap â and stores through the same enrich path as drift, so a federated-trust finding flows into issues/incidents/grc/hitl like any other. `Privileged` comes from the collector's `Admin` flag (the source `ghoidc`'s own doc names), `ReposComplete` stays FALSE because a cloud inventory says nothing about repository ownership, and **GCP is wired too.** `RawGCP` gained `WIFProviders` (the pool providers) and per-SA `Bindings` â the SA-level IAM policy, distinct from the existing flat `Impersonators` list, which carries no ROLE and so cannot tell an impersonation grant from an unrelated one; assuming the role would be guessing at the fact the finding turns on. `gcpwif` runs on `POST /v1/cloud/inventory?provider=gcp` and its value is the JOIN: an unconditioned pool provider and a pool-wide impersonation binding are each unremarkable alone, and together let any GitHub repository on the internet impersonate the service account. Tested end to end through the DISPATCH, not just the assessor â mutation showed the direct-call tests passed with the routing removed, which is the built-but-not-wired gap reproduced inside the tests meant to prove wiring. `gcpwif` had the same silent skip as `ghoidc` and one worse case: `if len(github) == 0 { return a }` returned a ZERO-finding assessment with no note, so an estate federating entirely through Okta read completely clean, and a service account impersonable from such a pool was skipped at `if !governs` â an impersonable SA looking exactly like an unreachable one. Both now land in `ChecksNotRun` NAMING the issuer, while a genuinely un-federated estate still declares nothing (asserted by test â a gap announced where no federation exists is the same overclaim pointed the other way); and adequacy of a PRESENT CEL condition is never asserted, only its absence. |
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

**Two of these assessments reached the AGENT and not the READER.** `corroborator_ledger` (hook 5) attaches the agreeing rule ids and `surface_priority` (hook 3) a {score, reason} — both rode the L2 digest (`corrob:N`, `surface:N`) and the L2 ranking boost, and `corroborated_by` also rendered in the zero-JS console, while the flagship finding page showed the WORD "corroborated" beside a confidence number and never which tool agreed. That citation is the substance of the claim and the first thing a sceptical reader asks for; Â§10 is that every recorded issue cites tool evidence, and the evidence was computed and withheld. `surface_priority` is the same {score, reason} shape as `exploitability`, sitting in the same struct and rendered on the same row â one was shown with its reason and the other was not. Both now render, guarded by `internal/uicheck`. The recurring shape is worth naming: a new L1.5 signal gets wired to the agent because that is where the author is working, and the human surface is a separate file nobody opens â so ASSUME the reader half is missing until checked.

`findings_raw` is captured **before** hook 1 â that's what the security engineer reads. `findings_enriched` is the post-hook view. Both ship.

**The chain runs on BOTH doors — but the engine door had to be WIRED, it was never automatic.** The
claim that engine-scanned findings "reach the host tracer via the sandbox sidecar, so the hooks fire
by construction" was FALSE for the platform: only `cmd/tsengine` (the CLI) ever built a tracer, and
no tracer exists in `internal/orchestrator` or `internal/sandbox`. `runner.scanAsset` stored whatever
the scanner returned, so every repo/container/web/api/ip scan through the PRODUCT landed with no
KEV/EPSS, no exploitability, no FP filtering, no compliance mapping and no confidence — while the
secondary ingest paths were fully enriched. The chain now runs on the engine path via `l15.Enrich`
(`internal/l15`, shared because platformapi imports runner so runner cannot import it back). Findings that enter through the platform's OWN ingest paths -- identity events, OSINT
snapshots, SaaS posture, TPRM, device posture, cloud drift (config + CDR), TLS scan -- used to call
`Store.PutFinding` directly and land UN-enriched (no threat-intel, no exploitability, no confidence;
any CVE they carried never got KEV/EPSS). `platformapi.enrichFindings` (`internal/platformapi/enrich.go`)
closes that asymmetry: each ingest handler runs the batch through a host-side `tracer.New(DefaultPerFinding,
DefaultFinalize)` before storing, so a finding is enriched the same way no matter which door it came in.
Safe for posture/config classes: the `compliance.map` hook MERGES (never clobbers) the inline mapping
each detector already set, and threat_intel/service_eol/exploitability no-op without a CVE/product/
critical-CWE -- so a config finding keeps its inline compliance and gains corroboration+confidence, while
a CVE-bearing one also gains KEV/EPSS. Honors `TSENGINE_L15_DISABLED`. **`cloudinvestigate.go` (the AI
Cloud Engineer's own attack-path findings) is now wired too** -- it builds a finding per L2 Issue then runs
the batch through `enrichFindings` before storing, so the agent's findings are first-class (exploitability/
confidence + KEV/EPSS on any CVE + merged compliance), not the second-class inline-built findings they used
to be. The `cloudinvestigate.go`-not-wired caveat is closed.

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

**A tool's EXIT CONTRACT is declared at the call site, not assumed from the tool.** `tool.DidNotRun`
separates "never ran" (missing binary, 126/127, killed) from "ran and exited non-zero", and every
wrapper then SWALLOWED the second case and parsed whatever came out. That is right for semgrep,
gitleaks and hadolint, which exit 1 to MEAN "found something", and wrong for any tool not given a
findings-exit flag. Measured: we pass no `--exit-code` to trivy and no `--fail-on` to grype, so both
exit non-zero only on ERROR — and
`TRIVY_DB_REPOSITORY="::::invalid" trivy fs` (exit 1, 0 bytes stdout, FATAL on stderr) came back
through our wrapper as `err=nil, findings=0`. **A scanner that could not reach its vulnerability
database reported a CLEAN SCAN**, the pass stayed authoritative, and the three absence-reasoning
consumers acted on it: `detect.Reconcile` resolved incidents, `retest.Verify` confirmed fixes,
`grc.Reconcile` flipped control gaps to MET. The degraded-pass guards built for exactly that cascade
never fired, because the failure never became a failure.

So `tool.Failed(err, findingExits ...int)`: a wrapper names the exits ITS flags make mean "found
something" (usually none) and everything else is an error. The declaration is per call site because
it depends on the flags that call site passes — which is precisely what the old comment got wrong
about trivy. `tool.ExitDetail` carries the stderr line naming the cause into the failure reason,
because "exit status 1" is the same string for a bad credential, an unreadable target and an
unreachable DB, and that string is what an operator reads in `Scan.ToolsFailed`.

**A BLANKET RULE IS NOT THE SAFER DIRECTION.** Flipping all 37 wrappers on the assumption that
trivy's semantics generalise would report every successful semgrep scan as a failure — a permanently
degraded pass in which incidents never resolve and no fix is ever confirmed. trivy and grype were
converted because their behaviour was MEASURED; the remaining 34 are recorded in
`internal/tool.swallowing` as the honest, countable remainder, and
`TestExitContract_NoNewWrapperMaySwallowSilently` is a ratchet: a NEW wrapper may not join that list,
and a converted one must leave it.

**Scanner versions are PINNED and CI enforces it — and the FIRST attempt at this was a vacuous pass.**
Four tools (dalfox, subfinder, gitleaks, naabu) floated on `latest`, so two builds of the same
Dockerfile shipped different scanners and no evidence pack could say which tested the customer. They
were pinned and `tool-freshness --fail-on-floating` was switched on in `.github/workflows/
signatures.yml`. **The gate then passed on a tree where ELEVEN MORE SCANNERS STILL FLOATED**, because
`toolfresh` matched only `ARG *_VERSION` / `go install` / pinned-pip lines and this image installs
most of its Go scanners via the `ts_install` helper and its Python scanners by appending to a `PKGS`
shell variable. 8 of 45 tools were visible; the report read `0 floating · 0 unmanaged` and a CI gate
was built on top of that. §14.2 rule 6, reproduced inside the tool written to enforce it — the guard
was green at the moment it was least able to see.

Now: 21 pinned · 0 floating · 14 unmanaged of 35 seen. `ts_install`, the `PKGS` list and branch-ref
`curl | sh` installers are all parsed; a version given as `@${ARG}` defers to the ARG rather than
being counted as a literal pin (which classified an irreproducible build as reproducible). The
unmanaged 13 (sqlmap, checkov, scoutsuite, syft, trufflehog, …) are **rendered and named**,
not just counted — pinning a PyPI/OS package can break the install, so they are reported rather than
gated. `Render` states its OWN coverage, because a tool absent from every list must read as
UNVERIFIED, never as confirmed-pinned. When adding a scanner, check `tool-freshness` actually SEES
it; the parser's floor test (`len(r.Tools) < 25`) exists because 8 tools cleared the old floor of 6.

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

**NONE OF THE ABOVE IS IMPLEMENTED, and it is documented here as though it were.** `tool.Result.SandboxEmittedFindings` (json `_sandbox_emitted_findings`) is declared once in `internal/tool/tool.go` and written by NOTHING â no tool, no tool-server, not even a test. There is no sandbox-side tracer, `cmd/tool-server` holds none, and `internal/sandbox.Client.Execute` calls no host tracer, so no key is stripped because none is ever set. What really happens: a sandbox tool returns findings in `Result.Findings`; the client returns the Result unchanged; the ASSET HANDLER's `Normalize` lifts them (`internal/asset/common.emitted` reads the union of both fields, which is why the unused one is harmless); and `l15.Enrich` runs over the normalized set â that is where the hooks fire. The consequence worth keeping: findings do NOT self-propagate from the sandbox client, so a new asset handler that does not lift them in `Normalize` emits nothing. Pinned by `internal/tool.TestSandboxEmittedFindingsHasNoWriter`, which fails if the sidecar is implemented without these two documents being corrected.

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
  **sqlmap, wpscan, nuclei, ffuf, hydra, padbuster**. It is ONE catalog slot acting as a GATEWAY, not N
  per-tool slots -- which is why it does NOT break the <=12-tool spirit (Sec 2.6). (This line used to
  say "the 14th webagent tool"; the agent has grown well past that. An ORDINAL in a doc is a number
  nobody updates when the thing it counts changes, and the count was never the point -- one slot
  reaching many tools is.)
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

### 12.8 The engagement fleet + worldview (`internal/fleet`, ADR 0030 — Phases A–D BUILT)

The offensive agents scale out WITHOUT changing: `webagent.Investigate` is called UNCHANGED per
worker (strangler-pinned byte-identical at 1 worker). The coordinator decomposes an authorized
surface into an intelligence-led, capped chunk plan (scanner seeds ranked by L1.5 enrichment >
CVE probes > crown-jewel routes > shape-deduped residual — ordering IS the bound), splits it into
state-coupled WAVES (auth-dependent chunks run after establishment; shared `StateKey` or shared
route never share a wave), and runs ≤N workers per wave. Every worker is bound by a shared
`fleet.Governor`: ONE request envelope drawn down atomically across workers (the absolute wall) +
ONE latching breaker with health kinds (`waf_blocked`/`target_unhealthy` recorded from grounded
Coverage facts; `session_invalidated` API-wired, no auto-detector yet). Termination guards are
deterministic and disclosed: schedulability skipping (settled route×class at CoverK costs zero),
a stall watchdog (StaleWaves verdict-free waves → halt naming what didn't run), envelope/breaker
halts with disclosure. Health signals are ALL grounded: `waf_blocked`/`target_unhealthy` from Coverage facts,
`session_invalidated` from the deterministic `webauth.IsLoginWall` classifier counted during the
run and recorded ONLY for chunks that declared an authenticated session. The WORLDVIEW is the
per-engagement coverage ledger keyed by `estategraph.Canonical("web", route)` × class —
evidence-or-refuse (`ErrNoEvidence`), Contested-not-averaged (Vulnerable×Clean → Contested, with
PER-SIDE evidence buckets so Phase D's panel can judge actual turns). Adjudication
(`AdjudicateContested`) is an odd 3-persona majority that may only SELECT between the two
evidenced sides (`ResolveContested` refuses everything else); ties/abstentions/failed panels KEEP
Contested with every vote recorded — fail-open as an outcome, never silence. Assurance tiers:
`fast` = CoverK 1; `verified` = CoverK≥2 + envelope ×2 (paid through the clamp, disclosed) + panel.
Usage/cost: all three cloudengine clients now accumulate usage (they parsed-and-discarded it);
pricing lives ONCE in `cloudengine.EstimateCost` and l2 delegates — fleet and L2 runs priced by
one book; a brain without usage renders "unknown", never "$0"; engagement totals exact via one
shared counter, per-worker attribution approximate by design. A route with no verdict
renders as "NO established verdict", never clean. D6 estate write-back DEFERRED until a worker
produces cross-surface claims (no producer = no pipe). CLI: `tsengine web-investigate --workers N
--assurance fast|verified` / `TSENGINE_FLEET_WORKERS`, `TSENGINE_FLEET_ASSURANCE`; unset =
today's single-agent engagement exactly.

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

**AI-application security** (testing the customer's OWN LLM features — prompt injection, jailbreak, insecure output handling, the OWASP LLM Top 10) is genuine whitespace: tsengine covers AI *governance* (ISO 42001 / NIST AI RMF / EU AI Act, §8) + *inventory* (AI-BOM, WRD-1) today, but not AI-app vuln *detection*. The approach is fixed in [docs/adr/0012-ai-application-security.md](docs/adr/0012-ai-application-security.md) — a wrapped-OSS `ai_application` asset (anchor: **garak**; registry: promptfoo/PyRIT), active-by-nature so gated by the RoE Guard + consent + ownership-verification — NOT an in-house detector. **The garak wrapper IS built** (`internal/tool/garak`, registered in BOTH `toolsbundle` and `cmd/tool-server/imports.go` per §12.7, installed last in the sandbox image so its large ML dependency set degrades alone). Its parser only counts a SCORED detection — garak logs every attempt including the ones the guardrail correctly refused, and counting lines would grade a well-defended app as riddled — reports one finding per probe class rather than per attempt, and carries the prompt sent AND the response received, because "the model said something bad" is a claim whose severity depends on context no scanner has. **The `ai_application` ASSET TYPE is still not built**, so nothing can be pointed at it yet; the readiness row stays UNBUILT and says exactly that, because claiming a row on the strength of a tool nobody can reach is the same overclaim as a green tick for a scan that never ran.

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
  **Cross-surface footholds reach the cloud DEPTH agent (G2):** the cloud specialist (`internal/cloudagent`)
  reasons over the cloud graph in isolation and had no crossdetect awareness, so it could not know a leaked
  key in code IS a foothold in the account. `platformapi.cloudBridges`/`bridgeHint` now extract the
  code→cloud (or web/host→cloud) chains from `crossdetect.Correlate` and feed them as grounded
  `cloudagent.Context.Bridges` ("CROSS-SURFACE ENTRY POINTS" in the agent prompt) at both the on-demand
  handler and the L2-delegated `cloudInvestigator`. Grounded (§10): a hint only tells the agent WHERE to
  look; it still confirms every recorded issue in the graph, so a bridge never authorises an ungrounded
  finding — the wedge's fuel delivered to the one agent that can deeply reason about IAM reachability.

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
| cloud_account · IAM privesc (EXTERNAL) | `internal/bench/iamvulnerable.go` + `iamvulnerable_fpfn.go` (`IAM_VULNERABLE_DIR` / `IAM_VULNERABLE_TOOLTEST_DIR`) | recall over BishopFox's ~31 named paths + **FP/FN control set** | **BishopFox IAM-Vulnerable — the first capability answer key in this repo we did not write.** Scored 64.5% on first run against 100% on every in-house bench; the FP set (deny precedence, resource/condition constraints) is the half that can go DOWN when detections are added |
| cloud_account · GCP privesc (EXTERNAL) | `internal/bench/gcpprivesc.go` (`RHINO_GCP_CATALOGUE`) | recall over RhinoSecurityLabs' 23-method catalogue | **Rhino's published research — the same one `internal/gcpiam/privesc.go` already cited.** Scored 65.2% on first run, almost exactly AWS's 64.5%: two independent keys each said ~two thirds, and no internal number ever did. **RECALL ONLY** — GCP has no published FP control set, so read it one-sided |
| identity/SaaS posture (EXTERNAL) | `internal/bench/scuba.go` + `scuba_test.go` (`tsbench` not needed — corpus is transcribed) | detection recall over CISA's baselines, stated three ways (total · scanner-detectable · mandatory-SHALL) | **CISA SCuBA — the strongest external key here, because its mappings are EXECUTION-PROVEN**: for every mapped policy the test builds a violating snapshot, runs the real assessor and asserts the rule fires, so an unproven mapping FAILS rather than inflating coverage. Went 0.322 → 0.753 → **0.993** (SHALL 0.426 → 0.842 → **0.990**; 145/146 detectable, 100/101 SHALL) over successive passes, and refused four distinct mistakes on the way: two unproven mappings, one attempt to claim policies CISA scopes procedural, and one product design error (two findings written mutually exclusive, which would have under-reported the tenant that had done the harder half of the work) |
| improvement loop (ADR 0018 item 2) | `tsbench improve --journal <file>` (`internal/improveloop`) | which capability to work on next, or why the loop STOPPED | Internal instrument â it decides, it does not improve |
| L1.5 ablation | (any L1 bench) + `TSENGINE_L15_DISABLED=1` | Î-metric = L1.5 lift | Internal |
| L2 agent | `bench/agent` (scorer + `tsbench agent`); live targets `bench/webgoat_dual` + `bench/juiceshop_full` | detection_rate, **verified_rate** (PoC/evidence-grounded â the XBOW no-FP bar), completion_rate, FP-control | vs XBOW / strix / NodeZero (exploitation-verified) |
| L2 agent (defense) — **AI Security Engineer** | `tsbench defense` (`internal/bench/defense.go` + `defense_ledger.go`); seeded code+cloud estate scenarios under `fixtures/defense/` | **remediation-capture** (seeded vulns verifiably closed on re-scan, via the SAME `retest.Verify` the product uses — the defensive XBOW-clean hero metric) + attack-path recall + triage precision (decoys) + grounding (FP=0); **substrate-vs-agent ablation** = the LLM engineer's measured lift | Internal (no neutral AI-SOC leaderboard exists — the honest gap) |
| L2 agent (defense) — **AI Security Engineer**, XBOW-derived | `tsbench defense-xbow` (`internal/bench/defensexbow*.go` + `internal/codeagent`; ADR 0014) over the same XBOW suite | **remediation-capture**: patch the real vuln → the RECORDED winning exploit no longer captures the flag AND the app still functions (the anti-sabotage regression guard) — execution-verified, by vuln CLASS; `--patch-file`/substrate vs LLM ablation | vs XBOW (offense-only — a lane it doesn't have: exploit it, then prove you can fix it) |
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
5. **An in-house answer key measures whether the fixtures and the code agree — not whether the
   product works.** Every capability bench here scored ~100% while two external keys independently
   put the same capability at ~65%. Where a neutral corpus exists, score against it and record the
   number BEFORE closing the gaps it names: fixing in the same commit that introduces the benchmark
   makes the result unfalsifiable. And once a corpus has told you what to add it is **no longer held
   out** — say so, and treat its FP half (if it has one) as the number that still means something,
   because recall can only rise when detections are added.

6. **A guard that cannot see its subject must FAIL, not skip.** Audited 2026-08-22: three guards called `t.Skip` when their input file was missing â the homepage positioning check, the marketing-copy walk, and the per-asset anchor-tool check. A skip is GREEN, so each stopped guarding at exactly the moment it was most needed: a renamed homepage is the change most likely to drop the approval-gate claim, and a refactored handler is when arch.md's anchor list goes unverified. This is Â§10's own distinction â "we looked and it was fine" versus "we could not look" â applied to the test suite. Related and equally invisible: a guard whose PATTERN matches nothing also passes, so a pattern-driven guard asserts a minimum match count (`internal/archcheck`'s route check failed its own mutation test by matching nothing, because the docs write the method inside the backticks, as in `GET /v1/coverage`, and it required a backtick followed immediately by the path). **Mutate the guard; a check that never ran is indistinguishable from one that passed.** The rule keeps catching its own author: `archcheck`'s route guard â added the day after the rule â `continue`d past a living document it could not read, so deleting `docs/platform-operations.md` (the OPERATOR GUIDE) left it green, the other three documents clearing its count floor on their own. A guard that quietly stops checking one of its subjects is worse than no guard, because the green tick now covers less than anyone reading it believes.

   A corollary the in-house scorecard needed: **a corpus must not SHRINK.** `internal/accuracybench` (`tsbench accuracy` â it had no runnable entry point, though it did gate itself via its own test) asserts every core at 1.00/1.00 and non-empty, which catches an accuracy regression but NOT a corpus that goes from 34 cases to 2: that still passes, at a perfect score, as a strictly weaker claim wearing the same number â the vacuous-pass shape where a rate rises as the evidence behind it disappears. Per-core case floors are recorded and gated. Live: 6 cores, 107 labeled cases, all perfect â which measures fixtureâcode agreement, NOT efficacy, and sits against BishopFox 64.5% and Rhino 65.2% on the same class of capability.

---

## 15. Coding conventions (Go)

* Module path: `github.com/ClatTribe/tsengine` (placeholder â confirm before phase 0)
* `go.mod` Go version: 1.22+
* Errors: `errors.Is`/`errors.As`; wrap with `fmt.Errorf("%w", err)`. No string-based error matching
* Context: every public function takes `context.Context` as first arg; honor cancellation
* Concurrency: `golang.org/x/sync/errgroup` for fan-out; bounded semaphore (`chan struct{}`) for tool dispatch (default `TSENGINE_DISPATCH_CONCURRENCY=4`)
* Tests: `go test ./...` standard; integration tests under `tests/integration/` gated by `-tags=integration`
* Lint: `golangci-lint run` with the project `.golangci.yml`; `govulncheck` on every PR
* **`make gate` before pushing** â gofmt + vet + test + the frontend typecheck, in one command that FAILS rather than reports. `make all` is `build test vet` and does not check gofmt, so formatting drift reached CI as a lint failure. The trap is specific: `gofmt -l` PRINTS the drifting files and exits 0, so any pipeline that greps its output without checking emptiness reports success on a broken tree â the same "reports a problem, exits happy" shape as the guards in Â§14.2 rule 6. It FAILS when the skip MATTERS: no `frontend/node_modules` AND modified `.ts`/`.tsx` in the working tree is an error naming the files, because a gate that skips the check for the files you just touched reports success on an unchecked tree â Â§14.2 rule 6 applied to the build, which the first version of this target got wrong by printing a notice and exiting 0. With no TypeScript changed it says tsc did not run and passes, so Go-only work is not blocked on a node install.
* Iter naming: `iter-XX.Y` in commit messages, code comments, and test file names where relevant
* PRs: squash-merge via `gh pr merge <N> --squash --delete-branch`
* **Always update CLAUDE.md and arch.md when architecture changes**
* **Releasing: [RELEASE.md](RELEASE.md).** One `v*` tag fires BOTH `release.yml` and `images.yml`,
  publishing twelve artifacts across two workflows that neither wait for nor check each other — so a
  GitHub Release can exist while an image build failed. The doc carries the tag taxonomy, the pre-tag
  checklist, and the rollback rule that matters most: deployments default to MOVING tags
  (`platform:latest`, `sandbox:full-latest`), so a rollback is a pin, not a revert, and a published
  tag is never moved or deleted — a scan records `sandbox_image_digest` as evidence (§6), and an
  evidence pack pointing at a digest nobody can pull stops being evidence.

---

## 16. Build phases â current status

> **Status note (2026-06-21):** phases 0â6 are **built + CI-green**; the platform layer
> (Â§18) is built on top. What remains is **live/scale verification gated on infra,
> credentials, or product decisions** â tracked in [docs/competitive-roadmap.md](docs/competitive-roadmap.md)
> (Tracks 1â3) and Â§18.3, not here. Concretely open: per-asset **live** benchmark numbers
> (need the sandbox image + deployed targets; SAST now measures **46.5% Youden** over all 2,740 OWASP
> BenchmarkJava cases — third on the published cohort, between Checkmarx 47% and Fortify 35%),
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
| `internal/remediate` | `Propose` (findingâAction; repoâPR, cloudâconfig, **workspaceâa per-rule identity runbook** `identity.go`) + **`ProposeBulk`** (`bulk.go` â "Bulk Fix": groups an asset's findings by fix unit â SCA package coordinate from `ToolArgs`, else rule id â and emits ONE PR per group of â¥2 repo findings, citing every finding it resolves via `Action.FindingIDs`; singletons/non-repo fall back to `Propose`; the runner's optional `ProposeBatch` supersedes per-finding `Propose` when set) + the **Respond breadth catalog** (**`appsec_catalog.go` `appsecFixCatalog`** gives web_application/api/container_image the SAME contract cloud has — these three previously fell to a generic "review this" ticket, so the AI Pentester could PROVE an SQLi by exploiting it and the proposal still read "review this finding". Sixteen classes keyed on CWE first (CWE survives template churn) with text as fallback; a runbook cites a version ONLY when the scanner really reported one, because an invented upgrade target is worse than none — it is actionable and wrong; no match keeps the generic ticket, since a catalog that guesses costs more than one that declines. Tier 1 throughout (no live write path). **`interim.go` — MITIGATE NOW, PATCH LATER**: for the eight classes whose real fix is a CODE change, the action ALSO carries `interim_mitigation` — an edge/runtime control that cuts exposure today (WAF ruleset, CSP at the edge, egress-deny to the metadata endpoint, blocking a served path, dropping process privilege, rate-limit-and-alert). Keyed on the `remediation_type` the catalog already decided, so no second matcher can disagree with the first. Classes whose fix is ITSELF a config change get nothing — there "mitigate now" and "fix" are the same act. TWO REFUSALS: it NEVER presents as a fix (every text says it does not fix, does not close, and the finding stays open — asserted across all eight, because a customer who applies a WAF rule and watches the finding vanish will believe the bug is gone), and it NEVER claims the customer HAS the control (no control-plane integration means we do not know whether they run a WAF, so each is conditional and names the control it needs; asserting an unobserved control is the same overclaim as a scan we never ran). Rendered at the approval desk, guarded by `uicheck`. `cloud_catalog.go` `cloudFixCatalog`: the common non-storage cloud-misconfig classes (IAM privesc, open security group, unencrypted-at-rest, public snapshot/DB, missing MFA, disabled logging, root access key, weak password policy) each get a machine-readable `remediation_type` + a SPECIFIC, PROVIDER-AWARE copy-pasteable runbook (the exact CLI cut — `pp()` picks aws/gcp/azure from the asset's provider so a GCP finding gets `gcloud`, an Azure finding `az`, never AWS CLI) instead of a generic "review this" ticket. Grounded 10 (matches the finding's own text, targets its own resource) + promotable: a class upgrades to a live HITL-gated mutation with one catalog entry the moment its connector write lands, exactly like S3 block-public-access. Only public-storage is live-writable today, the honest gate; the runbook classes (`cloudRunbookRemediations`, derived from `cloudCatalog`) DELIVER as actionable tickets — `Deliverer.Apply` files a cloud ActApplyConfig carrying a runbook-only `remediation_type` via the `Filer` instead of calling `connector.Apply` (which would error "no live write path"), so an approved fix hands the human the exact steps not a spurious failure; a live-writable storage class + identity `account_suspend` are NOT in the set, so they still route to their real connector write) + `Deliverer` (apply via connector; routes to the action's own connection; `file_ticket` â a `Filer` e.g. Jira) + **`PlanBackports`** (`backport.go` — the task-8 backport path): one merged fix → per-branch HITL-gated actions via `internal/backport` (clean/offset → a reviewable `ActOpenPR` with the patched content; needs_adaptation → an `ActFileTicket` naming why it will not apply, NEVER a PR with a patch it could not place; already_applied / not_applicable → NO action, since re-applying a security patch is itself a failure mode). The branch list + per-branch file fetch is the connector-gated half; the planner is pure + tested (BackportBench scorer in `internal/bench/backport.go`) |
| `internal/grc` | compliance control-state system-of-record + signed evidence pack + the auditor-facing **compliance report** (`Report` resolves each gap to its citing findings; `RenderMarkdown` is the attachable deliverable) + the customer-facing **VAPT/pentest report** (`VAPTReport`/`RenderVAPTMarkdown` â exec summary, scope, and every finding with severity/CWE/CVSS/exploit-status/evidence; grounded, served at `GET /v1/vapt/report`) + the **no-false-compliant coverage layer** (`Coverage`: `certifiable` always false, "X of Y technical controls assessed", `readiness` never says "Compliant") + **per-asset compliance** (`AssetCompliancePosture(assets, findings)` â the "is THIS asset compliant?" view: rolls each finding to the asset whose `Target` literally appears in its endpoint (longest wins, mirrors `crossdetect.datatier`), tallies per-asset gap-controls/frameworks/worst-severity; grounded Â§10 â unattributable assets (repo file:line endpoints) come back `attributed:false`, and the status line NEVER says a bare "compliant"; `GET /v1/compliance/by-asset` + a "By asset" section on `/compliance`) + **continuous evidence timeline** (`evidence_timeline.go` — the SOC 2 Type II / ISO-surveillance "prove it held ACROSS the window" artifact the point-in-time `EvidencePack` can't give: `CaptureEvidenceSnapshot` appends a timestamped posture snapshot per framework to `platform.ComplianceSnapshot` (an APPEND-ONLY store timeline, 6-place wired), change+heartbeat-gated (a real posture change captures immediately; an unchanged posture captures at most once per `evidenceHeartbeat`=24h — so a static estate doesn't bloat the timeline). `CaptureAllEvidence` is the continuous driver the **runner calls every monitoring pass** (after `Reconcile`); `EvidenceTimeline` reads it back with a grounded continuity summary (`FullyMetRatio` + a `Continuous` bit that's honest — it means every CAPTURED snapshot was fully met, NOT a claim about un-sampled instants). `GET /v1/compliance/{framework}/evidence-history` (timeline) + `POST /v1/compliance/{framework}/evidence/capture` (on-demand snapshot). Grounded §10: an un-monitored framework returns an empty, non-continuous timeline, never a fabricated "continuously compliant") |
| `internal/detect` | the continuous-monitoring backbone (deterministic detect half of detect-&-respond): `Detector.Reconcile` diffs a tenant's current findings against its open incidents â opens a `platform.Incident` for a new finding at/above a severity threshold (default high), resolves one when its issue (keyed `rule_id\|endpoint`) stops appearing. Signed into the ledger; LLM-free + grounded. The resolve is HYSTERETIC (`Incident.AbsentPasses`, default 2 consecutive authoritative passes) because one quiet scan is not proof: measured on WAVSEP, dalfox found 7 vulnerable cases in one run and 9 in the next on an UNCHANGED target while SUCCEEDING both times, so nothing reached `Scan.ToolsFailed` and the degraded-pass guard never fired. That state must be VISIBLE — rendered identically, an incident being held open through hysteresis and one still actively firing are the same row, and the reader most likely to be looking is the person who just deployed the fix, for whom an unchanged alert reads as the fix having failed. The SAME sweep found `Incident.Onset` in the same state one layer out: `annotateOnset` reads the estate timeline on EVERY `/v1/incidents` request to say WHEN the state changed â the difference between "this bucket is public" (triaged next week) and "this bucket became public forty minutes ago" (dealt with now) â and the queue displayed none of it, so the work was done per request and the answer discarded. Now a `<what> Â· first seen <at>` badge carrying the honest limit WITH the timestamp: state is compared between captures, so it is when the change was first OBSERVED, not when it happened. Both guarded by `internal/uicheck`. Surfaced as a `confirming fix Â· absent N scans` badge stating only the count we have; the configured threshold is server-side policy the page is not told, and naming a number it cannot see would invent the thing the badge exists to be honest about. `Reconcile` also takes an `attacked` key-set (ADR-0007 Phase 0b): a finding observed under attack in production opens an incident **regardless of the severity floor** + marks it `Incident.Attacked` (title prefixed `[under active attack]`); the runner computes it via `crossdetect.AttackedKeys(current, runtimeEvents)`. Driven by `runner.RescanTenant` each pass; opening a new incident fires an optional `Alerter` (Slack heads-up) so detectâalert happens in one pass |
| `internal/retest` | **fix-verification** — the answer to "60% don't retest after fixes; a fix that isn't verified is a fix taken on trust" (State-of-AI-in-Pentesting KF#4). The remediation-scoped twin of `detect.Reconcile`: when a remediation `Action` is APPLIED, `Verify(actions, current, now)` re-tests it against the next authoritative scan and records a grounded `platform.FixVerification` on the action — `fixed` ONLY when every finding key (`rule_id\|endpoint`, the SAME `detect.Key` so the two never drift) it claimed to resolve is provably absent, `still_present` when any remain (the fix didn't close it — reopen). Grounded (§10): the action carries `FindingKeys` stamped at propose time (`runner.stampFindingKeys`, stable across scans where finding IDs aren't); an action with no keys is never guessed at. `fixed` is terminal (a reappearance is a NEW incident, not a re-flip); `still_present` upgrades to `fixed` on a later clean scan. **THREE CONSUMERS REASON FROM ABSENCE and each must be gated the same way** — `Detector.Reconcile` (resolves an incident), `retest.Verify` (marks a fix confirmed) and `grc.Reconcile` (flips a control gap to MET). A pass that did not see the whole estate makes all three lie, and they were hardened one at a time: the `degraded` flag originally covered only a TOOL timing out inside a scan, not an asset dropping out entirely — an asset skipped for an inactive connection sets neither `firstErr` nor `scanned`, so on a tenant where other assets scan fine the pass LOOKS complete. `grc.Reconcile` was the last to be gated and the worst to get wrong: its comment claimed it was "Guarded by scanned>0 like the detector" while the detector also had `firstErr == nil` and the degraded routing, so a timed-out tool could mark a SOC 2 control MET in the Markdown report a customer hands an auditor (the FALSE-COMPLIANT mode the whole coverage layer exists to prevent, arriving underneath it). Each now has a degraded-mode twin that never makes the absence claim: `Detector.OpenFor`, skipping `retest.Verify`, and `grc.RefreshEvidence`. **The mirror is equally wrong and equally tested**: a COMPLETE pass must still resolve, still confirm and still clear, or a false-compliant bug is traded for a permanent false NON-compliant one. Wired into `runner.RescanTenant` right after `Detector.Reconcile` (both consume `current`); surfaced via `GET /v1/actions` (the list + a fix-verification roll-up: applied/verified/confirmed_fix/still_present, computed only over the verifiable set). Needs `Store.ListActions` (lists all of a tenant's actions, any status). LLM-free, evidence-backed |
| `internal/fieldevidence` | **what happened AFTER a fix shipped, turned into how much evidence the next verification needs** (ADR 0025 F1). `FixVerification` records what the ABSENCE check concluded (`RescanSaidFixed`) separately from what a live re-attack then proved (`Disagreement`) — its own comment calls the two disagreeing "the only way to answer 'what evidence is sufficient' from real data rather than from opinion". This is that answer: per rule CLASS, how often a clean re-scan was contradicted by a live exploit, and therefore whether a clean re-scan may still make the TERMINAL "fixed" claim. Consumed by `retest.VerifyWithPolicy` (wired in `runner.RescanTenant`, built from `acts` already in hand so it costs no I/O); a distrusted class lands `platform.FixStatusRescanUnconfirmed` — "gone, on evidence we know has failed for this class" — which is NOT terminal and is neither "fixed" nor "still present", so `grc` tallies it as a THIRD number rather than folding it into either. **It can only ever DEMAND MORE evidence**: no data, thin data or a clean record all keep exactly today's behaviour, so an empty corpus changes nothing (asserted by test, both directions). Absence reads as *unknown*, never as trustworthy or as suspect. `ClassOf` drops the endpoint half in ONE place because the class is world-state (a public OSS rule id) and the endpoint is the customer's. Gates built for the CROSS-tenant corpus ADR 0025 proposes — k-anonymity (`MinContributors`), a per-tenant weight cap so one estate cannot decide a shared statistic, an evidence floor — are present and configured; `ForTenant` sets `MinContributors: 1` AND disables the per-tenant cap EXPLICITLY, because a tenant reading its own record discloses nothing and there is no one else to dominate — the cap applied to one's own corpus TRUNCATES IN ARRIVAL ORDER and distorts the rate it exists to compute (2 contradictions then 60 clean re-scans read as 40% instead of 3%, refusing to confirm a healthy class). **F2 (`remediation.go`) — which remediation actually CLOSED it**: both fix catalogs already stamp a machine-readable `remediation_type` and `retest` already writes the outcome onto the same action, so `(finding class, remediation_type) → closure rate` was answerable from stored data and simply never asked. `RemediationsForTenant` counts it; `platformapi.annotateFixEfficacy` puts it on each PENDING approval (read-time, never persisted — mirrors `annotateApplyBlocked`/`annotateSLA`), rendered in the inbox and guarded by `uicheck`, because "this closed 8 of 10 times" and "this was reopened 5 of 8" are different decisions for the person about to approve it and read identically without it. **F1 feeds F2's honesty**: a `rescan_unconfirmed` application is counted as `Unproven` and EXCLUDED from the rate in BOTH directions — counting "we do not know" as a success would launder the exact uncertainty F1 exists to record, and as a failure would be the same error reversed. Keyed on class AND type together, since a fix that works for one class says nothing about another. `Weakest()` names the failing pairings WORST-FIRST (the order is the substance — a reader acts on the top entry) and is surfaced as `weakest_remediations` on `GET /v1/actions` and `/activity`, guarded by `uicheck`; kept DISTINCT from `distrusted_classes`, because one says our RE-SCAN was wrong and the other says the FIX was, and conflating them sends someone to repair the wrong thing. No history renders NOTHING: a zeroed record beside a proposed fix reads as a fix that never works. Surfaced on `GET /v1/actions`: `awaiting_proof` counted as ITS OWN bucket (that roll-up switched on STRING LITERALS, so the third status silently landed in none of them and the numbers stopped adding up) and `distrusted_classes` naming where our own absence-evidence has failed, rendered on `/activity` and guarded by `internal/uicheck`. Today it is single-tenant self-learning: no consent question, and promotion is a change of inputs, not a redesign. Evidence is derived from `Action.VerificationHistory`, an APPEND-ONLY log, NOT from current state: `ApplyReattack` replaces `Verification` wholesale, so an action contradicted in one pass and re-verified clean later USED TO LOSE the contradiction — a −1/+1 swing per action, biased toward TRUST, growing stronger the more diligently a customer fixed things. Appends are change-only (an unchanged verdict re-recorded every pass would be the mirror bug: one action out-voting the estate instead of vanishing from it), bounded, and a nil history falls back to the current verdict so a deploy does not silently empty the corpus. `RemediationsForTenant` deliberately still reads CURRENT state — F1 asks "was our absence-evidence ever wrong" (a question about EVENTS) and F2 asks "did this remediation close it" (a question about the END STATE). `RemediationCorpus.Muted` reports a record that EXISTS but cannot be scored, because F1 tightening shrinks F2's denominator and silence there is indistinguishable from "no history". `FromActions` counts only LABELLED examples (a re-attack actually ran) and one per DISTINCT class per action, so one remediation spanning five findings cannot outvote five separate ones; `TestRescanSaidFixedHasOneWriter` pins that `RescanSaidFixed` is written only by the re-attack path, since a second writer would fill the corpus with unlabelled rows all counted as "the re-scan was right". |
| `internal/attackcoverage` | **which attacker techniques were exercised against this estate, and which nobody checked**. Every wrapper already declared its ATT&CK techniques (46 tools, 30 distinct) and every finding carried its own; neither was aggregated, so the axis this category is compared on was unanswerable from data we held. Three states, and the third is the point: `observed`, `exercised_clean` (the ONLY status meaning "we looked and it was fine"), and `not_exercised` WITH the reason — a tool that FAILED reported differently from one never applicable, since rendered alike a broken scanner looks like a scope decision. **Reports counts, NEVER a percentage**: we do not ship the ATT&CK Enterprise catalogue, so the only denominator available is our own tool set and a percentage over it is "we cover 30 of the 30 we cover" — a tautology that cannot go down. `Report.Denominator` says so in words and the page renders it verbatim. Names are TRANSCRIBED from MITRE, never derived; a missing one renders the bare ID rather than a guess, and a test fails when a new wrapper declares a technique nobody looked up. `GET /v1/attack-coverage`, on `/coverage`, guarded by `uicheck`. |
| `platform.Asset.Owner` / `.Team` | **who to route a finding to** (ADR 0028 G1). `Owner` existed on `Risk` and `Policy` — the vCISO artifacts — so the product could say who ACCEPTED a risk and not who should fix the finding underneath it. Carried into every proposed action's payload via `remediate.ownerLine`. **Empty means UNOWNED and says so**: falling back to the tenant owner so every ticket has an assignee manufactures accountability — it names someone who never agreed to it and hides the fact a scoping exercise most needs to surface. Ownership ANNOTATES and never gates: a finding on an unowned asset is still ranked and still ticketed (asserted by test). Contact metadata, stored plain, and never an authorization input — or an unowned asset becomes an unprotectable one. |
| `internal/scubaingest` | **correlates a ScubaGear/ScubaGoggles run the CUSTOMER performed against ours** — INGEST rather than wrap, and the reasoning matters. §13 says wrap the OSS tool and identity is the one surface where we do not; but the audit showed the gap is PROVENANCE, not coverage — SCuBA recall is 0.993 with every mapping EXECUTION-PROVEN (the bench builds a violating snapshot, runs the real assessor, and fails if the rule does not fire). Running ScubaGear ourselves would add a PowerShell + Graph-modules runtime and a second credential ask to obtain a second opinion about detections we can already demonstrate; ingesting their run costs neither and CISA's tool is one many tenants already have. **The field-name problem is handled, not guessed**: CISA documents the semantic fields (Control ID · Requirement · Result ∈ Pass/Fail/Warning/Error/Omitted · Criticality) and NOT their JSON casing, and publishes no example — so the resolver enumerates the documented spellings and is tested against all of them, because a struct tag betting on one silently matches nothing (the `nuclei_template` bug). **The guard that makes tolerant parsing safe: an ingest recognising ZERO policies ERRORS** (`ErrNoPoliciesRecognized`) — a document we cannot read must never render as a tenant with nothing wrong. Only an explicit `Fail` is a violation (Warning is advisory; Error/Omitted mean CISA's tool declined to judge, and folding either in attributes to CISA a verdict it did not give); an unrecognised verdict normalises to `error`, never `pass`. `Correlate` separates `we_missed` (our detector was silent — the reason to run this) from `unmapped` (we have no detector at all), because merged, a coverage hole reads as a detection failure and sends someone to debug a rule that does not exist; a `~`-prefixed PARTIAL mapping does not count as catching the policy. `they_missed` is NOT a win by default and the caveat says so — it is equally a candidate false positive of ours. Policy→rule mapping comes from the SCuBA bench catalogue, the single home that proves its mappings by execution. `POST /v1/scuba/ingest`. |
| `internal/detectionvalidation` | **when we proved an attack works, did the customer's own defences notice?** — the test Gartner's 2026 AEV guidance uses to DEFINE this category, and the one tsengine never asked (ADR 0027 S1). Needs no connector: probes come from the engagement attempts already stored, events from the runtime-sensor ingest that already exists. **THE INVARIANT: silence is not a miss.** An undeployed sensor, late telemetry, a wrong window and a genuine miss are indistinguishable from here, so `not_detected` is claimed ONLY when the sensor proved it was watching (it reported something else in the same window); otherwise `undetermined` — §10's "we could not look" in this package's vocabulary. Reporting silence as a miss would be a false accusation about someone else's product made from our own blind spot. **Two evidence strengths, never merged**: a sensor reporting OUR canary is exact; same-endpoint-same-class-in-window is an INFERENCE, right most of the time and wrong exactly when a real attacker is hitting that endpoint concurrently. `Blocked` (long inert — parsed, counted once, read by nothing) finally means something: "we saw it" and "we stopped it" are different answers about a control. Enabled by two prerequisites the ADR wrongly assumed existed — the canary was generated and DISCARDED, so `ProposedAction.Canary`→`AttemptRecord.Canary` persists the join key, and `RuntimeEvent.Marker` lets a sensor report the token it saw (optional; most report only an attack's shape). `GET /v1/detection-validation`, rendered on `/detection` (a 7th SECURITY tab — the only one of the four "what actually happened" surfaces that grades somebody ELSE's product, which is why it refuses to call silence a miss), guarded by `uicheck` on both the fields and the WORDING: a field-presence check is satisfied by the summary counts line, so deleting the per-result monitor-only phrasing left it green while the page claimed every detection was an interception. |
| `internal/exposuretrend` | **is exposure going down?** — the question CTEM exists to make answerable, and one `SummarizeEpisodes`'s LIFETIME totals cannot answer ("opened 40, closed 38" says nothing about direction). A per-day series over the stored episode corpus. TWO honesty rules inherited from the data: **closed is NOT fixed** (`SecurityStateDelta` says Closed means the issue STOPPED APPEARING — a descoped asset and a degraded scan produce it too), so the re-test-proven `ConfirmedFixed` is reported BESIDE the series and never merged into it, which is exactly the difference between our chart and the industry's "no longer detected" burndown; and **an unscored run is not a quiet one** — counted as zero it reads as "nothing changed", the opposite fact, so it is counted as itself. `EpisodeRecord.Scope` is what makes two episodes comparable (`ledger.Diff` refuses a mismatch), so a mixed series DECLARES the mix rather than averaging incomparable censuses. `GET /v1/exposure-trend?scope=`, on `/activity`, guarded by `uicheck`. |
| `internal/coverage` | **per-asset "what was actually tested"** — the answer to "52% of organizations don't have full visibility into what was tested" (State-of-AI-in-Pentesting). `Compute(assets, findings, engagements)` produces, per asset: the DECLARED anchor toolset for its type (`Toolset` map — now GUARDED against the handlers it mirrors by `TestToolsetMatchesTheHandlersItMirrors`, which reads the live `Anchors()` through `assetregistry`; the hand-mirrored list had drifted in BOTH directions with nothing checking it, and over-declaring names a tool that did not run on the page built to answer "what was actually tested" — the tools that fire on every scan of that type, §4.1, so it's what actually runs not a wish list), whether/when it was last scanned (latest completed `Engagement`), and which of those tools surfaced a finding (the rest ran clean). Grounded (§10): a never-scanned asset reads `scanned:false` (never "covered"); tools-with-findings comes only from real findings attributed by a literal target match (longest-wins, same as data-tier / per-asset compliance); registry-tier depth tools are excluded (on-demand). Deterministic + LLM-free. `GET /v1/coverage` + the `/coverage` "Test coverage" page (per-asset cards: scanned-when, tools-run chips with finding-surfacing ones highlighted, "all ran clean" vs "N findings from M tools"). |
| `internal/ctoreadiness` | **the staged engineering-practice checklist** — a DIFFERENT axis from `grc`. GRC answers "which SOC 2 control does this finding affect" (an auditor's question, framed in controls); this answers "what should a company at my stage have in place, and what am I missing" (a CTO's question, framed in practices and staged seed→series C so a seed team is not measured against an enterprise bar). 30 items over 6 categories. **The load-bearing idea is FOUR KINDS OF EVIDENCE, which are not interchangeable**: OBSERVED (20 — a scanner answers it; only these may read pass/fail, and each names the OSS that establishes it so a tick is checkable rather than trusted), CAPABILITY (3 — the platform IS the answer; the question is whether it is switched on), ATTESTED (4 — no scan can see it, so a named human answers and BOTH answers are recorded), UNBUILT (3 — we do not cover it, and we name the OSS to use instead). A row that is ATTESTED must never be inferred from findings and an UNBUILT row must never be filed as "manual"; tests assert both. Grounded (§10): an observed row passes ONLY when the detector really ran and found nothing — nothing connected reads NOT CHECKED, never pass, because "we looked and it was clean" and "we never looked" are different claims. A NAMED TOOL THAT DID NOT RUN CANNOT BE CITED. `Input.Scanned` answers "did the engine run against this asset type", which is one level too coarse for a row that names its tools: an engagement completes and marks the type scanned even when the tool answering the row timed out, crashed, or was absent from the sandbox image, and the row then read `Checked by trivy, govulncheck, grype, osv-scanner — nothing open` while trivy produced nothing. `Input.FailedTools` (from the LATEST completed engagement per asset, so a transient failure a fortnight ago does not void a row the last scan answered) turns that row NOT CHECKED and names the tool. Same claim `Scanned` was added to stop, one level finer — there it was tools asserted about assets the engine never touched, here about assets it did. FINDINGS ARE PROOF THE CHECK RAN (a posted posture snapshot produces findings with no connection of that kind, so the needs-gate must not suppress a row a detector already answered). `Summarize` deliberately emits NO single percentage — folding unchecked in with passing produces a number that RISES when a customer connects nothing. Each measured row names the agent that owns it (engineer 16 / pentester 4; the other 10 are process and owned by nobody). `GET /v1/readiness/checklist` (+`?stage=` preview) · `POST /v1/readiness/stage` (the ONE onboarding question) · `POST /v1/readiness/attest/{id}` (refused on a measured row — a typed answer must not replace evidence) · `POST /v1/readiness/fix/{id}` (hands the row's findings to `remediate.Propose` → the SAME approval desk; the checklist gets no write path of its own) + the `/readiness` page. |
| `internal/platformapi/systemstate.go` | **one server-computed list of why the current view may be incomplete** — halted automation, a scan that failed, no model configured, a connection we cannot act through. Built after THREE defects shipped with the same shape: the backend knew something was wrong and the screen did not say so (a halted workspace whose sidebar read "agent online"; a failed scan rendering an empty findings list; a delivery failure sitting at "approved"). Three different mechanisms, one cause — **the default for a new degradation signal was invisible**. Note what would NOT have caught them: a frontend unit-test framework tests the component against the props you passed it, and two of the three were failures to fetch or pass anything at all, so the fix belongs in the contract between the halves. Degradations are computed once from real state and the shell renders whatever is in the list, so a new reason is visible by default and hiding one is the deliberate act. A guard test drives EVERY declared kind from the state that should produce it (a kind declared and never emitted is the same silent-signal bug one level up). `GET /v1/system-state` + `DegradationBar` in the app shell. | A fourth kind was added after the same shape recurred: `cloud_coverage_incomplete`, from `cloudsnap.Snapshot.CoverageGaps`. Escalation is computed from policy documents (AWS) or IAM bindings (GCP), so a snapshot omitting them yields ZERO escalation edges — and on an attack-path page zero reads as "nobody can become admin here". `connector.CoverAWS`/`CoverGCP` compute the gap at ingest, `POST /v1/cloud/inventory` returns it, and it is STORED because the reader of the page is rarely the CI job that posted the snapshot. Grounded §10: read from the snapshot's OWN recorded gaps, never inferred from an empty result — "we found none" and "we could not look" are different claims. GCP carries an extra silent failure: an unresolvable custom role makes `derivePrivesc` refuse an edge (the firm-allow rule), so `CoverGCP` NAMES those roles. **AWS carries the mirror of it, which the original check could not see**: a policy that is PRESENT but unparseable is counted by the has-policies test, so no note fired, while the ingest skipped every unreadable document — an account with zero privescs and zero coverage notes, which is the same confident all-clear the gap layer exists to prevent. `CoverAWS` now names principals whose policies ALL failed to parse (every, not any — one bad document alongside a good one still got evaluated, and naming it makes the note noise people learn to skip). The trigger was realistic rather than theoretical: **AWS's own IAM API returns `PolicyDocument` URL-ENCODED** (`GetRolePolicy`/`GetUserPolicy`/`GetPolicyVersion`), so a collector forwarding it verbatim produced exactly that state. `cloudiam.Parse` now reads that form — a decode, not a guess: the fallback is accepted only if the decoded bytes really parse, and anything else returns the ORIGINAL JSON error.
| `platform.Tenant.Branding` | **White-label** (`GET/PUT /v1/settings/branding`, the Settings "Branding" panel): the name, logo and support address on the artifacts a workspace hands to OTHER people — the VAPT report's prose (`VAPTReport.Brand`, both renderers) and the public Trust Center's chrome (`trustView.Brand`/`WhiteLabelled`; a branded page says "Provided by <brand>" and does NOT link to our marketing site, which would name a company the buyer has never heard of). Built for the MSP / consultancy motion reselling the managed tier. **It rebrands prose and chrome only: `VAPTReport.Engine` is provenance (§10 pinned context) and is never replaced** — an auditor re-running a finding needs to know what ran; pinned by `TestVAPTRender_BrandsProseNotProvenance`. Empty name clears it; logo must be https; no secret, stored plain. Custom domain on `/trust/{tenant}` is the follow-on. |
| `internal/trustcenter` | **the buyer-facing Trust Center — the security review as a link instead of a call.** Security is where most deals stall, and the category's answer (SafeBase, Vanta/Drata Trust Center) is one arrangement: a PUBLIC tier anyone with the link may read, a GATED tier behind an NDA and an approval, and a log of who read what. Every artifact this offers ALREADY EXISTED AND WAS UNREACHABLE — the VAPT report, the per-framework compliance report, the auto-answered questionnaire (§8) and the signed evidence pack were all authenticated tenant-only endpoints, so showing a buyer one meant exporting a file and mailing it, which is the two-hour call the feature deletes. **What makes ours different is also what obliges the stricter rules**: everyone else hosts a PDF somebody uploaded and the reader must trust it still describes the company; ours are GENERATED from the same grounded posture the customer sees in-app, so they cannot go stale — and this is the most expensive page in the product to overstate anything on, because the reader is a stranger doing vendor due diligence and there is no surrounding context to correct a wrong impression. THREE REFUSALS, each structural rather than left to whoever configures the page: (1) **a document naming open findings can never be PUBLIC** (`platform.DocKind.MinVisibility`) — `handleTrust` already refused to publish which controls are gaps because a gap list is a roadmap, and a VAPT report is that same list with reproduction steps attached, so the click has to be unavailable rather than discouraged (`ClampVisibility` clamps and SAYS SO, since a setting that silently declines to take effect is worse than one refused out loud); (2) **a document is listed only when it can actually be produced** — `Catalog` DROPS anything unavailable rather than showing it locked, because a locked row asserts the document exists and is merely withheld, which is exactly the claim a buyer would act on (the owner gets the reason, the public page shows nothing); (3) **what a buyer accepted is an artifact, not a boolean** — `NDAHash` pins the digest of the exact text, because the terms are editable configuration and "accepted" alone could not say WHICH agreement was on screen (the same instinct as pinning a corpus version into a scan). `Find` is the ONE decision both the listing and the fetch call, so a row cannot render locked while the endpoint behind it serves anyway. Auto-approve is per-domain, EXACT-match (suffix matching would admit `notacme.com` and `acme.com.attacker.example` to a penetration-test report) and a wildcard is REFUSED — auto-approving everyone is publishing wearing an access log, and a tenant who wants a document open should set it public where the consequence is legible. Grants are bounded in both directions (0 hours means the default, never forever; capped at a year since these regenerate from live posture). Every generated gated document is WATERMARKED with the recipient and the generation date — the only control available for an artifact whose whole purpose is to be forwarded, and its second half is the honest one: a copy read months later describes a state that has moved on. A PUBLIC document is deliberately NOT watermarked (stamping "provided in confidence" on something anyone may read is a false claim about how it travelled). **The share link is now REVOCABLE** (`TrustCenterConfig.TokenVersion` folded into the MAC): it was a bare HMAC over the tenant id, so it was PERMANENT — the only remedy was rotating the platform secret, which would take every other tenant's link and the OAuth state keyed by the same secret with it — while the public page told readers a link "has been revoked", a capability nothing in the product had. Versions 0 and 1 mint the same token so existing links survive the deploy. The sub-processor list is AUTHORED on the config rather than derived from `internal/tprm`, deliberately: tprm persists only the FINDINGS it raises, so a derived list would name the vendors that failed a check and omit every well-managed one — publishing "our problematic suppliers" under the heading "our sub-processors" — and a GDPR Art. 28 disclosure is a legal statement the company makes, not an inference a risk tool draws. `GET/PUT /v1/settings/trust-center` · `POST /v1/settings/trust-center/revoke-link` · `GET /v1/trust-requests` · `POST /v1/trust-requests/{id}/decision` (approve/deny/revoke; the access token is returned ONCE because only its digest is stored, and an approval with no named human is REFUSED — a rule approving and a person approving are different facts the log must distinguish) · PUBLIC: `POST /v1/trust/{tenant}/request` (rate-limited) · `POST /v1/trust/{tenant}/nda` · `GET /v1/trust/{tenant}/doc`. UX: the buyer's `/trust/{tenant}` page (documents, request form, click-through agreement — the gate decisions are RENDERED from the server's `readable`/`granted`/`nda_pending`, never re-derived, or the listing and the fetch would eventually disagree about what is gated) and the owner's Settings panel + access desk. **Four reader-half signals are guarded by `internal/uicheck`** for the reason Â§11 gives: the CORRECTIONS a save made (a config silently altered is one the owner believes says something it does not), the documents configured but NOT served and why (that omission is invisible by design, so it reads as a bug unless the owner is told), the desk's computed `granted` rather than `status=="approved"` (approved-and-expired, approved-and-revoked and approved-pending-signature are all not access), and the buyer page's split between waiting on a human and waiting on their own signature (only one is something they can act on). |
| `internal/ownership` | **proof-of-asset-ownership challenge** — the control leaders named as a precondition for trusting AI testing ("proof of asset ownership", State-of-AI-in-Pentesting p35). For a standalone target a customer ADDS (a domain/web/IP they typed, vs an OAuth-connected system which already proves control), they prove control by publishing a per-asset token via a DNS TXT record (`_tsengine.<host>`) OR a well-known file (`/.well-known/tsengine-verification.txt`). `NewChallenge(target, token)` builds the instructions; `Verify(ctx, ch, resolver, fetch)` checks the LIVE target (DNS first, then file) and returns verified+method. Grounded (§10): owner-verified ONLY when the token is really found — a lookup error / absent token is unverified, never assumed. The file fetch is SSRF-screened (same guard as `/v1/assess`). `POST /v1/assets/{id}/ownership/challenge` (issue+store a 128-bit token on `Asset.Meta`) + `POST /v1/assets/{id}/ownership/verify` (live check → `Asset.Meta["ownership_verified"]`/`["ownership_method"]`/`["ownership_verified_at"]`). Gating active scanning on verification is the documented follow-on; the challenge/verify capability + the agent-controls trust claim work today. |
| `internal/clouddrift` | **continuous CONFIG-SNAPSHOT drift detection** — the third drift signal, complementing `cloudcdr` (audit-log-event drift) + `detect` (finding-diff drift). `Diff(prev, cur *cloudgraph.Snapshot)` compares two cloud inventory snapshots over time and emits grounded change-control findings for the security-relevant config changes: `resource-became-public`, `principal-became-privileged`, `new-privileged-principal`, `new-public-resource`, `new-internet-exposure` (a new internet→resource reach edge), `new-privilege-escalation`, `new-lateral-movement` (new secret_access edge). The SOC2/CIS change-control "detect unauthorized change to the environment" signal WITHOUT the audit-log stream. Deterministic + LLM-free + grounded (§10): each finding cites the changed node/edge + before→after, carries the change-control compliance nexus (SOC2 CC8.1, NIST CM-3/CM-6, CIS 4.2/8.5, ISO A.8.32), and an unchanged pair / nil baseline (first observation) yields ZERO findings. Live driver: `POST /v1/cloud/drift` (prev+cur inventory → findings into the same store → issues/incidents/grc/hitl). **Continuous DIFF-ON-INGEST is now wired** (`cloudinventory.go`): re-POSTing to `POST /v1/cloud/inventory` diffs the fresh snapshot against the tenant's STORED baseline BEFORE overwriting it → automatic drift findings on every re-ingest (the "connect once, detect change" promise), no separate `/v1/cloud/drift` call. Both paths share `persistDriftFindings` (enrich → store → GRC → incident) so they never diverge; grounded §10 (first ingest / unchanged re-ingest yield 0). A live scheduled FETCH into `/v1/cloud/inventory` (vs the customer/CI re-POST) stays the credential-gated half |
| `internal/cloudsearch` | **"search your cloud like a database"** (Aikido /Cloud parity) over the inventory the engine ALREADY builds (`cloudgraph.Inventory`). `Search(inv, Query)` filters resources by kind/type/region/public/privileged/sensitive/tag/free-text and returns each match with its immediate relationships (`Reaches`/`ReachedBy`, derived from the real reach/grant/trust/pass/privesc/runs-as/trigger edges — the "JOIN"). The attack-path engine builds this graph to reason about exposure; cloudsearch exposes it as a queryable surface so an operator can instantly answer "which storage is public?", "what can reach this DB?", "every privileged principal in us-east-1" without re-scanning. Pure + deterministic + grounded (§10): every result is a real resource/edge from the supplied inventory; an empty/unsatisfiable query yields nothing, never invented. `POST /v1/cloud/search` (posted inventory + query, same snapshot shape as `/v1/cloud/drift`); persisting each tenant's last inventory so it's queryable any time (no re-post) is the documented follow-on. |
| `internal/ghoidc` | **GitHub Actions → AWS role transitions** — the CI/CD identity surface, previously invisible in every direction (`grep -ri oidc` over the tree returned nothing AWS-side). A workflow reaches AWS with NO stored credential: it presents an OIDC token and the role's trust policy decides, entirely through string conditions on the token's claims — so there is no secret for a scanner to find and no over-grant for an IAM evaluator to flag. The permissions are fine; the question is WHO gets to use them. Two halves, deliberately separate because they are different claims with different evidence: `Analyze(trustPolicy)` is POSTURE (what does this policy permit in general) and `CanAssume(trustPolicy, account, WorkflowContext)` is the TRANSITION (would AWS believe THIS workflow), returning a rung-aware `Verdict` (ADR 0002) rather than a flattened three-value enum — an implicit deny IS decided, because that is how a correctly-pinned policy refuses a stranger. **The load-bearing refusal is the OPERATOR DISTINCTION**: `*` is a wildcard under `StringLike` and a LITERAL under `StringEquals`, so `StringEquals sub=repo:acme/*` matches a repository literally named `*` — nothing — and fails CLOSED; reporting the two alike would raise a critical against a policy that is merely broken. Second refusal: the `sub` format is GitHub's (`repo:O/R:environment:NAME` takes precedence over the ref form even on a branch push), so the four shapes are spelled out rather than composed. Severity comes from the subject's SCOPE walked through GitHub's own grammar, never from counting asterisks; blast radius is NOT inferred (a trust policy does not say what the role can do). `Assess(Estate)` renders weaknesses as findings — `Privileged` supplied from real IAM data escalates one step AND says why; `ReposComplete` gates the unowned-repository check, declaring itself in `ChecksNotRun` rather than passing silently. **That discipline now also covers the federations it does NOT evaluate.** `Analyze` filtered principals to the GitHub issuer and DROPPED the rest, so a role assumable by an Okta SAML provider â the most common enterprise SSO-into-cloud path, and a real identity transition into the account â was indistinguishable from a role nobody federates into: no finding, no note, estate reads clean. `Analysis.OtherFederated` records them and `Assess` declares them per role in `ChecksNotRun`, NAMING the provider. **Those declarations now reach the PLATFORM too.** The ingest wiring took only `.Findings` and discarded `ChecksNotRun`, so the honest half stayed inside the package and an estate federating through Okta arrived looking exactly like one that federates through nothing. **Provenance is a PARAMETER of the shared persist path** (`findingProvenance`), not something a new producer inherits. The path was copied and its labels were not: reusing it stamped ids `drift-â¦`, marked the clouddrift posture assessed and wrote "cloud drift detected" â first for a SAML trust weakness, then again for a source-code finding from `codesweep`. Neither is drift, which asserts that something CHANGED; in both cases nothing had. A table test asserts every producer declares its own and that only the real drift producer may say the word, so the next reuse must say what it is rather than inheriting a claim about an event that did not happen. CI-identity findings are persisted under their OWN provenance (`ci_identity`) rather than through the drift persister they first reused, which stamped ids `drift-â¦`, marked the clouddrift posture assessed and wrote a ledger entry reading "cloud drift detected". A role trusting an unconstrained SAML provider is not drift â nothing CHANGED, the policy has most likely been that way since it was written â and the ledger is where a claim is meant to be checkable, so a claim there about an event that did not happen is worse than a vague one. `ciIdentityAssess` returns both, and the ingest merges the declarations into the STORED `cloudsnap` coverage notes beside the escalation gaps â stored for the same reason those are: the reader of the attack-path page is rarely the CI job that posted the inventory. Tested through the HANDLER, because mutation showed the assessor-level tests passed with the merge removed. Deliberately DECLARED, not analysed: SAML's claim grammar is `saml:aud`/`saml:sub`, not GitHub's `sub`, and inventing an assessment for it would be exactly the wrong kind of confident. Two refusals ride with it, both mutation-verified â a DENY naming a provider is the policy working and is not reported, and `sts:AssumeRoleWithSAML` is a DIFFERENT action from the web-identity one, so a check looking only for the latter would miss the enterprise path entirely. Enabled by `cloudiam` gaining the **`Federated` principal** (the web-identity trust key whose absence made the whole class invisible), which stays condition-gated — a Federated match is config-possible and only the sub/aud conditions decide |
| `internal/samltrust` | **AWS roles assumable via SAML federation** â the WORKFORCE path into an account (Okta, Entra, ADFS), and how most people actually reach AWS. `ghoidc` and `gcpwif` both cover CI and both DECLARE a SAML trust unassessed rather than judging it; this assesses the one thing decidable from the trust policy alone. **A missing `SAML:aud` condition** accepts an assertion minted for ANY service provider the IdP serves, not only AWS â so anyone able to obtain an assertion for another application at the same IdP can present it here. ADEQUACY of a PRESENT condition is not judged (gcpwif's rule: absence is provable, adequacy is intent), the key is matched case-insensitively because IAM keys are and real policies vary, a DENY is the policy working and is never reported, a web-identity trust stays `ghoidc`'s so one defect is not counted twice, and `Privileged` comes from the collector's admin flag because a trust policy does not say what a role can DO. Evaluated PER STATEMENT, not per role: a role typically trusts several providers and the realistic failure is a legacy one left unconstrained beside a correct one, so the finding names the provider that is actually open rather than condemning the whole role. **`SAML:sub` is deliberately NOT checked** â it looks like the obvious sibling of the audience check and is not: the IdP's role-attribute mapping is what decides which users may assume which role, so an absent subject condition is the INTENDED design and flagging it would fire on nearly every correct account. That distinction is what makes the audience check sound â an absent `SAML:aud` admits an assertion minted for a DIFFERENT service provider, which nobody intended; an absent `SAML:sub` admits the users the customer's own IdP chose to send. Pinned by a test so it is not added later. Wired into `POST /v1/cloud/inventory`; the unassessed-federation declaration REMAINS alongside it, since assessing one case is not assessing the grammar. |
| `internal/gcpwif` | **GCP Workload Identity Federation** — the GCP half of the same question, a separate package because GCP SPLITS THE DECISION ACROSS TWO OBJECTS usually edited by different people: the pool PROVIDER's attribute condition (which tokens the pool accepts) and the SERVICE ACCOUNT's IAM binding (which identities may impersonate it). Neither half is sufficient and neither looks wrong alone — an unconditioned provider reads as "fine, the bindings are narrow", a pool-wide binding as "fine, the provider is conditioned" — and together every GitHub repository on the internet can impersonate the account. A scanner reading one object at a time cannot see it, so **the join is its own critical finding** (`gcp_wif_open_impersonation`) which SUPERSEDES the pool-wide finding rather than firing alongside it (one defect reported twice inflates the estate); both halves still fire alone, at lower severity, because they have different owners. **THE HONEST LIMIT: absence is provable, adequacy is not.** The attribute condition is CEL, and an expression evaluator judging whether someone's condition is "good enough" would be an in-house engine (§13) making a call it cannot support — so an ABSENT condition is definite and a PRESENT one yields only the lexical fact of which attributes it names (`true` is a bad condition but it is not a missing one). An UNRECOGNISED `principalSet` selector is treated as the WHOLE pool, never as narrow: guessing narrow errs toward silence, and Google adds selectors we have not seen |
| `internal/tprm` | **third-party / vendor risk management (TPRM)** — the Vanta-TPRM "finding issues" capability the engine lacked; the vendor portfolio is an asset class. `Assess(vendors []Vendor)` surfaces grounded vendor-risk findings: `vendor-uncertified` (a PII/sensitive-data vendor with no SOC 2 / ISO 27001 — high), `subprocessor-no-dpa` (a subprocessor without a data-processing agreement — GDPR Art. 28, high), `vendor-breach-history` (a vendor with a recorded breach + data access — high), `card-vendor-no-pci` (a cardholder-data vendor without PCI — PCI 12.8, high), `vendor-stale-review` (a critical/high-criticality vendor not reviewed within the window, default 365d — medium). Each carries the vendor-management compliance nexus (SOC 2 CC9.2, GDPR Art. 28, PCI 12.8, ISO A.5.19/5.20/5.22, NIST SR-3/SR-6). Snapshot-driven, LLM-free, grounded (§10) — a well-managed portfolio yields ZERO findings. Live driver: `POST /v1/tprm/ingest` (vendor inventory → findings into the same store → issues/incidents/grc/hitl); a live vendor-inventory connector (procurement/SSO sync) is the follow-on, the posted-inventory path works today |
| `internal/deviceposture` | **endpoint / device posture (MDM-lite)** — the Vanta device-monitoring "finding issues" capability; employee laptops/phones are an asset class. `Assess(devices []Device)` surfaces grounded device-posture findings: `disk-unencrypted` (high; SOC2 CC6.7, HIPAA 164.312(a)(2)(iv), NIST SC-28), `tampered` (jailbroken/rooted, high), `os-end-of-life` (high; SI-2), `no-screen-lock` (medium; AC-11), `firewall-off` (medium; SC-7), `no-edr` (medium; SI-3), `auto-update-off` (low). Snapshot-driven, LLM-free, grounded (§10) — a compliant fleet yields ZERO findings; a missing field never invents risk. Live driver: `POST /v1/devices/ingest`; a live MDM connector (Kandji/Jamf/Intune/Kolide) is the follow-on, the posted-inventory path works today |
| `internal/dataplatform` | **data-warehouse access posture — who can read which table.** `cloudgraph` already classifies BigQuery/Redshift/Spanner as data stores (`classify.go`), so an attack path can reach a warehouse and say "this leads to data"; what it could NOT say is who holds the keys INSIDE. A warehouse runs its own grant system BENEATH cloud IAM (a Snowflake role with SELECT on `analytics.customers` is invisible to every cloud policy evaluator we have), and **Snowflake is not a cloud-provider resource at all**, so it never appeared in an inventory. This closes the last step — the table, and the grant that exposes it. `Assess(Estate)` surfaces: `internet-public-grant` (critical — `allUsers`), `provider-wide-grant` (critical — `allAuthenticatedUsers`, any account at the provider, still outside the org), `account-wide-grant` (`PUBLIC`/Postgres PUBLIC — high on declared-regulated data, medium otherwise), `external-grant-on-sensitive` (high; GDPR Art. 28), `write-access-on-sensitive` (high; SOX ITGC, admin roles exempt), `stale-grant` (unused ≥90d). **Public is deliberately NOT one verdict** — the three scopes differ by orders of magnitude in blast radius. Snapshot-driven, LLM-free, grounded (§10) with four refusals, each mutation-verified: **sensitivity is DECLARED, never inferred from a table name**; **"external" needs `org_domains`** (we will not guess who works there); **unknown last-use is not "unused"**; and the finding's verb follows the privilege (a public INSERT is reported writable, never "readable"). A well-governed warehouse yields ZERO. Live driver: `POST /v1/dataplatform/ingest` → the same store → issues/incidents/grc/hitl; the response carries **`checks_not_run`** so a caller never reads "0 issues" as a clean warehouse when a check was skipped for want of grounding data. Live collectors (Snowflake ACCOUNT_USAGE, BigQuery getIamPolicy, Postgres information_schema) are the credential-gated half |
| `internal/dataclass` | **DATA CLASSIFICATION — deciding what KIND of data an object holds by looking at the DATA, not its name.** THE GAP: across the engine a data store's sensitivity (`cloudgraph.Node.Sensitive`, `estategraph.SensHigh`, `dataplatform`'s declared flag) is only ever COPIED THROUGH from an upstream source or declared by the customer — nothing DISCOVERS it. So every attack path ends at a crown jewel that was ASSERTED, never proven: "this bucket is sensitive" rests on a checkbox, and a checkbox nobody ticked reads as safe. `Classify(Object)` inspects an object's columns (names + a bounded VALUE sample) and returns the data classes actually present (`pii`/`phi`/`pci`/`secret`/`auth`), each with the evidence that found it — so a crown jewel can be a fact. Grounded (§10), four refusals, all mutation-verified: (1) **NEVER from the object's NAME** — a table called "customers" is not evidence (the same refusal `dataplatform` makes; only column names + values count); (2) **a VALUE signal outranks a NAME signal** — a column *named* ssn is `Suspected`, a column whose *values* are SSNs is `Confirmed`, and they collapse to one Confirmed match when they agree; (3) **STRUCTURE is checked, not just shape** — a 16-digit number is not a card without Luhn, a 9-digit number is not an SSN in a reserved range (this is the line between DSPM and a DLP noise generator); (4) **evidence names the column + signal and NEVER echoes a raw value** (auditable without leaking the data). Deterministic, dependency-free, sample-based (metadata + bounded sample, never the full dataset — ADR-0002). A clean object yields nothing. **Wired into the warehouse ingest**: `dataplatform.Classify` runs `dataclass` over the collected columns before `Assess`, so the severity of a public grant reflects what the table actually HOLDS rather than what someone declared. The per-object proof (`discovered_sensitive` — object, classes, and the column-level evidence, which never echoes a raw value) now renders on the database-scan panel, guarded by `internal/uicheck`: it was computed, returned to whoever posted the scan, and shown to nobody, while being the strongest evidence this product has that a crown jewel IS one. The frontend type also declared it `string[]` where the server sends objects — a mismatch nothing caught because nothing read it. **Still open: the GRAPH half.** A table proven to hold PII does not mark a `cloudgraph.Node.Sensitive`, so an attack path still ends at a declared crown jewel; the blocker is NOT Snowflake being special: **no cloud inventory carries any warehouse resource** â `RawAWS` is users/roles/SGs/instances/buckets/grants and `RawGCP` the same shape, so there is no BigQuery or Redshift node to mark either, and `cloudgraph`'s classifier recognising those type strings is a capability nothing feeds. The enabling step is an INGEST field plus a collector, not identity-matching across two models â recorded because the earlier note pointed at the harder problem and would have sent someone to solve the wrong one, so this needs a design decision about identity across the two models, not a wiring change. |
| `internal/estategraph` | **the cross-surface ESTATE GRAPH — the substrate the two L2 agents are meant to be downstream of.** THE PROBLEM IT FIXES: the engine has a real typed graph for exactly ONE surface (`cloudgraph`, walked by `cloudagent`). Every other surface — code, SaaS, identity, OSINT, TPRM, devices, warehouse — is a flat `[]types.Finding`, and cross-surface reasoning happens in `crossdetect.Correlate`, which rebuilds an EPHEMERAL node set per call by regex-matching entity strings and renders the result to prose. The Lead then reads that prose (`l2.Estate.AttackPaths` is `[]string`), so the AI Security Engineer cannot traverse an edge, pivot to a neighbour, or ask what else touches a node; and the AI Pentester (`webagent.Investigate` — a target + seed routes) has NO estate awareness at all. The tell that the shape was wrong is `cloudagent.Context.Bridges []string`: a hand-built channel for smuggling cross-surface knowledge into the one agent with a graph, AS STRINGS. All three agent jobs are graph operations (discovery extends nodes/edges, a pentest walks a path, a remediation cuts an edge). **TWO REFUSALS make it ours rather than a generic graph, both mutation-verified:** (1) **an edge that cannot cite evidence cannot exist** — `AddEdge` returns `ErrNoEvidence`, and `Merge` re-validates so it is not a back door (§10 enforced structurally, because an unproven edge in the agent's ground truth is a hallucination with a data structure around it); (2) **identity resolution is EXACT, never fuzzy** — `Canonical(surface, raw)` normalises known identifier FORMATS (ARN case, URL scheme/slash, email case, `*.iam.gserviceaccount.com`) so a Snowflake grantee and the GCP service account converge on ONE node, but never merges on resemblance (a wrong merge fabricates a path, which is worse than two disconnected subgraphs). Merge semantics are additive-only: sensitivity and exposure flags RISE and never clear, so an unclassified re-assert cannot silently downgrade a crown jewel. `PathsFrom` is bounded and REPORTS truncation; `ChokePoints` is real betweenness over enumerated paths (endpoints excluded, counted once per path) rather than counting occurrences in rendered text. **STRANGLER, NOT BIG-BANG**: this lands ALONGSIDE `crossdetect`, which keeps working untouched; surfaces move over one at a time and `crossdetect` retires when the last one has. Nothing consumes it yet — the substrate ships first, deliberately |
| `internal/estateingest` | one converter per surface into `estategraph` (the strangler seam; `estategraph` stays a LEAF and must not learn about every detector). **`ghoidc.go`** adds the CI→cloud edge `code:repo --assumes--> cloud:role` — the wedge edge that needs NO mistake: unlike a leaked credential, the trust is deliberate infrastructure working exactly as configured, and an attacker who lands a workflow in a trusted repository gets the role legitimately with no secret to steal. Mirrors the leaked-key refusal exactly: a WILDCARD subject names no single repository, so the role node is emitted and the edge is NOT. Direction is repo→role because that is the move; reversed, the rendered path reads backwards. **`ghidentity.go`** closes the last hop — the HUMAN who controls the code — and is where the discipline shows: Okta names a person by EMAIL, GitHub by LOGIN and does not publish their email, so nothing in either dataset says alice@acme.com is @alice-acme. That is a RESEMBLANCE, and a wrong merge produces a confident WRONG path that sends someone to revoke the access of a person who never had it while the person who does keeps theirs. The mapping must be ASSERTED by a system that knows it (Okta SCIM, GitHub SAML external identity) and the accepted-source set is deliberately tiny; an unattributed link is REFUSED, not softened. With no assertion the chain is reported BROKEN, the unlinked accounts NAMED, and the message says which integration closes it — a broken chain we can name beats a complete-looking one built on a guess, and unlike a guess it is fixable. Case-insensitive login matching IS done, because GitHub logins being case-preserving-but-not-case-sensitive is a documented platform fact rather than a resemblance judgement |
| `internal/tenanteval` | **the customer's OWN eval suite** — the answer to "is this still catching the thing that bit US?", which no public benchmark can give and which a vendor's number about a vendor's corpus cannot either. Cases are not authored by us: each is a judgement the CUSTOMER already made — a finding a human REINSTATED after the filter dropped it, an issue they IGNORED as a false positive, a fix a re-scan CONFIRMED closed. TWO GRADERS over the same cases: `Score` replays the CURRENT L1.5 chain (`l15.Enrich` — the same code the product runs, not a simulation), and `ScoreModel` asks the tenant's OWN configured model, so a BYOK customer can finally see whether the model they chose helps ON THEIR ESTATE. `Compare` is the ablation, and it refuses to declare a winner on a tie, on a suite too small, or across arms graded on different case sets. Grounded (§10) throughout: an empty suite has NO score (a vacuous 100% would rise as a customer does less), an unanswered case counts AGAINST the model (three of twenty right is not 100%) and carries WHY (a wrong key, a rate limit and a chatty model are different problems), and "no model configured" is reported as itself and never as a zero. Each arm keeps its OWN recorded history (`Arm`/`Model` on `platform.EvalRun`) — interleaved, a trend would compare a model's score against the filter's; and a lower score after a model SWAP is reported as a reason to reconsider the switch, never in the same words as a genuine regression. The model is only ever GRADED: nothing it returns can keep, suppress or alter a real finding. `GET /v1/eval` (free, deterministic) · `POST /v1/eval/model` (a POST on purpose — it spends a model call per case on the customer's key, so it must be asked for, never done because a page rendered) + the `/eval` page. **THE FEEDBACK LOOP (`platform.Feedback` + the recovered signals).** Every case source above is
INFERRED from an action the customer took for another reason, and all of them answer the same question:
did we RANK this right. Four changes close the loop, and three of them were signal the product was
ALREADY PRODUCING AND DISCARDING:

1. **`retest.ApplyReattack` disagreements are now machine-readable** (`FixVerification.RescanSaidFixed` +
   `.Disagreement`). The rescan saying "gone" while the exploit still RUNS is the case the product's
   credibility rests on; it was explained in English on the Evidence string and recorded nowhere
   countable, so building the corpus meant regexing prose. Two kinds, separate because they indict
   DIFFERENT methods: `rescan_missed_live_exploit` (absence-as-evidence failed — the dangerous
   direction, a customer one step from being told they were safe) and `scanner_sees_variant` (the
   re-test playbook failed). Only the first becomes a case (`SourceEvidenceInsufficient`, a Keep).
2. **An `accepted_risk` suppression AGREES with us** and was producing nothing. `BuildSuite` only looked
   for `false_positive`, so the one reason a customer gives that CONFIRMS the finding was silent while
   the reason that disputes it trained the filter — the corpus could only ever learn it was wrong. Now
   `SourceAcceptedRisk`, a Keep. `wont_fix` stays out: it is ambiguous, and a case source has to know
   which answer it is recording.
3. **`platform.Feedback` is the one genuinely missing channel** — deliberately NOT the ignore endpoint
   with an extra field. An `IgnoreRule` is an ACTION (hide this); Feedback is an OPINION. The two axes
   are independent on purpose: `Verdict` judges the FINDING, `Evidence` judges our PROOF, and "yes this
   is real, and no you did not show me why" is the most useful sentence a customer can offer and is
   unrepresentable if they collapse. Recording an opinion CHANGES NOTHING (no suppression, no severity
   move, asserted by test and stated in the UI copy) — feedback a person suspects will hide their
   finding is feedback they will not give honestly. `unclear` is first-class, because "I could not
   understand this finding" is a defect in the write-up rather than an absence of opinion. Labels nobody
   defined are REFUSED with a 400, since a corpus with open-ended labels cannot be counted.
   `POST/GET /v1/issues/feedback` + the `IssueFeedback` control, whose GET now returns a SUMMARY and the `/issues` page renders it. Both axes were being collected and neither was ever shown back: the verdict reached `tenanteval` as a case, the evidence axis reached it as PROSE appended to a reason string ("and said our evidence did not show them why"), and no page read any of it â so a person who answered had no sign it landed anywhere, which is a question asked rather than a loop closed. The same uncountable-prose shape `retest.ApplyReattack` had before `RescanSaidFixed`/`Disagreement`. `evidence_insufficient` is the ACTIONABLE half â a fault in OUR write-up rather than in the finding â so it is counted separately from the verdicts and aggregated per issue key (`weakest_explanations`, worst first) to name which description to fix. `unclear` and UNANSWERED are counted rather than folded away, since "I could not understand this" is an answer and a low insufficient count over mostly-unanswered questions is not approval, which sits BELOW the actions on its own
   line so it never reads as one of the controls that makes the row move.
4. **Explicit answers OUTRANK inferred ones** (`SourceHumanVerdict`, ordered directly below
   reinstatements). Someone who typed "false positive" said something a suppression can only be read to
   imply; where the click and the typed answer disagree, the typed answer is the one they meant.
   `BuildSuiteFrom(Inputs)` replaces a fifth slice parameter — two adjacent `[]types.Finding` arguments
   are trivially swappable and the compiler cannot tell, which yields a suite that scores fine and means
   nothing.

**Cold start:** `StarterCases` is a small FIXED set with publicly checkable answers (a KEV-listed RCE and a live `sk_live_` key must be KEPT; the AWS-documentation example key `AKIAIOSFODNN7EXAMPLE` and a Stripe `pk_test_` PUBLISHABLE key must be SUPPRESSED — both are strings their own vendors publish, and reporting them is the alert that teaches a team to ignore alerts). It exists because a suite built from the customer's decisions is EMPTY on day one, which is the wrong way round for someone choosing which model to trust. Three rules keep it from contaminating the claim: scored + recorded under its OWN arm (`ArmStarter`), never folded into "agreement with your experts"; BALANCED 2/2 so a constant answerer scores half, not 100% (verified live — a stub answering only KEEP scored exactly 2/4); and every case CITES the external authority that settles it, so the answer key is checkable rather than taken on our word. **Note the key discipline:** the suppression source once built the issue key by hand and matched nothing for every tenant, and its test passed because the fixture hard-coded the same wrong format — always key through `crossdetect.DedupKey`. |
| `internal/assetregistry` | shared `HandlerFor(assetType)` (so `cmd/tsengine` + `cmd/platform` don't duplicate routing) |
| `internal/crossdetect` | the **unified cross-detection** layer (orchestration glue over `correlate` + the flat finding list â adds no detection, Â§10/Â§13 hold). Six capabilities: (1) **attack paths** â buckets findings by inferred asset type so `correlate.Correlate` builds cross-surface chains (a finding bridging, via a real shared entity — an AWS key, a non-AWS provider secret (GitHub/Slack/Google/Stripe token, `EntSecret`), an ARN, host, IP, S3 bucket, or a human email — to a crown jewel on another surface, so a leaked GitHub token in code chains to the SaaS org-admin it unlocks, not only AWS keys); `GET /v1/attack-paths` + `/attack-paths` page + dashboard banner. (2) **unified issues** (`UnifiedIssues`) â "one issue, many signals": collapses findings sharing a CVE (else rule\|endpoint) into one Issue carrying the worst severity + the distinct source scanners + `Confirmed` (â¥2 tools agree); `GET /v1/issues` + `/issues` page + dashboard noise-reduction banner. (3) **issue suppression** â `GET /v1/issues` hides issues with a `platform.IgnoreRule` (default) / `?show=ignored`; `POST /v1/issues/ignore`\|`/unignore` (ledger-recorded) + the `/issues` Active/Ignored toggle + per-row ignore/restore. (4) **custom exclusion rules** (`exclude.go` â Aikido "custom rules": exclude paths/packages/conditions) â `platform.ExclusionRule` (field â rule_id/package/path/cve/any + a `*`-glob `Pattern`); `ApplyExclusions` drops matching findings BEFORE `UnifiedIssues`, so excluded noise never becomes an issue (the `excluded` count rides on `GET /v1/issues`); `GET /v1/exclusions` + `POST /v1/exclusions`\|`/exclusions/delete` (ledger-recorded) + the `/issues` exclusion-rules manager. (5) **runtime correlation** (`runtime.go` â Runtime Protection, ADR-0007 Phase 0) â `platform.RuntimeEvent` is an in-app-firewall/RASP attack observation (the OSS "Zen" sensor streams its block events in); `AnnotateRuntime` flags any issue whose endpoint path matches a runtime event â `Attacked`/`AttackCount` = observed-in-the-wild (the strongest exploitability signal). tsengine consumes the signal, never blocks (Â§13). `POST /v1/runtime/events` (ingest, single or batch; body-tenant ignored for isolation) + `GET /v1/runtime/events` + the `attacked` count on `GET /v1/issues` + an "under attack" badge/stat on `/issues`. Phase 1 (the managed in-app sensor) stays ADR-0007-gated. (6) **data-tier prioritization** (`datatier.go` â the Synthesia "tier repos by customer-data exposure" idea) â an owner classifies each asset's data sensitivity (`platform.DataTier` 1=customer-data â¦ 3=low, stored in `Asset.Meta["data_tier"]`, default Standard; `POST /v1/assets/{id}/data-tier`, surfaced on `GET /v1/assets` as `data_tier`/`data_tier_label`, set via the `/assets` Data-tier control). `RiskWeight(severity, tier)` is the tier-adjusted priority (tier 1 +50%, tier 3 â40%; severity stays dominant within a tier, so a Medium on a customer-data asset can outrank a Medium on a low-sensitivity one or edge a Low on a standard one); `PrioritizeByDataTier` attributes each issue to a tiered asset (BEST-EFFORT + grounded, Â§10 â only when the asset's Target literally appears in the issue Endpoint; repo file:line endpoints stay Standard until a findingâasset link exists in the data model) and re-ranks `GET /v1/issues` so the highest-risk issues lead (no-op while every asset is Standard). Engine `surface_priority` is untouched (Â§18.2 inv 1) â this is a platform-layer reordering only |
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
minutes-long scan; `Jobs==nil` falls back to synchronous (test back-compat). **The OAuth
callback queues the FIRST scan the same way** (`kind:"connect"`, redirect carries `&job=<id>`,
`/assets` polls it via `/api/job`): it used to run `DiscoverAndScan` synchronously INSIDE the
provider redirect, so the browser sat on GitHub's redirect page for the whole scan, the edge timed
out first, and the cancelled request context killed the scan mid-flight — the one moment the
funnel is built around ended on a timeout page. `DiscoverAndScan` also now continues past a single
failing asset (as `RescanTenant` always did) and returns the first error beside the count, so a
partial first pass is reported as partial. Observability:
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
password â email-based invites are the next step). **A third role, `auditor`, is READ-ONLY** — the external SOC 2 / ISO auditor, a CPA-firm partner,
a customer's security reviewer: they read every finding, control, report and evidence pack and can
change nothing. Enforced in the `auth` middleware (every non-GET/HEAD/OPTIONS request is refused
`403 read_only_role`), not by hiding buttons, so a hand-crafted request is refused the same way a
click is; the auth-management endpoints stay open so an auditor can rotate their own password.
Invited via `POST /v1/auth/invite` with `role: auditor`; `owner` is never invitable and an unknown
role is a 400, never a silent member seat. Before this the only way to give an auditor access was a
full member seat, which can start scans and approve fixes. **Forced first-login rotation is wired**:
an invited member's account carries `User.MustChangePassword`; while set, the `auth`
middleware blocks every app endpoint with `403 password_change_required` (the auth-mgmt
endpoints â me/logout/password â use `sessionAuth`, so they stay reachable), and
`POST /v1/auth/password` (verify current â set new â clear the flag) unlocks it. So the
owner-issued temp password can't remain the standing credential. **A password change also revokes the user's OTHER sessions, and a FAILED revocation is now reported.** That call exists to evict a stolen token, which is why most people are on that page at all - and its error was swallowed, so the response said `{"ok":true}` to exactly the person who believed their password was compromised while an attacker's session stayed valid. The change itself still succeeds and is never rolled back (a user who cannot change their password is worse off than one whose old sessions linger); the response carries `sessions_revoked` plus a `detail` the change-password page renders instead of navigating away. `signed_out` covers the other branch - the wipe landed and took the caller's own session with it, which is safe but needs saying, or their next request bounces them to the login page for no visible reason. Frontend: a top-level
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

**IMAGES ARE PUBLISHED; A VM PULLS.** `release.yml` used to publish exactly ONE image — `host`, the
engine CLI. The three images a deployment actually runs were never built by CI, so
`docker-compose.prod.yml` carried `build:` stanzas and every VM compiled Go, built a Next.js bundle
and assembled a 45-scanner sandbox before it could serve a request — putting the box's toolchain on
the production surface. Meanwhile prod pointed at `tsengine/sandbox:0.1.0`, a LOCAL tag nothing
pushed, while the weekly signature rebuild published `sandbox:signatures-latest`, an address nothing
read: a refresh pipeline publishing where no deployment looks is indistinguishable from no refresh
pipeline, and the only signal it worked was a green tick.

`.github/workflows/images.yml` publishes `platform`, `frontend` (both multi-arch) and `sandbox` to
GHCR. It is REUSABLE (`workflow_call`) and `signatures.yml` calls it for the weekly rebuild, so the
refresh produces the SAME tags a deployment consumes — one definition, no drift. `docker-compose.prod.yml`
now PULLS; `docker-compose.build.yml` is the override that restores local building (air-gapped, a
fork, uncommitted changes), and `deploy-single-box.sh` pulls by default with `--build` for the old
behaviour. `make pull` / `make pull-slim` / `make up-prod`.

**THE IMAGE MUST CONTAIN WHAT IT CLAIMS TO — codeql and kics were absent from EVERY image.** Both
fetches 404'd and both were swallowed by `|| echo "non-fatal"`, so the build exited 0:
codeql publishes `codeql-linux64.ZIP` and we asked for `.tar.gz`; kics v2.1.3 publishes NO platform
binaries at all (and the arch string was `x64` where releases use `amd64`). Both gate on
`ts_want repository`, which `full` satisfies — so production shipped without the repository asset's
taint-analysis escalation (§5.3) and its deeper IaC pass, while `tool-freshness` reported both as
"pinned", asserting a version for a binary that was not there. Same defect class as a scanner that
cannot reach its DB reporting a clean scan (§12.3): a failure swallowed into a success.

**codeql is x86_64-ONLY and that was invisible too.** Upstream ships one Linux CLI, `codeql-linux64`,
and the old `CQ_ARCH` ternary printed `linux64` in BOTH branches — dressing the absence of an arm64
build up as arch handling. Measured on an arm64 build with the URL corrected: the 469MB download and
the unzip both SUCCEED, then `codeql version` dies with `Trace/breakpoint trap`, an x86_64 binary
under emulation. So on arm64 it is deliberately STUBBED (exit 127 → `tool.DidNotRun` → `ToolsFailed`)
rather than installed broken: an unrunnable binary on `$PATH` fails at scan time with an error nobody
can map back to the image's architecture. The taint escalation is an amd64 capability, and the image
now says so instead of implying otherwise. `verify-tools.sh` exempts codeql on non-x86_64 for the
same reason — demanding a binary upstream does not publish is not a check, it is a broken build.

A third bug rode along: the kics release tarball does NOT bundle `assets/queries`, despite the
comment saying so — it holds LICENSE, README and the binary. kics without its query corpus RUNS AND
FINDS NOTHING, which is worse than being absent, because an absent tool lands in `ToolsFailed`. The
corpus now comes from the source archive for the same tag, pinned together so binary and rules match.

Why the existing guard missed it: `toolsbundle.TestSandboxImageProvidesEveryToolBinary` asks whether
a tool's NAME APPEARS IN THE DOCKERFILE — a textual check, as its own doc says. Both names appear, on
the install lines that were failing. It verifies INTENT; nothing verified OUTCOME.
`docker/sandbox/verify-tools.sh` now runs as the FINAL build step and fails the build when a
`TOOLSET=full` image is missing any scanner binary or has one stubbed. Its list is kept in sync with
the wrappers by `TestVerifyToolsListMatchesTheWrappers` (a hardcoded list is only as good as what
stops it drifting). It skips slim images by design — there a stub is the intended outcome.

**A pip PIN was being silently defeated, found by the same check.** The Python toolset installs one
package at a time (deliberate — isolating each install avoids resolver backtracking), so
`semgrep==1.96.0` installed first and then `mobsfscan`, which requires semgrep UNPINNED, quietly
upgraded it. Measured: the Dockerfile pinned 1.96.0 and the image ran **1.172.0**, while
`tool-freshness` reported 1.96.0 — a version claim about a different binary than the one installed,
the same defect as claiming a version for a binary that is not there. Fixed with a pip CONSTRAINTS
file (`-c`), which applies across every install without merging them into one resolve, so the
isolation is kept and the pin holds. Verified in the built image: semgrep 1.96.0, with mobsfscan,
bandit and modelscan all still installing.

**garak was REMOVED.** It was the only registered tool with ZERO callers — no asset handler, no
agent, no dispatcher — because `ai_application` does not exist, so it shipped a large ML dependency
set in every image for a capability nobody could invoke. Wrapper, registrations and image install are
gone; it returns when the asset does (ADR 0012). `ctoreadiness` still RECOMMENDS garak to the
customer but no longer claims we ship it. `modelscan` moved from the `ai` toolset to `repository`,
which is the asset that actually dispatches it — it would otherwise have been stubbed in the very
slim image that needs it.

**THE TOOLSET GROUPS DID NOT MATCH DISPATCH, so every slim image was broken.** `toolset.sh` gates a
tool on ONE asset, and that mechanism was written for `make sandbox-image-dev` — whose own help text
says "partial coverage, dev only" — then reused to publish per-asset PRODUCTION images. Tools do not
belong to one asset. Measured against the handlers: `grype` gated on repository but dispatched by
**container** too; `httpx` gated on web but dispatched by **api, domain and ip**; `sqlmap` gated on
web but dispatched by **api**; `schemathesis` gated on api but dispatched by **web**; `modelscan`
gated on `ai` but dispatched by **repository**. So `sandbox:container-latest` had no grype — a
primary container CVE scanner — and three images had no httpx. Confirmed by building one: modelscan
was genuinely absent from the repository image.

`ts_want_any` + a quoted list on `ts_install` make the gate able to say "either", and every group is
widened to the assets that really dispatch it.
`TestToolsetGroupsCoverEveryDispatchingAsset` derives the requirement FROM THE HANDLERS and fails
when a gate is narrower than dispatch — the groups were wrong precisely because nothing connected
them to dispatch, so fixing the five without that guard would leave the next tool to drift the same
way, silently, in an image nobody builds locally. Mutation-verified: reverting grype or httpx
reproduces the original defect by name.

Proven by building one: `TOOLSET=container` now carries trivy, grype, dockle, syft AND cosign — all
five the container handler dispatches, grype included — while correctly excluding semgrep, codeql,
prowler and sqlmap. **1.43 GB against 5.8 GB for `full`**, so the slim images are worth having now
that they are correct.

**PER-ASSET SLIM SANDBOX IMAGES.** The sandbox is built once per TOOLSET (`full` + web · api ·
repository · container · ip · domain · cloud), so a box that only scans repositories stops pulling
codeql, prowler and scoutsuite. `sandbox.ScanImages.For(assetType)` resolves the image per
scan: an explicit override, else `TSENGINE_SANDBOX_IMAGE_TEMPLATE` with `{toolset}` substituted, else
**the full image** — the only safe default. `sandbox.AssetToolset` is the asset→toolset mapping,
written out rather than derived by string-munging (cutting `container_image` at the underscore also
"works" for `ip_address`, and would silently produce garbage the day an asset is renamed); an asset
absent from it falls back to full, and a test pins it against `types.AllAssetTypes()`. Safety is
STRUCTURAL, not documentary: `toolset.sh` STUBS an unselected tool to exit **127**, which
`tool.DidNotRun` reports as "did not run" → `ToolsFailed` → degraded pass. So the wrong slim image
degrades a scan honestly instead of returning a clean one — verified end to end. **The DB is still
SQLite on a volume (single-node); Postgres remains the `store.Store` successor.**

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
| **Risk register** (vCISO judgment) | `pkg/platform.Risk`, `internal/grc/risk.go`, `internal/platformapi/risks.go`, `/risks` | `CandidateRisks` clusters high+ findings by coarse category (CWEâcat, else tool), cites finding ids, sets a *starting* likelihood/impact. Seeded on-demand (`POST /v1/risks/seed`) AND **automatically after an L2-agent investigation** (cloud-investigate calls `Deps.seedRisks`, AND the post-scan `AutoReviewAfterScan` calls `seedRisks` too — so a routine scan's high+ findings reach the vCISO desk, not only the on-demand cloud path) â so the agent's proven attack paths land candidate risks on the vCISO desk (agent proposes â named human disposes) | `POST /v1/risks/{id}/decision` â a named owner accepts/mitigates/transfers/avoids residual risk with a rationale; the agent never accepts risk |
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
