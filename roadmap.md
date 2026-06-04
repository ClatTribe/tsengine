# tsengine Roadmap — toward an AI-Native Offensive Security & Triage Agency

> **Product thesis.** Sell an *autonomous, continuous adversarial loop*, not a once-a-year
> static PDF. Deploy AI agents that continuously hack staging/APIs/AI-models while an AI
> triage layer separates the real from the noise — and *proves* each finding before it alerts.
>
> **Where we are honest:** the engine today is the **hardest part** — grounded autonomous
> reasoning + verified remediation across **all three agent flavors** (cloud, web/api, LLM
> red-team), each with an anti-circularity bench — plus a **deployable service**, the
> **report** deliverable, and a **findings DB**. What remains is mostly **product surface**
> (multi-tenant SaaS, continuous loop, delivery/ingest connectors, compliance workflow) and
> **agent depth** (browser/DOM, business-logic, RAG, live LLM-target adapter). This roadmap is
> the gap, prioritized.

Status legend: ✅ built · 🟡 partial · 🔴 missing. Items are tracked here; convert to PRs as picked up.

> **What's left at a glance** (prioritized, buildable in-tree first):
> 1. **SCA / code reachability triage** — the one hole in Validation (does our app *call* the vulnerable dep function?). §3.
> 2. **CI/CD gate trigger** — opens the Shift-Left pillar (offensive test on push → pass/fail). §1.
> 3. **SARIF / Snyk / GHAS importers** — triage other scanners' alerts through the grounding engine. §3.
> 4. **Live HTTP target adapter + RAG probes** — finishes the LLM red-team service. §2.
> 5. **Browser/DOM + business-logic (BOLA/BFLA)** — web agent depth. §1.
> 6. **Continuous scheduler + delivery connectors (PR/Jira/Slack)** — converts engine → retainer SaaS. §4.
> 7. **Multi-tenant store + onboarding + billing + compliance workflow** — the SaaS/Vanta surface; an *infra* project, not in-tree code. §4/§5.
>
> Items 1–5 are Go you can write + test in this repo today; 6–7 need real infrastructure (DB, OAuth apps, a cluster).

---

## 0. What's built (the moat)

- ✅ **Detection across 7 asset types** — OSS-wrapped (nuclei, sqlmap, semgrep, trivy, prowler, …), L1 anchor + escalation + registry tiers (arch.md).
- ✅ **The cloud AI agent** (`internal/cloudagent`) — LLM brain + deterministic tools, **evidence-grounded** (can't record a finding the graph doesn't support), at **parity with the deterministic engine** on a 612-resource account.
- ✅ **Correct IAM reasoning** (`cloudiam.Authorize`) — identity ∧ boundary ∧ SCP ∧ resource-policy ∧ conditions; attack-path graph (`cloudgraph`); blast radius.
- ✅ **Verified remediation** (`cloudengine.GenerateRemediations`) — SCP/IAM-Deny/SG artifacts, self-checked via `cloudiam.Authorize`; `--export` to disk.
- ✅ **L1.5 enrichment** — FP filter, corroboration, confidence, threat-intel (KEV/EPSS), `compliance.map` (SOC2/PCI/HIPAA/CIS/NIST).
- ✅ **Signed evidence/attestation** (ed25519 over snapshot+findings+evidence).
- ✅ **Deployable service** — `tsengine serve` (tool-replay API behind bearer auth + `/healthz` `/readyz` `/version` probes, request logging, graceful SIGTERM drain), host container image (`docker/host`), version-stamped builds, tag-triggered release pipeline (cross-platform binaries + GHCR image), ops guide (`docs/DEPLOYMENT.md`).
- ✅ **The LLM red-team agent** (`internal/llmredteam`) — multi-turn attacker + **deterministic verifier**; a jailbreak is recorded only when a planted canary/sentinel leaks or a forbidden tool fires (grounded, not asserted). 100% recall / 0 false breaches vs an emulated population of vulnerable + hardened targets.
- ✅ **Anti-overfit benchmark ladder** — in-distribution / held-out / llm-emulate / CloudGoat / large procedural dataset (cloud); **`internal/webrange`** (web) + **`internal/llmredteam`** (LLM) procedural populations with decoys — grounding proven non-circular for all three agents (100% recall, 0 false positives across seeds).

---

## 1. Service: Autonomous AppSec Pentesting  🟡

The agentic exploiter now exists for **cloud AND web/api** (`internal/webagent`). Remaining gaps are depth (browser/JS, business-logic) and delivery (CI gate).

| Capability | Status | Gap |
|---|---|---|
| Web/API detection (katana, nuclei, sqlmap, dalfox, OpenAPI ingest) | ✅ | — |
| **Multi-turn agentic exploitation** (analyze response → adapt → follow-up) | ✅ web/api (`internal/webagent`), ✅ cloud | the cloudagent brain+tools pattern now drives live HTTP; same grounded ReAct loop |
| **Grounded findings + injection defense** (finding rides on a deterministic indicator, not the model reading attacker text) | ✅ | `record_finding` rejects any claim whose cited turn lacks the class's indicator (sqli⇒sql_error, xss⇒reflected_input, redirect⇒redirect:host); `confirm_exploit` re-fires to verify |
| **Structural safety** (host allowlist + request cap + throttle, never LLM-trusted) | ✅ web | the `Requester` (cloudsafety principle); legal RoE/consent capture still 🔴 (§6) |
| **Context-aware fuzzing** (read client-side JS + API spec → craft payloads) | 🔴 | new tools: spec/JS reader, payload-crafter |
| **Prove-in-sandbox validation** (execute the exploit before alerting) | 🟡 web | `confirm_exploit` re-fires the proving request in isolation (indicator must reproduce); full sandboxed payload execution still 🔴; for cloud we prove *reachability* instead |
| **Signed evidence bundle** (tamper-evident PoC deliverable) | ✅ web | `BuildEvidence`/`SignEvidence`/`VerifyEvidence` (ed25519 over canonical JSON) + CLI `web-investigate --export-evidence` / `web-verify`; proving request+response captured per finding |
| **Vuln coverage** | ✅ 5 classes | sqli, xss, open_redirect, **path_traversal/lfi**, **command_injection/rce** — each grounded on a deterministic indicator |
| **Seed from L1 scanners** (confirm, don't rediscover) | ✅ web | `Options.SeedFindings` surfaces nuclei/sqlmap/dalfox leads as *suspected*; the agent must still ground them |
| **CI/CD gatekeeping** (offensive test on every push) | 🔴 | VCS webhook trigger + scoped staging run + pass/fail gate |
| **Browser-driven DOM/JS exploitation** | 🔴 | Playwright tool (deferred — see docs/design/web-agent.md) |
| Authenticated + business-logic / BOLA/BFLA / IDOR | 🟡 | seed_auth exists; authz-logic is a documented backlog item (no OSS does it — agent's job) |

**Built (this rung):** `internal/webagent` — single grounded agent + 6-tool catalog
(`list_routes`, `send_request`, `record_finding`, `confirm_exploit`, `note_defense`,
`finish`), deterministic indicators, the safety `Requester`, `tsengine
web-investigate --target`. Proven end-to-end against an in-process mock-vulnerable
target (planted SQLi found, recorded grounded, and verified; ungrounded + injected
claims rejected; off-scope/over-budget requests blocked). Design + decisions in
`docs/design/web-agent.md`.

**Next:** context-aware payload crafting (JS/spec readers), full sandboxed
exploit execution, CI-gate trigger, browser tool for DOM XSS.

---

## 2. Service: Agentic / LLM Red Teaming (AI-Sec)  🟡

**Core built (`internal/llmredteam`)** — the multi-turn attacker agent + deterministic verifier + emulated population. Remaining gaps are the live HTTP-target adapter and depth (RAG extraction, richer orchestration).

| Capability | Status | Gap |
|---|---|---|
| Attacker agent + deterministic verifier (grounded breaches) | ✅ | `internal/llmredteam`: `record_breach` rejected unless the verifier confirmed it on a real turn |
| **Multi-turn jailbreak orchestration** | ✅ | conversation is multi-turn; technique battery (direct/ignore/DAN/encoding/injection/tool-abuse) via the `Prober`, or a real LLM brain |
| **System-prompt extraction + secret leak** | ✅ | `secret_leak` (planted canary) + `system_prompt_leak` (sentinel) breach classes |
| **Agent goal-hijack / tool-misuse** | ✅ | `forbidden_tool` breach — denylisted tool fired |
| **PII disclosure** | ✅ | `pii_leak` breach (planted PII pattern) |
| **Indirect prompt-injection auditing** (untrusted-data → action) | 🟡 | injection technique + the inward-pointed defense exist; a poisoned-RAG corpus is the depth gap |
| Emulated eval (vulnerable + hardened decoys, recall vs answer key) | ✅ | `Generate`/`ScorePopulation`: 100% recall, 0 false breaches across 7 seeds; `tsengine llm-redteam --bench` |
| `llm_endpoint` asset type + **live HTTP target adapter** | 🔴 | OpenAI/Anthropic/custom chat-endpoint adapter; wire into the L1 dashboard |
| **RAG / vector-DB leakage** | 🔴 | extraction probes + leak-detector over a retrieval corpus |
| **Our own** agent-injection resilience (we read untrusted pages/logs) | 🟡 | the same harness points inward; web/llm agents already ride on grounded indicators not model-read text |

**Built:** `internal/llmredteam` — `Target`/`Engagement`, the deterministic verifier
(`detectBreaches`), the attacker loop + 3-tool catalog (`send_prompt`,
`record_breach`, `finish`), the `Prober` technique battery, the emulated population
+ scorer, `tsengine llm-redteam --bench`. Design: `docs/design/llm-redteam.md`.

**Next:** live HTTP target adapter, RAG extraction probes, signed evidence bundle
(reuse `webagent.EvidenceBundle`), real-model attacker benched vs the population.

---

## 3. Service: AI Triage / Autonomous SOC Analyst  ✅🟡

**Closest to today's strength** — but cloud-shaped; needs code-reachability + delivery.

| Capability | Status | Gap |
|---|---|---|
| **Reachability prioritization** (real vs config-bad noise) | ✅ cloud | this is the core competency |
| **Verified remediation** (the fix is proven to cut the path) | ✅ cloud | — |
| **Code/SCA reachability** ("does our app *call* the vulnerable function?") | 🔴 | call-graph/taint reachability over repo findings (CodeQL/semgrep escalation exists; no agentic triage over it) |
| **Auto-generated Pull Requests** | 🔴 | GitHub App: open a PR with the verified fix |
| **ChatOps verification** ("why is this a risk?" in Slack) | 🔴 | Slack/Teams bot over the finding + attack-path |
| Ingest other scanners' alerts (Snyk/GHAS/cloud) to triage | 🟡 | prowler ingested; add Snyk/GHAS/SARIF importers |

---

## 4. Platform / SaaS plumbing (services-company table stakes)  🔴

| Capability | Status | Note |
|---|---|---|
| **Deployable service + health + auth + packaging** | ✅ | `tsengine serve` (bearer-auth `/replay` + liveness/readiness/version probes, graceful drain), host image, release pipeline (binaries + GHCR), `docs/DEPLOYMENT.md` — the engine runs as a service now |
| Multi-tenancy + RBAC + data isolation | 🔴 | engine is single-scan; tenants/clients/teams model |
| Durable **findings DB** + lifecycle (open→fixed→verified→closed) + SLA + ownership | ✅ | `internal/findingstore` + `tsengine findings ingest/list/set` — fingerprint dedup across scans, auto open→fixed (disappeared) / reopened (returned), per-severity SLA + overdue, owner assignment, audit history, JSON-backed. Multi-tenant SQL is the separate platform layer |
| **Continuous scheduling** (cron + event/CI-triggered) | 🔴 | the "continuous loop" the thesis sells |
| Integrations: Jira/Linear, Slack/Teams, GitHub/GitLab, SSO | 🔴 | delivery + ingest connectors |
| Customer **onboarding / connect** (read-only cloud role, GitHub App, OAuth) | 🔴 | how a client plugs in |
| Dashboards + posture trend + exec report | 🟡 | webappsec named; engine emits JSON |
| **Report generator** (branded VAPT deliverable) | ✅ | `internal/report` + `tsengine report` — branded Markdown + self-contained HTML (print-to-PDF) from any engine output (vulnerabilities.json / web evidence bundle / LLM red-team); exec summary, risk dashboard, per-finding evidence + remediation, compliance mapping, signed-attestation provenance. SOC2 evidence-pack templating is the next slice |
| HITL **analyst console** (review/accept/reject/add manual findings, sign report) | 🔴 | deferred; required for a VAPT firm's sign-off |
| Billing / SOW / engagement mgmt | 🔴 | commercial layer |

---

## 5. Compliance (SOC2 / ISO / PCI) — the underestimated 80%  🟡

Most of SOC2 is **evidence + workflow**, not scanning. We cover the ~15–20% that is technical posture.

| Capability | Status | Gap |
|---|---|---|
| Finding → control mapping | ✅ | `compliance.map` (SOC2/PCI/HIPAA/CIS/NIST) |
| Signed, pinned evidence pack | ✅ | `attestation` |
| **Org-evidence connectors** (IdP/Okta, HR, MDM, VCS, ticketing) | 🔴 | the *heart* of a Vanta/Drata — almost entirely absent |
| **Continuous control monitoring** over an audit *period* | 🔴 | point-in-time today; need control-test scheduling + timeline |
| **Control breadth** (~60–100 TSC: access reviews, vendor/TPRM, change mgmt, BCP/DR) | 🔴 | we operate ~the technical subset |
| **Policy management** (infosec/IR/access-control policies) | 🔴 | generate + version |
| **Auditor workflow** (evidence requests, auditor portal, gap report) | 🔴 | — |
| **Trust center + questionnaire automation** (SIG/CAIQ auto-answer) | 🔴 | modern up-sell |
| PCI ASV scan / mandated annual pentest deliverable | 🟡 | detection exists; framework-specific report doesn't |

---

## 6. Trust, safety, quality (what makes it defensible)  🟡

| Capability | Status | Gap |
|---|---|---|
| Read-only enforcement for cloud (Guard + scoped STS) | ✅ | `cloudsafety` |
| **Runtime guardrails for active web/api testing** (rate-limit, scope, do-no-harm) | 🟡 | web agent's `Requester` enforces host allowlist + request cap + throttle structurally (never LLM-trusted); a global per-engagement budget + kill-switch + audited scope policy across all agents is the remaining slice |
| **Authorization / consent / RoE capture** (legal) | 🔴 | required to test client assets |
| **Agent-injection resilience** (prompt injection from scanned content) | 🟡 | web + LLM agents ride on grounded indicators, not model-read attacker text (proven: a lying reply can't fabricate a finding); the `llmredteam` harness points inward to measure it. RAG/document-injection depth still 🔴 |
| Eval/regression harness on real engagements | 🟡 | cloud bench ladder + **web agent bench** (`internal/webrange`) + **LLM red-team bench** (`internal/llmredteam`) — procedural populations with decoys, recall/precision vs answer key, all three agents |
| Chain of custody / audit trail | 🟡 | attestation exists; extend to per-action log |
| Live-AWS validation rung (CloudGoat deploy→sync→confirm) | 🟡 | `RunTier1Live` stub; needs AWS account |

---

## 7. Prioritized sequencing (maps to the tiered monetization)

**Shipped:**
- ✅ **AI pentester for web/API** (`internal/webagent`) — grounded exploitation, signed evidence, 5 classes. → Tier 2 "Attack".
- ✅ **LLM Red-Team module** (`internal/llmredteam`) — attacker + verifier + emulated bench. → Tier 1 "Guard".
- ✅ **Report generator + findings DB + lifecycle** (`internal/report`, `internal/findingstore`) — the sellable artifact + the retainer backbone.
- ✅ **Deployable service + packaging + load/auth benchmark** (`internal/server`, `internal/loadbench`, `docker/host`, release pipeline).

**Next (buildable in-tree, highest leverage first):**
1. **SCA / code-reachability triage** — closes the one Validation hole (does our app call the vulnerable dependency function?). Agentic triage over CodeQL/semgrep escalation. (§3)
2. **CI/CD gate trigger** — VCS webhook → scoped staging run → pass/fail. Opens the Shift-Left pillar. (§1)
3. **SARIF / Snyk / GHAS importers** — triage external scanner alerts through the grounding engine. (§3)
4. **LLM red-team depth** — live HTTP target adapter + RAG/vector-DB extraction probes + signed evidence (reuse `webagent.EvidenceBundle`). (§2)
5. **Web agent depth** — browser/DOM (Playwright tool), authenticated business-logic / BOLA/BFLA. (§1)

**Then (needs real infrastructure, not in-tree Go):**
6. **Continuous scheduler + delivery connectors** (cron/event trigger, auto-PR, Jira/Slack) — converts engine → retainer SaaS. → Tier 3 "Scale". (Platform §4, Service §3)
7. **Multi-tenant store + onboarding (OAuth/GitHub App) + billing + compliance workflow** (org-evidence connectors, continuous control monitoring, auditor portal). The Vanta/Drata surface. (§4, §5)
8. **Live-AWS validation rung + global safety/RoE hardening** before autonomous testing at customer scale. (§6)

> **Blunt summary:** the part that's genuinely hard — *grounded autonomous reasoning that separates real from noise and verifies its own claims* — is built and proven across **all three agent flavors** (cloud, web/api, LLM red-team), each with an anti-circularity bench, and now runs as a benchmarked service that emits a sellable report and tracks findings over time. What remains is **agent depth** (SCA-reachability, browser/DOM, RAG, business-logic), **delivery glue** (CI gate, importers, connectors), and the **SaaS/compliance platform** (multi-tenant, scheduling, onboarding, billing, control-monitoring) — which is an infrastructure project on top of a core that's hard to copy.

---

## 8. Maturity-model scorecard (Shift-Left / Continuous / Validation / Prioritization)

How we map against the modern VM maturity model. We are **deliberately strongest on
Validation + Prioritization** — the hard, defensible end — and lighter on Shift-Left
+ Continuous-Scanning, which the model itself calls the first line of defense and
"increasingly commoditized by AI."

| Pillar | Rating | Built | What's left |
|---|---|---|---|
| **1. Shift Left** | 🟡 ~5/10 | repo SAST (semgrep), secrets (gitleaks/trufflehog, corroborated), SCA (trivy/grype/osv), container (trivy/grype/dockle/hadolint), CodeQL/mobsfscan escalation | no shift-left **workflow** — CI/CD gate, VCS webhook, PR-block, IDE/pre-commit (§1, §7-next-2) |
| **2. Continuous Scanning** | 🟡 ~6/10 | 7 asset types, recon→fan-out, L1.5 enrichment, deployable benchmarked service, per-tool recall held to OSS baseline | no **scheduler** — cron / event / CI-triggered re-scan loop; no L3 portfolio re-scan (§4) |
| **3. Validation** *(is it running, reachable, exploitable?)* | 🟢 ~9/10 | the core thesis — web agent **proves exploitability** (payload→indicator→re-fire verify, signed PoC); cloud **computes reachability** (`cloudiam.Authorize` ∧ attack-path graph); `verification_status` ladder; anti-circularity benches prove validation isn't itself a hallucination | **code/SCA reachability** ("does our app *call* the vulnerable function?") — call-graph/taint triage over dependency findings (§3, §7-next-1) |
| **4. Prioritization** *(context → path to crown jewel)* | 🟢🟡 ~7/10 | cloud agent's job **is** "path to a crown jewel" (identity ∧ network ∧ resource-policy reachability, blast radius); threat-intel beyond CVSS (KEV/EPSS); surface_priority + exploitability hooks; compliance mapping | the asset/identity/network **graph** is cloud-deep but thinner for web/repo; no **cross-asset correlation** (web finding + cloud identity + network path as one chain) — the L3 portfolio layer (§3, §4) |

**Read:** tsengine is a **Validation-and-Prioritization engine**, not a shift-left or
continuous-scanning product — by design, since those pillars are commoditizing and
#3/#4 are the hard, copy-resistant part. The three honest knocks: (a) no CI/shift-left
workflow, (b) no continuous scheduler, (c) prioritization is cloud-deep but not
cross-asset, and SCA call-reachability is unbuilt. None are architectural dead-ends —
they're the §7 "next" list.
