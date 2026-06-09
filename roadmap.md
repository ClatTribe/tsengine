# tsengine Roadmap — toward an AI-Native Offensive Security & Triage Agency

> **Product thesis.** Sell an *autonomous, continuous adversarial loop*, not a once-a-year
> static PDF. Deploy AI agents that continuously hack staging/APIs/AI-models while an AI
> triage layer separates the real from the noise — and *proves* each finding before it alerts.
>
> **Where we are honest:** the engine's *analysis loop* is complete — find (scan + import) →
> **prove** (grounded agents + reachability) → **prioritize** (cross-asset correlation) →
> decide (CI gate) → package (report) → **emit** (SARIF export + signed finding/case webhook) →
> track (findings DB) → serve (API), across all three agent flavors with an anti-circularity
> bench each. The **outbound handoff** is now built (`internal/exporter` + `tsengine export`):
> the engine both *imports* other scanners and *emits* its proven findings into the systems
> customers already run (SARIF/code-scanning, SIEM/SOC, ticketing) — the loop is closed.
> What's left to **complete the functionality** is, in order: (1) a **replayable agent
> decision ledger** (the trust/transparency layer); (2) **agent depth** (browser/DOM,
> business-logic, RAG, live LLM-target); and (3) the **platform surface** (continuous
> scheduler, multi-tenant SaaS, onboarding, billing, compliance workflow) — an infra project.
> See §9 for how the handoff positions us vs a downstream AI-SOC.

Status legend: ✅ built · 🟡 partial · 🔴 missing. Items are tracked here; convert to PRs as picked up.

> **What's left at a glance** (prioritized, buildable in-tree first):
> 1. ✅ **SCA / code reachability triage** — closed the one Validation hole (`internal/reachability`: does our app *call* the vulnerable dep function, from an entrypoint, with a cited path?). Go-first; extend to other languages via new extractors. §3.
> 2. ✅ **CI/CD gate** — opened the Shift-Left pillar (`internal/gate` + `tsengine gate` + composite Action): pass/fail on proof + reachability, baseline + waivers, GitHub annotations. §1.
> 3. ✅ **SARIF / Snyk / GHAS importers** — `internal/importers` + `tsengine import`: a customer's existing scanner output flows through the grounding, reachability, and gate. §3.
> 4. ✅ **Cross-asset correlation** — `internal/correlate` + `tsengine correlate`: stitch findings across assets into one attack chain to a crown jewel (moves the Prioritization pillar 🟢🟡~7 → 🟢~8). §3/§4.
> 5. ✅ **Outbound handoff / export** — the completing piece (§9). `internal/exporter` + `tsengine export`: **SARIF export** (→ GitHub code-scanning / any SARIF consumer, proven findings inline on the PR), a **signed finding/case webhook** (→ SIEM/SOC/AI-SOC/ticketing, Bearer + HMAC-SHA256). The OUT mirror of the importers — the engine is now a finding *source*, not just a sink. §3/§9.
> 6. 🔴 **Replayable agent decision ledger** — persist + sign every agent step (prompt/tool-call/observation/decision) into a verifiable, replayable ledger (parity with an AI-SOC's "Investigation Ledger"). In-tree. §6.
> 7. **Live HTTP LLM-target adapter + RAG probes** — finishes the LLM red-team service. §2.
> 8. **Browser/DOM + business-logic (BOLA/BFLA)** — web agent depth. §1.
> 9. **Continuous scheduler + delivery connectors (PR/Jira/Slack)** — converts engine → retainer SaaS. §4.
> 10. **Multi-tenant store + onboarding + billing + compliance workflow** — the SaaS/Vanta surface; an *infra* project, not in-tree code. §4/§5.
>
> Items 5–8 are Go you can write + test in this repo today (5–6 are the highest-leverage "complete the loop" pieces); 9–10 need real infrastructure (DB, OAuth apps, a cluster).

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
- ✅ **SCA / code reachability** (`internal/reachability`) — real call graph from source (stdlib, no deps); answers "does our app actually *call* the vulnerable dependency function, from an entrypoint?" with a **cited call path**. Splits SCA noise into reachable / dead-code / unused. `tsengine reachability`. (Go-first; closes the Validation-pillar hole for dependency findings.)
- ✅ **CI/CD security gate** (`internal/gate`) — `tsengine gate`: policy over scan / web-exploit / SCA-reachability findings → pass/fail exit code. Gates on **proof** (verified exploit, reachable CVE) not raw CVSS; an unreachable critical dep CVE does **not** block. Baseline (fail on new only) + waivers; GitHub-annotation output; reusable composite Action + `docs/CI.md`. (Opens the Shift-Left pillar.)
- ✅ **Third-party scanner importers** (`internal/importers`) — `tsengine import`: SARIF 2.1.0 (CodeQL/semgrep/code-scanning), Snyk, GitHub Dependabot → `types.Scan` + `reachability.SCAFinding`. A customer's existing Snyk/CodeQL output flows through the grounding, reachability triage, gate, report, and findings DB.
- ✅ **Outbound handoff / export** (`internal/exporter`) — `tsengine export`: the OUT mirror of the importers. **SARIF 2.1.0 export** (`--format sarif`) so GitHub code-scanning / any SARIF consumer shows *proven* tsengine findings inline on the PR (`[verified]` prefix, `security-severity` + CWE `external/cwe/*` tags, file:line→region locations); a **signed finding/case webhook** (`--webhook`) that POSTs a normalized, MITRE-friendly event to a SIEM / SOC / AI-SOC / ticketing endpoint with optional Bearer auth + HMAC-SHA256 body signature (`X-TSEngine-Signature`). The engine is now a finding *source*, not just a sink. (§9)
- ✅ **Cross-asset correlation** (`internal/correlate`) — `tsengine correlate`: stitches findings ACROSS the 7 asset types into one attack chain (external entry → crown jewel) via a concrete shared identifier (leaked AWS key, ARN, host). The Prioritization "path to a crown jewel", applied across asset boundaries; grounded (no shared id → no chain).
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
| **CI/CD gatekeeping** (pass/fail gate on every push) | ✅ | `internal/gate` + `tsengine gate` — policy over scan/web-exploit/SCA-reachability findings; gates on PROOF (verified exploit, reachable CVE) not raw CVSS; baseline (fail on new only) + waivers; `--format github` annotations; reusable composite Action (`.github/actions/tsengine-gate`) + `docs/CI.md`. (VCS-webhook-triggered staging *runs* are the remaining slice — the gate consumes findings; the trigger is platform §4) |
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
| **Cross-asset correlation** (a finding HERE → a crown jewel THERE) | ✅ | `internal/correlate` + `tsengine correlate` — bridges findings across assets by a concrete shared identifier (leaked AWS key, ARN, host) into one chain (web SQLi leaks key → cloud IAM privesc to admin); grounded (no shared id → no chain). Richer linkers + live attack-path-graph feed are incremental |
| **Verified remediation** (the fix is proven to cut the path) | ✅ cloud | — |
| **Code/SCA reachability** ("does our app *call* the vulnerable function?") | ✅ Go | `internal/reachability` + `tsengine reachability` — builds a real call graph from source (stdlib, no deps), reports whether an app entrypoint reaches the vulnerable symbol, **cites the call path** (grounded); SCA triage splits findings into reachable / dead-code / unused. Go-first; other languages = new extractor (solver is language-agnostic) |
| Ingest other scanners' alerts (SARIF/Snyk/GHAS) to triage | ✅ | `internal/importers` + `tsengine import` — SARIF 2.1.0 (CodeQL/semgrep/code-scanning), Snyk test JSON, GitHub Dependabot alerts → `types.Scan` (report/findings/gate) and `reachability.SCAFinding` (reachability triage). A customer's existing Snyk/CodeQL output flows through the grounding + gate |
| **Outbound: SARIF *export*** (findings → code-scanning / any SARIF consumer) | ✅ | the OUT mirror of the importer — `tsengine export --format sarif` (`internal/exporter`); GitHub code-scanning shows *proven* tsengine findings inline on the PR (`[verified]` prefix, `security-severity` + CWE tags, file:line regions). In-tree (§9) |
| **Outbound: finding/case webhook + emitter** (→ SIEM / SOC / AI-SOC / ticketing) | ✅ | `tsengine export --webhook` POSTs a normalized, MITRE-friendly, **signed** (Bearer + HMAC-SHA256) finding/case event to a downstream endpoint — the tsengine→SOC handoff; turns tsengine into a finding *source* a downstream operate layer consumes (§9) |
| **Auto-generated Pull Requests** | 🔴 | GitHub App: open a PR with the verified fix (the write side of delivery) |
| **ChatOps verification** ("why is this a risk?" in Slack) | 🔴 | Slack/Teams bot over the finding + attack-path |

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
| **Replayable agent decision ledger** | 🔴 | persist + sign every agent step (prompt / tool-call / observation / decision) into a verifiable, replayable ledger — parity with an AI-SOC's "Investigation Ledger". The agents already keep an in-memory transcript; this writes it to a signed, queryable record. In-tree; the trust/transparency completeness piece (§9) |
| Chain of custody / audit trail | 🟡 | attestation + (above) ledger extend the per-action trail; per-action log over the whole engagement still to wire |
| Live-AWS validation rung (CloudGoat deploy→sync→confirm) | 🟡 | `RunTier1Live` stub; needs AWS account |

---

## 7. Prioritized sequencing (maps to the tiered monetization)

**Shipped:**
- ✅ **AI pentester for web/API** (`internal/webagent`) — grounded exploitation, signed evidence, 5 classes. → Tier 2 "Attack".
- ✅ **LLM Red-Team module** (`internal/llmredteam`) — attacker + verifier + emulated bench. → Tier 1 "Guard".
- ✅ **Report generator + findings DB + lifecycle** (`internal/report`, `internal/findingstore`) — the sellable artifact + the retainer backbone.
- ✅ **Deployable service + packaging + load/auth benchmark** (`internal/server`, `internal/loadbench`, `docker/host`, release pipeline).
- ✅ **SCA / code-reachability triage** (`internal/reachability`) — closes the Validation hole for dependency findings (call path cited; reachable/dead-code/unused).
- ✅ **CI/CD security gate** (`internal/gate` + `tsengine gate` + composite Action) — pass/fail on proof + reachability, baseline + waivers, GitHub annotations. Opens the Shift-Left pillar.

- ✅ **Third-party scanner importers** (`internal/importers` + `tsengine import`) — SARIF / Snyk / Dependabot → the engine; gate + reachability + report + findings DB consume them.
- ✅ **Outbound handoff: SARIF export + signed finding/case webhook** (`internal/exporter` + `tsengine export`) — the OUT mirror of the importers; emit proven findings into code-scanning (SARIF 2.1.0) and SIEM/SOC/ticketing (signed webhook). *The piece that completes the loop* (§9).

**Next (buildable in-tree, highest leverage first — completion before depth):**
1. **Replayable agent decision ledger** — sign + persist every agent step; AI-SOC "Investigation Ledger" parity (§9). (§6)
2. **LLM red-team depth** — live HTTP target adapter + RAG/vector-DB extraction probes + signed evidence (reuse `webagent.EvidenceBundle`). (§2)
3. **Web agent depth** — browser/DOM (Playwright tool), authenticated business-logic / BOLA/BFLA. (§1)
4. **Reachability beyond Go** — JS/TS + Python extractors over the same language-agnostic solver. (§3)
5. **Richer correlation linkers** — container image → cloud workload, more credential/identity kinds, feed the live cloud attack-path graph into the chain. (§3/§4)
6. **Auto-PR / Jira / Slack delivery + VCS-webhook trigger** — the write side of delivery (open a PR with the verified fix, file a ticket) and firing a scoped staging scan on push to feed the gate (the platform half of CI/CD). (§3/§4)

**Then (needs real infrastructure, not in-tree Go):**
8. **Continuous scheduler + delivery connectors** (cron/event trigger, auto-PR, Jira/Slack) — converts engine → retainer SaaS. → Tier 3 "Scale". (Platform §4, Service §3)
9. **Multi-tenant store + onboarding (OAuth/GitHub App) + billing + compliance workflow** (org-evidence connectors, continuous control monitoring, auditor portal). The Vanta/Drata surface. (§4, §5)
10. **Live-AWS validation rung + global safety/RoE hardening** before autonomous testing at customer scale. (§6)

> **Blunt summary:** the genuinely hard part — *grounded autonomous reasoning that separates real from noise and verifies its own claims* — is built and proven across all three agent flavors (cloud, web/api, LLM red-team), each with an anti-circularity bench; the engine now scans, imports, proves, reachability-triages, correlates cross-asset, gates CI, reports, tracks, serves, and **emits** (SARIF export + signed finding/case webhook). The outbound edge is closed — the engine both ingests other scanners' output and emits its own proven findings into the systems customers run, an integrable finding *source*. What remains to fully **complete the functionality** is the **agent decision ledger** (the trust/transparency layer; §9). After that it's **depth** (browser/DOM, RAG, more languages/linkers) and the **SaaS/compliance platform** (continuous scheduler, multi-tenant, onboarding, billing) — an infrastructure project on top of a core that's hard to copy.

---

## 8. Maturity-model scorecard (Shift-Left / Continuous / Validation / Prioritization)

How we map against the modern VM maturity model. We are **deliberately strongest on
Validation + Prioritization** — the hard, defensible end — and lighter on Shift-Left
+ Continuous-Scanning, which the model itself calls the first line of defense and
"increasingly commoditized by AI."

| Pillar | Rating | Built | What's left |
|---|---|---|---|
| **1. Shift Left** | 🟢🟡 ~7/10 | repo SAST (semgrep), secrets (gitleaks/trufflehog), SCA (trivy/grype/osv), container (trivy/grype/dockle/hadolint), CodeQL/mobsfscan escalation; **CI/CD pass-fail gate** (`tsengine gate` + composite Action) gating on proof + reachability, with baseline + waivers | VCS-webhook-triggered *staging run* (the gate consumes findings; the trigger is platform §4); IDE/pre-commit hook |
| **2. Continuous Scanning** | 🟡 ~6/10 | 7 asset types, recon→fan-out, L1.5 enrichment, deployable benchmarked service, per-tool recall held to OSS baseline | no **scheduler** — cron / event / CI-triggered re-scan loop; no L3 portfolio re-scan (§4) |
| **3. Validation** *(is it running, reachable, exploitable?)* | 🟢 ~9/10 | the core thesis — web agent **proves exploitability** (payload→indicator→re-fire verify, signed PoC); cloud **computes reachability** (`cloudiam.Authorize` ∧ attack-path graph); **SCA/code reachability** (`internal/reachability` — does the app call the vulnerable dep function, with a cited path); `verification_status` ladder; anti-circularity benches prove validation isn't itself a hallucination | SCA reachability is Go-first (other langs = new extractors); the runtime side is complete |
| **4. Prioritization** *(context → path to crown jewel)* | 🟢 ~8/10 | cloud agent's job **is** "path to a crown jewel" (identity ∧ network ∧ resource-policy reachability, blast radius); **cross-asset correlation** (`internal/correlate` — a web/repo finding bridges via a shared identifier to a cloud crown jewel, e.g. web SQLi leaks an AWS key → cloud IAM privesc to admin); threat-intel beyond CVSS (KEV/EPSS); surface_priority + exploitability hooks | richer bridge linkers (more identifier kinds, container→workload), and feeding the live cloud attack-path graph into the chain (today correlation links findings; deepening per-asset reachability is incremental) |

**Read:** tsengine is a **Validation-and-Prioritization engine** that now also gates
the SDLC (Shift-Left) — strongest exactly where the model says the durable value is.
Pillars #1/#3/#4 are built; SCA reachability, the CI gate, cross-asset correlation, and
the **outbound handoff** (SARIF export + signed finding/case webhook) all shipped. The
one remaining honest knock is **no continuous scheduler** (#2 — the platform project);
the outbound edge that used to be the highest-leverage completion gap is now closed
in-tree (`internal/exporter` + `tsengine export`; §9).

---

## 9. Completing the functionality — the outbound handoff (positioning vs an AI-SOC)

> Surfaced by comparing against a downstream AI-SOC platform (e.g. AiSOC). tsengine
> sits **left of deploy** (find → prove → prioritize → gate); an AI-SOC sits **right
> of deploy** (detect → triage → respond). They're complementary, and the clean seam
> is: **tsengine is a finding *source* that feeds the operate layer.**

The analysis loop is complete, and the **outbound edge is now built** (`internal/exporter`
+ `tsengine export`). The engine is no longer import-only: it both pulls SARIF/Snyk/GHAS
in (`tsengine import`) and pushes proven, prioritized findings out into the machine
systems a customer already runs. The OUT mirror that turns tsengine into an integrable
node:

| Completion piece | Status | Why it completes the loop |
|---|---|---|
| **SARIF export** (`tsengine export --format sarif`) | ✅ | the OUT mirror of the importer; GitHub code-scanning / any SARIF consumer shows *proven* tsengine findings inline on the PR (`[verified]` prefix, `security-severity` + CWE `external/cwe/*` tags, file:line→region locations) — makes the gate visible where developers already look |
| **Finding/case webhook + emitter** (`tsengine export --webhook`) | ✅ | POSTs a normalized, **signed** (Bearer + HMAC-SHA256 over the body, `X-TSEngine-Signature`) finding/case event to a downstream endpoint (SIEM / SOC / AI-SOC / ticketing) — the tsengine→operate handoff; severity ladder + status (verified/corroborated) + CWE/threat-intel/compliance ride in the payload so a consumer can open a case directly |
| **Replayable agent decision ledger** | 🔴 | persist + sign every agent step (prompt / tool-call / observation / decision) — parity with an AI-SOC's Investigation Ledger; the transparency/defensibility layer (§6) |
| **Auto-PR / Jira / Slack delivery** | 🔴 | the write side of delivery — open a PR with the verified fix, file a ticket, post the chain to ChatOps (§3/§4) |

**The combined picture:** with SARIF export + the webhook emitter (both shipped), a
customer wires tsengine as a *connector into* their SOC / code-scanning / ticketing —
proven, prioritized risk flows left→right so analysts work *confirmed exploitable paths
to crown jewels* instead of raw scanner noise. That handoff was one small in-tree build
(the mirror of the importers against an existing contract), **not** an infra project —
and it's what makes the engine *complete* as an interoperable product rather than a
standalone CLI. The remaining outbound items (agent ledger, auto-PR/Jira/Slack) deepen
the same edge. The platform surface (continuous scheduler, multi-tenant, onboarding,
billing — §4/§5) remains the separate infrastructure track.
