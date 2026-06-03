# tsengine Roadmap — toward an AI-Native Offensive Security & Triage Agency

> **Product thesis.** Sell an *autonomous, continuous adversarial loop*, not a once-a-year
> static PDF. Deploy AI agents that continuously hack staging/APIs/AI-models while an AI
> triage layer separates the real from the noise — and *proves* each finding before it alerts.
>
> **Where we are honest:** the engine today is the **hardest part** (grounded autonomous
> reasoning + verified remediation) but only **~1.5 of the 3 core services** and a fraction of
> the services-company surface. This roadmap is the gap, prioritized.

Status legend: ✅ built · 🟡 partial · 🔴 missing. Items are tracked here; convert to PRs as picked up.

---

## 0. What's built (the moat)

- ✅ **Detection across 7 asset types** — OSS-wrapped (nuclei, sqlmap, semgrep, trivy, prowler, …), L1 anchor + escalation + registry tiers (arch.md).
- ✅ **The cloud AI agent** (`internal/cloudagent`) — LLM brain + deterministic tools, **evidence-grounded** (can't record a finding the graph doesn't support), at **parity with the deterministic engine** on a 612-resource account.
- ✅ **Correct IAM reasoning** (`cloudiam.Authorize`) — identity ∧ boundary ∧ SCP ∧ resource-policy ∧ conditions; attack-path graph (`cloudgraph`); blast radius.
- ✅ **Verified remediation** (`cloudengine.GenerateRemediations`) — SCP/IAM-Deny/SG artifacts, self-checked via `cloudiam.Authorize`; `--export` to disk.
- ✅ **L1.5 enrichment** — FP filter, corroboration, confidence, threat-intel (KEV/EPSS), `compliance.map` (SOC2/PCI/HIPAA/CIS/NIST).
- ✅ **Signed evidence/attestation** (ed25519 over snapshot+findings+evidence).
- ✅ **Anti-overfit benchmark ladder** — in-distribution / held-out / llm-emulate / CloudGoat / large procedural dataset.

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

## 2. Service: Agentic / LLM Red Teaming (AI-Sec)  🔴

**Greenfield — zero current overlap.** This is the hottest 2026 wedge *and* the cheapest entry tier.

| Capability | Status | Gap |
|---|---|---|
| `llm_endpoint` / `ai_agent` asset type | 🔴 | new asset type + handler |
| **Indirect prompt-injection auditing** (untrusted-data → action) | 🔴 | poisoned-context corpus + a judge |
| **Multi-turn jailbreak orchestration** (PyRIT-style) | 🔴 | adversarial-prompt agent (reuse the agent loop; prompts are the "payloads") |
| **RAG / vector-DB / system-prompt leakage** | 🔴 | extraction probes + a deterministic leak-detector |
| **Agent goal-hijack / tool-misuse** | 🔴 | tool-abuse scenarios + grader |
| **Our own** agent-injection resilience (we read untrusted pages/logs) | 🔴 | same harness, pointed inward — closes a real self-risk |

**Build:** an `llmredteam` module — a multi-turn attacker agent vs the client's LLM, graded by a **deterministic verifier** (did PII/secret/system-prompt leak; did a forbidden tool fire). Same grounding principle: a "successful jailbreak" must be provable, not asserted.

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
| Multi-tenancy + RBAC + data isolation | 🔴 | engine is single-scan; tenants/clients/teams model |
| Durable **findings DB** + lifecycle (open→fixed→verified→closed) + SLA + ownership | 🔴 | L3 portfolio layer is "future"; needed for retainer model |
| **Continuous scheduling** (cron + event/CI-triggered) | 🔴 | the "continuous loop" the thesis sells |
| Integrations: Jira/Linear, Slack/Teams, GitHub/GitLab, SSO | 🔴 | delivery + ingest connectors |
| Customer **onboarding / connect** (read-only cloud role, GitHub App, OAuth) | 🔴 | how a client plugs in |
| Dashboards + posture trend + exec report | 🟡 | webappsec named; engine emits JSON |
| **Report generator** (branded VAPT PDF / SOC2 evidence pack) | 🔴 | the actual sellable deliverable |
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
| **Runtime guardrails for active web/api testing** (rate-limit, scope, do-no-harm) | 🔴 | needed before autonomous testing at scale |
| **Authorization / consent / RoE capture** (legal) | 🔴 | required to test client assets |
| **Agent-injection resilience** (prompt injection from scanned content) | 🔴 | the AgentLAB axis; also Service 2 pointed inward |
| Eval/regression harness on real engagements | 🟡 | bench ladder for cloud exists; extend to agents |
| Chain of custody / audit trail | 🟡 | attestation exists; extend to per-action log |
| Live-AWS validation rung (CloudGoat deploy→sync→confirm) | 🟡 | `RunTier1Live` stub; needs AWS account |

---

## 7. Prioritized sequencing (maps to the tiered monetization)

1. **Report generator + findings DB + lifecycle** — turns the engine's output into the *sellable artifact* and the retainer's backbone. (Platform §4)
2. **AI pentester for web/API** — extend the proven cloud agent pattern + sandboxed exploit-confirmation. → **Tier 2 "Attack"** ($5–12k/scan). (Service §1)
3. **LLM Red-Team module** — cheapest, hottest wedge; also fixes our own agent-resilience gap. → **Tier 1 "Guard"** ($990–1990/mo). (Service §2, §6)
4. **Continuous loop + CI trigger + multi-tenant + PR/ChatOps delivery** — converts "engine" into "retainer SaaS." → **Tier 3 "Scale"** ($50k+/yr). (Platform §4, Service §3)
5. **Compliance connectors + continuous control monitoring** — the SOC2 product's center of gravity (only after the above, unless compliance is the lead GTM). (§5)
6. **Live-AWS / safety hardening** — guardrails + injection resilience before autonomous testing at customer scale. (§6)

> **Blunt summary:** the part that's genuinely hard — *grounded autonomous reasoning that separates real from noise and verifies its own fixes* — is built and proven. What remains is mostly **breadth** (two new agent flavors: web/api + LLM red-team) and **product surface** (continuous, multi-tenant, delivery, reporting, compliance connectors) on top of a core that's hard to copy.
