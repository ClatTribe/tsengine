# Agentic Security Lifecycle for Small–Medium Non-Software Companies
### Goal: *"Run a secure organization"* — with an agent roster, not a security team

> **Third in a series.**
> 1. tsengine (CLAUDE.md) — the *software-company* lifecycle: **"build secure"** (SDLC).
> 2. `sec_lifecycle_non_software.md` — the *non-software org* lifecycle: **"run secure"**
>    (NIST CSF operational program, 51 control requirements).
> 3. **This document** — what (2) becomes for a **small-to-medium non-software company**
>    in an **agentic** world: the same NIST CSF skeleton, run by an **orchestrated roster
>    of AI agents supervised by one accountable human**, not a multi-role security team.

---

## 0. The problem this solves

`sec_lifecycle_non_software.md` is correct but **unreachable for an SMB**: it assumes a
CISO, an IAM lead, a DPO, a detection engineer, and a SOC. A 50–250-person dental group,
regional law firm, 3-factory manufacturer, or e-commerce retailer has **one IT generalist
(or an MSP) and zero security staff**. The barrier is *headcount*, not just budget.

The agentic shift removes that barrier. **The lifecycle does not change — the operating
model does.** The program's headcount requirement collapses into a roster of specialized
agents that run the controls continuously, supervised by a single human **on the loop**.

| | Classic program (the spec as written) | **Agentic SMB program (this doc)** |
|---|---|---|
| Who runs it | 7 phases × dedicated roles × 10+ vendors | One **orchestrator agent** + a **phase-agent roster** + 1 accountable human |
| Human posture | *in* the loop (operates controls) | *on* the loop (approves consequential actions) |
| Cadence | periodic (annual pentest, quarterly review) | **continuous / always-on** |
| Evidence | collected manually for audits | **auto-generated, signed, replayable** (the ledger) |
| Time-to-stand-up | 0–18 months | **days-to-weeks** (agents do the standing-up) |
| New risk introduced | — | **the agents themselves** → a new governance phase (§D) |

> **The non-negotiable enabling primitive.** Autonomy that touches identity, endpoints,
> and SaaS is only deployable if every agent action is **grounded** (acted on evidence, not
> assertion), **gated** (consequential actions pause for a human), and **recorded** in a
> **tamper-evident, replayable decision ledger**. Without that substrate (§B), an agentic
> security program is uninsurable and unauditable. *This is exactly tsengine's signed agent
> decision ledger.*

---

## 1. How to read this document

* **Keywords** follow RFC 2119: **MUST**, **SHOULD**, **MAY**.
* **Requirement prefixes**: `OM` operating model · `TS` trust substrate (grounding /
  HITL / ledger / kill-switch) · `AGT` the phase-agent roster · `WRD` agent governance
  (the warden) · `CON` connectors · `ACC` accountability.
* **Autonomy tiers** (§3) classify every agent action by blast radius and decide whether
  it runs alone, on policy, or only with human sign-off.
* **Maturity** (§7): **Crawl → Walk → Run**, recast for an SMB measuring rollout in weeks.
* **Crosswalk** (§9) maps every agent back to the `sec_lifecycle_non_software.md`
  requirement IDs and NIST CSF 2.0, so this is an *operating model for that spec*, not a
  replacement of it.

---

## 2. Reference architecture

```
                       ┌───────────────────────────────────────┐
   Owner / fractional  │  SINGLE PANE                          │
   vCISO  ────────────►│  approvals · weekly report · kill-switch│
   (ON the loop)       └───────────────────┬───────────────────┘
                                           │  HITL gates (Tier-2/3)
                       ┌───────────────────▼───────────────────┐
                       │      vCISO ORCHESTRATOR AGENT          │
                       │  schedules · supervises · reports      │
                       └─┬───┬───┬───┬───┬───┬───┬──────────────┘
            A-GOV ◄──────┘   │   │   │   │   │   └──────► A-ASR  (tsengine: validation)
            A-IDN ◄──────────┘   │   │   │   └──────────► A-RCV
            A-PRO ◄──────────────┘   │   └──────────────► A-RSP
            A-DET ◄──────────────────┘
                       A-WARDEN ◄── governs every agent above (AI-BOM, identity, injection)
                                           │
                       ┌───────────────────▼───────────────────┐
                       │   SIGNED DECISION LEDGER (§B)          │  ← trust + audit substrate
                       │   every step: thought→tool→obs→decision│
                       │   ed25519, tamper-evident, replayable   │
                       └───────────────────┬───────────────────┘
                                           │
   Connectors (§E): IdP · M365/Workspace · EDR/MDM · domains/cloud · SaaS APIs · backup
```

Principles:
* **One orchestrator, many narrow agents.** Each phase-agent has a *small, scoped* tool
  catalog (the tsengine ≤12-tool discipline applies — narrow agents are more accurate and
  more auditable than one omnipotent agent).
* **One human, one pane.** The SMB supervises a fleet through a single approval+report
  surface; they never operate a console.
* **One ledger.** Every agent writes to the same signed decision ledger — the single
  source of truth for "what did our security do, and prove it."

---

## 3. Autonomy tiers — the escalation boundary (the core design decision)

An SMB human cannot review everything but **MUST** own anything destructive, legal, or
business-breaking. Every agent action is classified:

| Tier | Blast radius | Examples | Default authority |
|---|---|---|---|
| **T0 — Observe** | read-only, no change | discovery, EASM, log triage, validation, restore *verification* | **Always autonomous** |
| **T1 — Reversible / low** | easily undone | fix config drift, enrich/dedup an alert, schedule a patch, send a phishing sim, generate an access-review packet | **Autonomous + logged + human notified** |
| **T2 — Consequential** | reversible with effort, can disrupt | disable an account, isolate a host, revoke a token, block an IP/domain, force a password reset | **HITL approval** *or* a **pre-authorized break-glass policy with post-hoc review** |
| **T3 — Irreversible / legal / business-critical** | cannot be undone or carries legal weight | regulatory breach notification, customer comms, mass deletion, invoking DR, **accepting risk**, policy approval | **Human decision only** — the agent *prepares*, the human *signs* |

* **OM/TS requirement:** every agent action **MUST** be tagged with its tier at execution
  time and recorded in the ledger; **T2 MUST** be gate-able per-org; **T3 MUST NOT** be
  executable by any agent without a recorded human approval (see ACC-1).

---

## 4. Operating-model requirements (OM)

| ID | Requirement | Acceptance / evidence | Tier-gate |
|---|---|---|---|
| **OM-1** | A single **orchestrator agent MUST** schedule, supervise, and health-check the phase-agent roster, and produce a periodic plain-language owner report. | Orchestrator config; weekly report artifact; roster health dashboard. | — |
| **OM-2** | Each phase-agent **MUST** operate with a **scoped, least-privilege identity** and a **bounded tool catalog**; no shared god-mode credential. | Per-agent identity + permission manifest (feeds the AI-BOM, WRD-1). | — |
| **OM-3** | The human supervisor **MUST** have a **single pane** exposing pending approvals, the weekly report, and a **global kill-switch** that halts all agent action. | Kill-switch test record; approval-queue screenshot. | — |
| **OM-4** | The roster **MUST** run **continuously**, not on a manual cadence; "annual"/"quarterly" controls from the base spec **MUST** be re-expressed as always-on agent loops. | Continuous-run logs; cadence-to-loop mapping. | T0/T1 |
| **OM-5** | The program **SHOULD** degrade safely: if an agent, model, or connector is unavailable, it **MUST** fail closed for T2/T3 actions and alert, never act blind. | Failure-mode test; alert evidence. | — |

---

## 5. The phase-agent roster (AGT)

Each agent maps 1:1 to a `sec_lifecycle_non_software.md` phase. Format: **mandate ·
autonomous (T0/T1) · escalates (T2/T3)**.

| Agent | Maps to | Mandate & autonomous actions | Escalates (human gate) |
|---|---|---|---|
| **A-GOV** — vCISO orchestrator | GOV | Maintain risk register, draft/keep policies current from templates, map compliance obligations, schedule roster, write owner report | Risk acceptance, budget, **policy sign-off** (T3) |
| **A-IDN** — asset & exposure | IDN | Continuous discovery of devices/SaaS/identities/data/vendors; **EASM** of domains/IPs/cloud; flag shadow & exposed assets *(tsengine EASM slice)* | "Shadow SaaS holds customer PII — sanction or remove?" (T2) |
| **A-PRO** — hardening & identity | PRO | Remediate config drift, enforce MFA/SSO posture, generate access-review packets, schedule patches, harden M365/Workspace, run phishing sims & training | Disable account, ops-risky change, grant exception (T2) |
| **A-DET** — SOC | DET | 24×7 log ingest, alert triage, correlation, enrichment, dedup, threat-intel, T1 auto-response | Confirmed incident handoff, any destructive containment (T2) |
| **A-RSP** — incident response | RSP | Run playbooks, contain clear-cut incidents (isolate host, revoke token), collect forensics, **draft** breach comms & notifications | **Regulatory notification decision**, customer comms, major containment (T2/T3) |
| **A-RCV** — continuity | RCV | Verify backup immutability, run scheduled **restore drills**, validate RTO/RPO, flag gaps | Invoke DR, recovery decisions during a live incident (T3) |
| **A-ASR** — red-team / validation | ASR | Continuous external pentest, phishing-sim program, control-monitoring, **package signed audit evidence** *(tsengine agents + ledger)* | None destructive (grounded/read-only); surfaces validated risk |

**Roster requirements:**

| ID | Requirement | Acceptance / evidence |
|---|---|---|
| **AGT-1** | Every phase of the base spec **MUST** have a named owning agent (or an explicit "human-only, no agent" decision). | Phase→agent (or →human) coverage map. |
| **AGT-2** | Each agent **MUST** classify every action by autonomy tier (§3) and record it (TS-3). | Ledger entries carry a tier field. |
| **AGT-3** | **A-RSP MUST** treat all breach-notification and external-comms actions as **T3** — drafted by the agent, decided and signed by a human. | Ledger shows human approval before any notification send. |
| **AGT-4** | **A-ASR MUST** be **grounded and non-destructive** — it validates (proves exploitable / reachable) and reports; it **MUST NOT** hold T2/T3 authority. | A-ASR identity has no write/destructive scopes. |
| **AGT-5** | Agents **SHOULD** be narrow (small tool catalogs) rather than one omni-agent, for accuracy and auditability. | Per-agent catalog size recorded; no agent with the full toolset. |

---

## 6. The new phase — Agent Governance / the Warden (WRD)

> **Agentic world adds a phase the classic spec never needed.** The SMB now also deploys
> *business* agents (support bot, AP-automation, scheduling), and the *security* agents
> above hold the keys to the kingdom. Both are new, high-value attack surface. An agent
> that can disable accounts is a weapon if hijacked.

| ID | Requirement | Acceptance / evidence |
|---|---|---|
| **WRD-1** | The org **MUST** maintain an **AI-BOM**: an inventory of every agent (security and business), its model/provider, its tools, its permissions, and its data access. | AI-BOM register, reconciled with OM-2 manifests. |
| **WRD-2** | Each agent **MUST** have a **distinct, scoped, revocable identity** (non-human identity governed like an employee — JML, least privilege, periodic review). | Agent-identity inventory; review attestations; instant-revoke test. |
| **WRD-3** | Agents that ingest untrusted content (web pages, emails, documents, tickets) **MUST** be protected against **prompt injection / instruction-hijack** — they act on grounded tool output, never on instructions embedded in scanned/ingested data. | Injection test-suite results; the grounding boundary (TS-1) covers agent inputs. |
| **WRD-4** | The warden **MUST** monitor agent behavior for anomaly (privilege creep, off-pattern tool use, escalation attempts) and **MUST** be able to **quarantine a misbehaving agent** without halting the rest. | Per-agent anomaly alerts; single-agent quarantine test. |
| **WRD-5** | Agent decision ledgers (§B) **MUST** themselves be audited by the warden for gaps/tamper, closing the reflexive loop. | Ledger-integrity report; gap/tamper alerts. |
| **WRD-6** | Business (non-security) agents **SHOULD** be brought under the same identity, least-privilege, and ledger discipline as the security agents. | Coverage of business agents in AI-BOM + ledger. |

---

## 7. Trust substrate — grounding, HITL, ledger, kill-switch (TS)

The three primitives that make autonomy deployable for a wary SMB:

| ID | Requirement | Acceptance / evidence |
|---|---|---|
| **TS-1** | No agent **MUST** take a **T1+ action** on an **ungrounded** claim — every action cites the deterministic tool evidence that justifies it (the anti-hallucination guard). | Ledger decisions carry evidence refs; ungrounded-action test is rejected. |
| **TS-2** | **T2 actions MUST** pause for human approval **or** run under a documented, pre-authorized break-glass policy with mandatory post-hoc review; **T3 MUST** always require recorded human sign-off (ACC-1). | Approval records; break-glass policy + review log. |
| **TS-3** | Every agent step **MUST** be written to a **signed (ed25519), tamper-evident, replayable decision ledger** — thought, tool, args, observation, decision, tier, and (for T2/T3) the approver. | Ledger verifies; replay reconstructs the trail; tamper breaks verification. *(tsengine `ledger verify`/`replay`.)* |
| **TS-4** | The ledger **MUST** be the **audit/insurance evidence of record** — exportable to an auditor or cyber-insurer as proof of what the autonomous program did over a period. | Quarterly signed evidence export; auditor/insurer acceptance. |
| **TS-5** | A **global kill-switch (OM-3)** and **per-agent quarantine (WRD-4)** **MUST** exist and be tested. | Kill-switch + quarantine drill records. |

---

## 8. Accountability — what stays human (ACC)

> Autonomy is delegated; **accountability is not.**

| ID | Requirement | Acceptance / evidence |
|---|---|---|
| **ACC-1** | A **named human** (owner, officer, or fractional vCISO) **MUST** remain legally accountable for risk acceptance, regulatory/breach decisions, and policy approval; agents **prepare**, the human **decides and signs**. | Named-accountable-officer record; T3 sign-off trail. |
| **ACC-2** | The org **MUST** document the **autonomy policy**: which tiers each agent may execute, the break-glass conditions, and the review cadence — approved by the accountable human. | Approved autonomy policy doc. |
| **ACC-3** | Vendor/agent failure **MUST NOT** transfer accountability; the org **SHOULD** retain the right and means to operate critical controls manually (degraded mode). | Manual-fallback runbook for top controls. |

---

## 9. Maturity & rollout (Crawl → Walk → Run)

Agents do the standing-up, so an SMB measures this in **weeks**, not the base spec's 18 months.

**Crawl — Day 1 to Week 1 (connect & see).**
Connect IdP + M365/Workspace + endpoints + domains. Stand up **A-IDN** (asset/EASM),
**A-PRO** baseline (MFA gaps, risky OAuth, config drift), **A-DET** (log triage), the
**ledger**, the **kill-switch**, and the **autonomy policy** (ACC-2). Human approves all
T2 manually (no break-glass yet).
*Outcome: you can see your estate, your exposure, and your gaps within days — signed.*

**Walk — Weeks 2–6 (validate & respond).**
Add **A-ASR** (continuous validation + signed evidence), **A-RSP** playbooks (T2 still
gated), **A-RCV** restore drills, **A-WARDEN** (AI-BOM + agent identity), and phishing
sims. Introduce **break-glass policies** for a few well-understood T2 actions.
*Outcome: the program proves itself continuously and can contain clear-cut incidents.*

**Run — ongoing (optimize & widen).**
Broaden break-glass coverage where the ledger shows the agent is reliable, bring **business
agents** under the warden (WRD-6), feed the signed evidence into a SOC 2 / insurance cycle
(TS-4), and tune autonomy tiers from ledger data.
*Outcome: an always-on, self-evidencing security program supervised by one human.*

---

## 10. Honest limits & agentic-specific risks

* **Accountability is non-delegable** (ACC-1) — agents recommend; a human signs the legal calls.
* **Over-autonomy is itself the risk.** An agent that can disable accounts/isolate hosts is
  a high-value target and a single point of failure → scoped identity (OM-2/WRD-2), tier
  gates (§3), the ledger (TS-3), and the kill-switch (TS-5) are the controls *on the controls*.
* **Agents hallucinate** → grounding is mandatory (TS-1); never act on an unproven claim.
* **The agents are new attack surface** (prompt injection, model/tool supply chain) → the
  warden phase (§6) exists for exactly this and has no pre-agentic equivalent.
* **Trust is earned via transparency** — the SMB lets vendor agents touch everything only
  because the signed, replayable ledger lets them (and their auditor/insurer) verify it.

---

## 11. Crosswalk & where tsengine fits

| This doc | `sec_lifecycle_non_software.md` | NIST CSF 2.0 | tsengine today |
|---|---|---|---|
| A-GOV (OM-1) | GOV-1…8 | GOVERN | — |
| A-IDN | IDN-1…6 | IDENTIFY (esp. ID.AM, ID.SC) | ✅ **EASM/exposure validation** (`domain`/`ip`/`cloud`) |
| A-PRO | PRO-1…13 | PROTECT | ➖ configures bought tools |
| A-DET | DET-1…6 | DETECT | ➖ feeds the AI-SOC (finding source) |
| A-RSP | RSP-1…6 | RESPOND | ➖ consumes findings |
| A-RCV | RCV-1…5 | RECOVER | — |
| A-ASR | ASR-1…6 | cross-cutting validation | ✅ **grounded validation agents** (web/cloud/LLM) |
| WRD (warden) | *(new — agentic only)* | GV.OV / PR.AA extended to agents | ◐ the **agent identity + injection-resistance** discipline |
| TS (ledger) | acceptance/evidence at control level | GV.OV / audit | ✅ **the signed, replayable decision ledger** (PR #69) |

> **tsengine's role in the agentic SMB program is specific and durable:** the **A-ASR +
> A-IDN agents** (grounded validation, EASM) and — more importantly — the **decision-ledger
> trust substrate (TS)** that *every* agent in the roster writes to. It is the
> validation-and-evidence backbone an "agentic MSSP" would **buy rather than build**, because
> grounding + signed replay is exactly what makes an autonomous security program trustworthy
> enough to deploy.

---

### One-line summary

> For an SMB in an agentic world, the run-secure lifecycle keeps the same NIST CSF skeleton
> but swaps the operating model from *"a security team running a program across 10 vendors"*
> to *"an orchestrated agent roster + one accountable human + a signed decision ledger"* —
> and grows one new reflexive phase, **securing the agents themselves.** What makes it
> deployable (and insurable) is precisely the **grounded, tier-gated, signed, replayable
> decision ledger** — the primitive tsengine already ships.

---
---

# Part II — Commercialization: the India compliance-first wedge

> Part I is the full lifecycle (the *what*). Part II is *how it goes to market for an
> Indian SMB* — which **agent leads, what records the platform owns, what it integrates
> with, and how the customer + channel actually use it.** The lifecycle is unchanged; the
> **sequencing and packaging** are inverted for India.

## 12. Why compliance leads in India (the wedge inversion)

In Part I, the governance/compliance agent (A-GOV) is **P3** — model-heavy, commoditizing,
lowest *code* moat. **For the Indian SMB market it is the *wedge product*** — because the
moat here was never the agent's code; it's the **channel, the system-of-record, the
DPDP-specific mappings, and the accumulated evidence data**. India's structure forces this:

| India factor | Consequence for packaging |
|---|---|
| **DPDP Act** (2023; rules rolling out ~2025–26; penalties up to ₹250 cr) | Broad, fresh **compliance** demand across every SMB handling personal data — no "Vanta-of-DPDP" incumbent yet |
| **Export SOC 2 / ISO 27001 demand** | India's IT-services/SaaS/BPO base *must* certify to sell to US/EU (the Sprinto/Scrut-proven wedge) |
| **Cheap local security labor** | The autonomous-SOC *cost* pitch is muted → lead with compliance, not SOC |
| **GST/Tally e-filing culture** | SMBs already *pay for compliance SaaS* — compliance is the natural budget unlock |
| **The CA / consultant / Zoho-Tally channel** | Distribution flows through accountants & SIs, not US-style MSSPs |

**Sequencing:** lead with **compliance evidence** (A-GOV + A-IDN + A-ASR) → expand to
**light hardening** (A-PRO: MFA/posture, gap-remediation) → only later **security
operation** (A-DET/A-RSP) and the **warden** (WRD). Compliance unlocks the budget; security
operation is the retention/expansion layer.

> **The moat inversion to internalize:** the wedge agent (compliance content) is *cheap to
> build and commoditizing* — that's fine. The defensibility is in the **system-of-record
> (§15), the India-specific integrations (§16), the CA/MSP channel, and the operational
> evidence data** — none of which a better model or a US incumbent reproduces cheaply.

## 13. The two workflows (customer + channel)

Because India distribution is channel-led, there are **two** users: the **SMB end-customer**
and the **CA/MSP/consultant partner** who delivers and resells.

### 13a. SMB customer workflow (compliance-first)

| # | Stage | User does | Agents do | 🟢 Value-add | 🛡️ Moat |
|---|---|---|---|---|---|
| 0 | **Trigger** | A customer asks for SOC 2 / a DPDP deadline / an RBI mandate lands | — | Demand is *pulled* by a forcing function | Channel referral (CA/auditor) |
| 1 | **Connect** | OAuth-connects M365/Google/Zoho, cloud, HRMS, endpoint | A-IDN discovers assets + **where personal/regulated data lives** (RoPA) | Weeks of consultant discovery → minutes | Integration treadmill (esp. India stack §16) |
| 2 | **Assess** | Reads a plain-language gap report vs DPDP/SOC2/ISO | Compliance-mapping agent maps systems→controls; A-ASR **validates** real gaps | Proven gaps, not a checklist; readable by a founder | Grounding kernel + control-mapping corpus |
| 3 | **Generate** | Approves auto-drafted policies | Policy-generation agent drafts from templates mapped to controls | Policy pack in hours, not a ₹-lakh consultant engagement | System-of-record (policy register) |
| 4 | **Remediate** | Approves the fix batch (T2-gated) | Gap-remediation agent applies MFA/access/config fixes | Real risk reduction, not compliance theater | Permission-to-act + ledger |
| 5 | **Evidence (continuous)** | Nothing — it runs | Evidence-collection agent pulls **signed, continuous** evidence | Compliance becomes a *byproduct of operation* | **Signed evidence ledger = system-of-record lock-in** |
| 6 | **Audit / questionnaire** | Clicks "export evidence pack"; forwards questionnaires | Audit-liaison agent assembles the pack + **auto-answers security questionnaires** | The pre-audit screenshot scramble disappears | Switching = re-papering compliance |
| 7 | **Expand** | Turns on security ops + brings own AI agents under the warden | A-PRO/A-DET/A-RSP + A-WARDEN | Security as retention on the compliance wedge | Operational data flywheel |

### 13b. Channel-partner workflow (CA / MSP / consultant)

| # | Stage | Partner does | Platform does |
|---|---|---|---|
| P0 | **Onboard** | Joins the partner program (white-label, revenue-share) | Provisions a **multi-tenant partner console** |
| P1 | **Add clients** | Adds their SMB book as tenants | Per-tenant agent rosters spin up |
| P2 | **Oversee** | Reviews agent-generated posture **across all clients** in one pane | Cross-tenant dashboard + exceptions queue |
| P3 | **Deliver & upsell** | White-labels reports; sells DPDP→SOC2→security-ops upgrades | Branded evidence packs; tier upgrades |
| P4 | **Earn** | Recurring margin per client | Billing + revenue-share + the partner owns the relationship |

> The partner is a **first-class user**. The console's **cross-tenant oversight + white-label
> + revenue-share** is what wins the India channel — and the channel is the distribution moat.

## 14. The agentic layer — the "Compliance Co-pilot"

The India wedge is delivered by **specializations of the Part I roster**, packaged as a
Compliance Co-pilot. Most compliance work is **T0/T1** (read + draft) — only remediation is
**T2-gated** — so it is *safe to deploy early* and *cheap to run* (the cost-to-serve unlock
for tiny ACVs).

| Co-pilot agent | Part I roster | Does | Tier |
|---|---|---|---|
| **Compliance-mapping** | A-GOV | Maps systems/data → DPDP / SOC 2 / ISO 27001 / RBI / CERT-In controls; tracks control state | T0 |
| **Data-discovery & RoPA** | A-IDN | Discovers personal/regulated data, flows, owners; builds the DPDP Record of Processing | T0 |
| **Evidence-collection** | A-ASR / A-IDN | Continuously pulls **signed** evidence from connected systems | T0 |
| **Policy-generation** | A-GOV | Drafts + version-controls policies mapped to controls | T1 |
| **Gap-remediation** | A-PRO | Proposes + (gated) applies fixes: MFA, access, config, posture | **T2** |
| **Audit-liaison / questionnaire** | A-ASR / A-GOV | Packages auditor evidence; **auto-answers security questionnaires** from the system-of-record | T1 |

| ID | Requirement | Acceptance / evidence |
|---|---|---|
| **CMP-1** | Compliance work **MUST** be **grounded** — a control is "met" only when backed by collected evidence, never asserted by the model (the anti-theater guard). | Each control state cites evidence in the ledger. |
| **CMP-2** | The co-pilot **MUST** support DPDP + SOC 2 + ISO 27001 day one; RBI / CERT-In / HIPAA-India as fast-follow. | Framework coverage matrix; control libraries. |
| **CMP-3** | Gap-remediation **MUST** be **T2-gated** (human approves any change to live systems); everything else may run T0/T1. | Ledger shows approver on every remediation. |
| **CMP-4** | Security-questionnaire answers **MUST** be generated **from the system-of-record (§15)**, not free-form, so every answer is evidence-backed. | Answer→evidence linkage in the export. |

## 15. System of records (the lock-in)

The platform's defensibility is becoming the **authoritative system-of-record** for the
SMB's compliance + security state. Once you hold these, switching = re-papering compliance
and re-earning trust. **These records ARE the moat.**

| # | Record | What it holds | Why it locks in |
|---|---|---|---|
| **SOR-1** | **Control-state registry** | Live met/gap/exception state per control, per framework | The single source of audit truth |
| **SOR-2** | **Signed evidence ledger** | Continuous, tamper-evident evidence + every agent action *(extends tsengine's ledger)* | The audit + insurance artifact of record |
| **SOR-3** | **Asset & data inventory / RoPA** | What data, where, flows, owners (DPDP Record of Processing) | Rebuilding it elsewhere is a project |
| **SOR-4** | **Policy register** | Versioned policies + staff attestations | Re-papering = months |
| **SOR-5** | **Vendor / third-party register** | TPRM tiers, DPAs, assessments | The supplier compliance graph |
| **SOR-6** | **Access & identity register** | Who-has-access + review attestations | Continuous, not point-in-time |
| **SOR-7** | **Incident & breach register** | Incidents, CERT-In reports, notifications | The legal record |
| **SOR-8** | **Audit & assessment history** | Past audits, findings, remediation, certificates | The track record |

| ID | Requirement | Acceptance / evidence |
|---|---|---|
| **SOR-A** | Every record **MUST** be **continuously updated** by the agents (living, not a periodic snapshot). | Freshness timestamps; change log. |
| **SOR-B** | Records **MUST** be **exportable as a signed pack** (auditor/insurer/regulator consumable) — portable evidence, but the *living* copy is the stickiness. | Signed export verifies (ledger scheme). |
| **SOR-C** | The system-of-record **MUST** be **multi-tenant** with strict per-tenant isolation (channel partners hold many clients). | Tenant-isolation test; partner-console scoping. |

## 16. Tools & integrations needed

Integrations are the moat-treadmill — and the **India-specific connectors are a defensible
local advantage a US incumbent won't prioritize.** Grouped by purpose:

| Group | Integrations | Note |
|---|---|---|
| **Identity & productivity** | M365 (Graph), Google Workspace (Admin SDK), **Zoho One / Zoho Directory**, Okta/Entra/JumpCloud | Zoho is a *huge* India SMB suite — a local edge |
| **Cloud & infra** | AWS / GCP / Azure (read-only config), DigitalOcean | Posture + data-location for RoPA |
| **Endpoint** | **Seqrite / Quick Heal**, CrowdStrike/SentinelOne/Defender, Intune/Jamf | Seqrite dominates India SMB endpoint |
| **HR / people (India)** | **Keka, Darwinbox, GreytHR, Zoho People** | Drives access reviews + joiner/mover/leaver evidence — India-native HRMS |
| **Finance / ops (India)** | **Tally, Zoho Books, GST portal** | Asset/data context + the SMB's real system of record |
| **Code / dev (for IT-SaaS ICP)** | GitHub / GitLab, CI | **tsengine plugs in here** via the SARIF/webhook/ledger seam |
| **DPDP-specific** | Consent-management, data-flow mapping, **Data-Subject-Request (DSR) handling** | The DPDP operational layer — net-new, defensible |
| **HITL / comms** | Slack, Teams, email, **WhatsApp Business** | WhatsApp is the India SMB approval/notification channel |
| **Audit & compliance handoff** | Auditor portal, security-questionnaire automation, **the CA/MSP partner console** | The channel surface |
| **Backup & resilience** | Veeam, Datto, native cloud / M365 backup | RCV evidence |
| **Regulatory reporting** | **CERT-In incident submission**, RBI reporting formats | Sector forcing functions |
| **Trust substrate** | The **signed evidence ledger / SOR store** *(tsengine kernel)* | The system-of-record spine (§15) |

| ID | Requirement | Acceptance / evidence |
|---|---|---|
| **INT-1** | Connectors **MUST** be **least-privilege + OAuth**, scoped read-only by default; write scopes only for T2 remediation. | Per-connector scope manifest (feeds the AI-BOM, WRD-1). |
| **INT-2** | The platform **MUST** ship the **India stack** (Zoho, Tally, Keka/GreytHR, Seqrite, GST, WhatsApp, DPDP/DSR, CERT-In) — these are the local moat, not afterthoughts. | India-connector coverage in the catalog. |
| **INT-3** | Each connector **MUST** map its pulled data to **control evidence (SOR-2) and the data inventory (SOR-3)**, not just store raw output. | Evidence-mapping per connector. |

## 17. India build sequence

**Phase 1 — Wedge (DPDP-readiness co-pilot).** Compliance-mapping + RoPA + policy-gen +
evidence-collection over M365/Google/Zoho/cloud/HRMS; the signed system-of-record; the
**CA/MSP partner console**. Sell DPDP-readiness to cloud-native export/regulated SMBs through
CA firms. *Outcome: signed compliance posture in days; channel live.*

**Phase 2 — Expand (SOC 2 / ISO + remediation).** Add SOC 2 / ISO 27001 control libraries,
**gap-remediation (A-PRO, T2-gated)**, and **security-questionnaire automation**. *Outcome:
the wedge becomes a renewable compliance platform; security value begins.*

**Phase 3 — Operate (security retention layer).** Light A-DET/A-RSP, the **warden** for the
SMB's own AI agents, and **tsengine validation** wired via the SARIF/webhook/ledger seam.
*Outcome: security operation as the retention moat on top of the compliance wedge.*

## 18. Master matrix — workflow × agent × system-of-record × integrations

The single cross-mapping of all four dimensions. Rows are the customer workflow (§13a);
the columns tie each stage to the agent that runs it (§14), the autonomy tier (§3), the
record it makes the platform own (§15), and the integrations it needs (§16). **India-native
integrations are bolded — the defensible local edge.**

| # | Workflow stage | Agent (agentic layer) | Tier | System-of-record written | Tools / integrations |
|---|---|---|---|---|---|
| 0 | **Trigger** (SOC2 ask / DPDP deadline / RBI) | Orchestrator (intake) | — | — | CA/auditor referral; partner console |
| 1 | **Connect** | Data-discovery & RoPA (A-IDN) | T0 | SOR-3 data inventory/RoPA · SOR-6 access | M365/Google/**Zoho**, AWS/GCP/Azure, **Keka/GreytHR/Darwinbox**, **Seqrite**, **Tally/Zoho Books/GST** |
| 2 | **Assess** | Compliance-mapping + validation (A-GOV + A-ASR) | T0 | SOR-1 control-state · SOR-2 evidence ledger | DPDP/SOC2/ISO/RBI/CERT-In control libraries; **tsengine grounding** |
| 3 | **Generate** policies | Policy-generation (A-GOV) | T1 | SOR-4 policy register | policy template corpus; e-sign/attestation |
| 4 | **Remediate** gaps | Gap-remediation (A-PRO) | **T2** *(gated)* | SOR-1 control-state · SOR-2 ledger · SOR-6 access | IdP write (MFA/access), M365/Workspace config, endpoint config |
| 5 | **Evidence** (continuous) | Evidence-collection (A-ASR/A-IDN) | T0 | SOR-2 signed evidence ledger · SOR-1 | all connectors (continuous pull) → signed ledger |
| 6 | **Audit / questionnaire** | Audit-liaison / questionnaire (A-ASR/A-GOV) | T1 | SOR-2 signed export · SOR-8 audit history · SOR-5 vendor register | auditor portal, questionnaire automation, **CA/MSP console**, signed export |
| 7 | **Expand** (security ops + warden) | A-PRO/A-DET/A-RSP + A-WARDEN | T1→T2 | SOR-7 incident/breach register · SOR-2 | SIEM/logs, GitHub/CI (**tsengine seam**), **WhatsApp/Slack** HITL, **CERT-In** reporting, AI-BOM |

### 18a. Agent-centric reference (the Compliance Co-pilot)

| Agent | Solves | Tier | Writes to | Key integrations |
|---|---|---|---|---|
| **Compliance-mapping** (A-GOV) | systems/data → control state | T0 | SOR-1, SOR-2 | control libraries (DPDP/SOC2/ISO/RBI), tsengine grounding |
| **Data-discovery & RoPA** (A-IDN) | where personal/regulated data lives | T0 | SOR-3, SOR-6 | M365/Google/Zoho, cloud, HRMS, Tally/GST |
| **Evidence-collection** (A-ASR/A-IDN) | continuous signed proof | T0 | SOR-2, SOR-1 | all connectors → ledger |
| **Policy-generation** (A-GOV) | policies mapped to controls | T1 | SOR-4 | template corpus, e-sign |
| **Gap-remediation** (A-PRO) | close real gaps (MFA/access/config) | **T2** | SOR-1, SOR-2, SOR-6 | IdP/M365/endpoint write APIs |
| **Audit-liaison / questionnaire** (A-ASR/A-GOV) | auditor pack + auto-answer questionnaires | T1 | SOR-2, SOR-5, SOR-8 | auditor portal, questionnaire automation, partner console |

### 18b. Channel layer (CA / MSP partner — the distribution)

| Partner stage | What it touches | System-of-record | Integration |
|---|---|---|---|
| **Onboard** | multi-tenant provisioning | SOR-C tenant isolation | partner program / billing |
| **Add clients** | per-tenant rosters | all SOR (per tenant) | OAuth connect per client |
| **Oversee** | cross-tenant posture | SOR-1 across tenants | cross-tenant dashboard |
| **Deliver / upsell** | white-label packs | SOR-2 signed exports | branded reporting, revenue-share |

**How to read it:** the **workflow** (rows) is what the customer experiences; the **agentic
layer** is who does it; the **system-of-record** is what the platform *owns* as a result —
the lock-in; the **integrations** are the moat-treadmill, with the India-native stack the
defensible local edge. Autonomy tiers show that nearly everything is **T0/T1** (read/draft —
safe + cheap at SMB ACV); only **remediation is T2-gated** (human approves live-system changes).

---

### Part II one-liner

> In India, **lead with compliance, deliver through the CA/MSP channel, and win on the
> system-of-record.** The compliance co-pilot (cheap, model-driven) is the wedge; the
> **signed evidence ledger + the India-native integrations (Zoho/Tally/Keka/Seqrite/GST/
> WhatsApp/DPDP/CERT-In) + the multi-tenant partner console + the accumulated evidence data**
> are the moat. DPDP is the entry; SOC 2/ISO is the expansion; security operation is the
> retention — all unified on one signed system-of-record.
