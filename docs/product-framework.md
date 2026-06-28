# Product Framework — the four‑layer stack + the service‑model flag

> Strategic reference (2026‑06‑29). The product = a **deterministic security + compliance
> substrate**, two **AI teammates** (a defender and an attacker) that reason over / against it,
> and a **named‑human top layer** whose *employer* is a single config flag. This doc captures the
> proposition, the competitive positioning, the pricing architecture, and an honest evaluation of
> what's built vs. what needs to change.

---

## 1. The stack

```
┌─ HITL TOP LAYER — a NAMED HUMAN (judgment the AI cannot/should not do) ─────┐
│   vCISO risk acceptance · independent audit attestation (legal) ·           │
│   named pentest sign‑off · policy publication        (§18.4, ledger‑signed) │
│   ▲ the engine PROPOSES/SEEDS; the human DISPOSES (required‑by‑API)          │
├──────────────────────────────────────────────────────────────────────────── ┤
│   AI SECURITY ENGINEER (defense)    │    AI PENTESTER (attack)               │  L2 — LLM, propose/seed
├──────────────────────────────────────────────────────────────────────────── ┤
│   DETERMINISTIC SUBSTRATE  "L1.7"   (no LLM — the security + compliance      │  deterministic, free/base
│   posture both AI products reason over)                                      │
│     L1   detect      OSS scanners + cloudengine.Assess + operate + sspm      │
│     L1.5 enrich      threat‑intel (KEV/EPSS) · compliance map · FP · exploit │
│     L1.7 correlate   crossdetect: unified issues · cross‑surface attack      │
│                      paths · data‑tier priority  (the "estate view")         │
└──────────────────────────────────────────────────────────────────────────── ┘
```

**Layer ownership is fixed; only ONE thing varies across go‑to‑markets — who employs the HITL human:**

`Tenant.ServiceModel ∈ { internal · msp · managed }` (§18.5)

| Model | HITL human is… | ICP | We sell |
|---|---|---|---|
| **self‑serve** (`internal`) | the customer's own team | has a security person | the **product** |
| **MSP / channel** (`msp`) | a **partner firm's** expert (cross‑tenant operator desk) | consultancies / MSPs | the **platform** |
| **managed** (`managed`) | **our** hired expert, on the customer's behalf | a **founder** who wants it handled | the **outcome** |

One engine, one codebase, three GTMs. The "product vs. service" decision is a field value for us; for a competitor it's a different company.

---

## 2. The two AI products

- **AI Security Engineer (defense)** — an LLM agent that reasons *over* the L1.7 substrate (the whole connected estate: cloud + code + SaaS unified issues + attack paths + compliance posture) → prioritize, chain across surfaces, explain, remediate, write the compliance narrative. It only ever **proposes/seeds**; deterministic predicates + the human dispose. Target architecture: a **generalist over the `crossdetect` graph** that **delegates cloud‑depth to the cloud specialist** (`cloudagent` over `cloudgraph`). The cloud agent's graph reasoning is unchanged — the engineer is a generalist promoted *above* it (altitude split, not a substrate swap).

- **AI Pentester (attack)** — active, consent/RoE‑gated exploitation → exploitation‑proven VAPT (`pentest` ModeDeep). "Agent proposes a benign demonstration, a deterministic predicate disposes" → zero LLM false positives by construction.

**Grounding moat:** neither AI ever asserts a finding it can't back. Defense rides on the deterministic substrate; attack rides on a predicate that must hold over benign probes. Competitors' "AI" is mostly triage/summary bolt‑ons; ours is reasoning over a signed, deterministic substrate.

---

## 3. Compliance is deterministic L1.5 (by design)

Compliance framework analysis is **not passed through any LLM**. The `compliance.map` hook (L1.5, hook #7) is a pure embedded `CWE → control` crosswalk; `grc` (coverage, evidence pack, OSCAL, reports) is also 0‑LLM. An auditor needs reproducible, signable mappings — not LLM guesses (§10). The AI Security Engineer **consumes** the compliance annotation (to prioritize remediation toward the gap and write the narrative); it never **produces** the mapping.

---

## 4. Competitive positioning

The differentiation is the *shape*: two AI personas over a deterministic, correlated, compliance‑aware substrate spanning cloud + code + SaaS + identity, with an **accountable, portable HITL layer**.

| | Aikido | Vanta / Sprinto | **Us** |
|---|---|---|---|
| Deterministic security posture | ✅ scans | ❌ evidence only | ✅ L1→L1.7 + cross‑surface correlation |
| Compliance mapping | thin | ✅ their core | ✅ deterministic, signed |
| AI defense reasoning | triage/noise‑cut | ❌ | ✅ AI Security Engineer |
| AI offensive (pentest) | ✅ (Doyensec‑measured) | ❌ | ✅ AI Pentester (unproven at scale) |
| **HITL as accountable, signed layer** | ❌ | partial (external auditor marketplace) | ✅ risk/attest/sign‑off/policy |
| **Can run as a managed service** | ❌ | ❌ | ✅ `managed` |
| **Can run as an MSP channel** | resell only | resell only | ✅ `msp` |

- **vs Aikido** — a scanner + AI pentest a human *operates*. No accountable HITL layer, no practitioner‑of‑record, no operator desk → Aikido can be your security team's *tool*, never your security *team*. We can be the tool **or** the team.
- **vs Vanta/Sprinto** — compliance‑evidence automation with **no security detection or exploitation**; you still bring a pentester, a vCISO, and an auditor. We unify posture + security engineering + pentest + the vCISO/attestation HITL — and that HITL can be **ours**.

The thesis: the repeatable bulk of SMB security/compliance **consulting** is (1) run scanners → L1.7, (2) triage/prioritize → AI Engineer, (3) pentest → AI Pentester, (4) judgment/attestation/sign‑off → the HITL human. We **automate 1–3** and make **4 efficient + accountable + portable**. A consultancy uses us to 10× delivery (MSP), or we *become* the consultancy (managed) — capturing the consulting margin, not just the software seat.

**Positioning line:**
> *A free deterministic security + compliance substrate, an AI Security Engineer that defends it, an AI Pentester that attacks it to prove what's real — and a named human accountable for every judgment call. Run it yourself, have us run it, or run it for your clients.*

---

## 5. Pricing architecture

The pricing boundary follows the **marginal‑cost** boundary (LLM tokens), and the code already enforces it (`pkg/platform/plan.go`):

| Tier | Adds | Gate (already enforced) |
|---|---|---|
| **Free** | Deterministic substrate only (L1→L1.7, no LLM) — costs ~nothing to run | `AIEnabled:false` |
| **Growth** | + **AI Security Engineer** (defense, continuous) | `AIEnabled:true` |
| **Enterprise / add‑on** | + **AI Pentester** (attack, episodic VAPT) | `AutonomousPentest:true` (separate flag) |

- **BYO‑LLM lever** (§18.5): a tenant supplying their own sealed key uses AI on any plan (the LLM cost is theirs) — decouples AI *access* from AI *cost*. Currently un‑marketed.
- **Managed** is the founder‑ICP *outcome* sale (per‑engagement), not just an Enterprise feature.

---

## 6. Evaluation — what's built vs. the gaps (2026‑06‑29 audit)

**Verdict: the framework is ~80% already implemented in the backend. The real work is one wiring gap + making the IA and pricing *express* the architecture they already implement.**

### 6.1 Backend

| Area | State | Gap |
|---|---|---|
| Deterministic substrate (L1→L1.7) | ✅ built (`crossdetect` correlation, unified issues, attack paths) | — |
| **Substrate → Engineer wiring** | ❌ **the largest gap** | Neither LLM agent reasons over `crossdetect`. `l2` translate gets a **flat finding list** (per‑asset); `cloudagent` reasons only over the **cloud graph**. No generalist over the unified estate. |
| **Auto‑invoke after scan** | ❌ gap | A platform scan (`orchestrator.Run` → `runner.RescanTenant`) **stops at L1.5**; the AI engineer is on‑demand only (`/v1/l2/translate`, `/v1/cloud/investigate`). |
| HITL top layer (risk/audit/sign‑off/program) | ✅ built, ledger‑signed | — |
| ServiceModel + operator desk (act‑on‑behalf, isolation) | ✅ fully wired, isolation‑proof | — |
| Entitlements (`AIEnabled`, `AutonomousPentest`) | ✅ enforced | Two minor issues: `/v1/l2/translate` doesn't re‑check `AIEnabled` (Free could spend operator LLM budget); `autonomousPentestEntitled` is a string‑match codepath that drifts from `Entitlements()`. |
| Compliance determinism | ✅ 0‑LLM (hook + grc) | — |

**Ranked backend changes:**
1. **[Highest]** Feed `crossdetect` unified issues + attack paths into the AI engineer's context (extend `l2.Deps`, render issues‑first in the prompt, populate from `crossdetect` in `translate.go`). *Makes "engineer reasons over the estate" real.*
2. **[High]** Promote L2 to a generalist that **delegates cloud‑depth to `cloudagent`** as a tool (altitude split).
3. **[High]** **Auto‑invoke** the engineer after a scan in `runner.RescanTenant`, gated on `AIEnabled` (or own‑key) + not‑halted; store the prioritized/chained output.
4. **[Med]** Let `cloudagent` run over stored cloud findings, not only a posted inventory.
5. **[Med]** Close the `/v1/l2/translate` entitlement bypass (apply the `AIEnabled` gate).
6. **[Low]** Collapse the `autonomousPentestEntitled` drift onto `platform.Entitlements()`.

### 6.2 Post‑login IA (`frontend/app/(app)/`)

All the pages exist and are polished; the **IA flattens the two AI personas into a generic "Security" bucket**, so the product's thesis is invisible in the nav.

- The **AI Security Engineer is split + partly orphaned**: `/cloud-engineer` is the only nav‑visible "AI engineer" and it's **cloud‑only**; `/brief` (literally "the AI security engineer's translated report") is **off‑nav**. There is no single cross‑estate "AI Security Engineer" home.
- The **AI Pentester** (`/pentest`) is well‑built but mis‑grouped inside "Security" — attack vs. defense is lost.
- **ServiceModel is nearly invisible to the tenant**: configured in a buried Settings panel; `CapacityBadge` shows *who acted* (good) but there's **no standing "your security engineer / service model" indicator** — yet that's the whole value prop for a `managed`/`msp` customer.

**Ranked IA changes:** (1) restructure the sidebar into the 4 layers — **Posture / AI Security Engineer / AI Pentester / Governance(HITL)**; (2) add a standing service‑model + practitioner‑of‑record indicator in the shell; (3) build an "AI Security Engineer" landing page (cross‑estate, not cloud‑only); (4) un‑orphan `/brief`, `/posture`, `/findings`; (5) consolidate the HITL story (Inbox + Reviews + Governance + sign‑off read as one layer).

### 6.3 Marketing + pricing (`frontend/app/(marketing)/`)

The persona pages (`/ai-security-engineer`, `/ai-pentest`), GTM pages (`/managed`, `/partners`), and competitor pages (`/vs-aikido`, `/vs-vanta`, …) all **exist and are strong**. The gap is that the **pricing page flattens it back into a feature list** and the GTM models are demoted.

**Ranked marketing changes:** (1) restructure `pricing/page.tsx` around **personas + substrate** (Free = "your deterministic posture" → Growth = "+ AI Security Engineer" → Enterprise = "+ AI Pentester"), with a one‑line layer diagram; (2) market the **BYO‑LLM** lever (+ FAQ); (3) make the **three GTM models a first‑class "Service models / how to buy" surface** (promote `/managed` + `/partners` out of the Company menu; give Managed its own per‑engagement pricing card); (4) sharpen the structural HITL wedge on `/vs-aikido` ("a product a human operates — no accountable HITL layer, so it can't be a managed service"); (5) cross‑link the persona pages from pricing + homepage so the two‑persona story is the backbone.

---

## 7. One‑paragraph summary

The architecture is right and mostly built: a deterministic, signed security + compliance substrate; two AI teammates (a defender that reasons over it, an attacker that proves what's exploitable); a named‑human top layer for judgment/legal/accountability; and a single `ServiceModel` flag that turns the same product into self‑serve, MSP channel, or managed service. The **one substantive engineering gap** is that the AI Security Engineer doesn't yet reason over the `crossdetect` estate graph (and isn't auto‑invoked after a scan) — fixing that makes the "whole‑estate AI security engineer" claim true. Everything else is **expression**: the post‑login IA and the pricing page need to *show* the four‑layer / two‑persona / three‑GTM structure the backend already enforces.
