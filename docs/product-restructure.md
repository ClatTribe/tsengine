# Product restructure — outcome-led IA + agentic AI consoles

**Status:** design (campaign `c39c917a`, 2026-06-29). Implemented in phases, one PR per phase.
**Why:** the post-login app is grouped by our *architecture* (Posture / AI Engineer / AI Pentester /
Governance), not by what the user is trying to *do*. A founder logs in asking two questions — **"am I
secure?"** and **"am I audit-ready?"** — so the spine must be **Security** and **Compliance**, with the
two AI personas as agents that operate *on* those outcomes. This doc is the agreed target + the phase plan.

---

## 1. The goal (unchanged framework, sharper expression)

The four-layer / two-persona / three-GTM model ([docs/product-framework.md](product-framework.md)) is right;
this restructure makes the **app and marketing express it**:

1. **L1.7 substrate (opt-in scanning engine)** — deterministic + corpus-driven detect → L1.5 enrich (dedup,
   threat-intel, compliance map, reachability) → L1.7 correlation (unified issues, attack paths, data-tier).
   Produces the **Security** output (issues/findings/incidents/attack-paths/posture) AND the **Compliance**
   output (control mapping + reachability + evidence). This is the "pre-AI" product.
2. **AI Security Engineer (enabled)** — reasons over the substrate, digs deeper on demand, decides what to
   fix, **writes the fix**.
3. **AI Pentester** — exploitation-proven VAPT; a **separate, lighter image** (exploit/browser/OAST tools,
   different from the scan image).
4. **HITL / Governance** — the named-human decisions (risk accept, attest, sign-off, publish).

ServiceModel (self_serve / msp / managed) is who employs the HITL human — unchanged.

---

## 2. THE key UX decision: agentic ACTION flows, not a chat box

The AI personas are **NOT a blank chat console**. They are **one-click agentic actions** — buttons that
trigger an agent and return a grounded result (the Aikido "AutoFix button" + Microsoft Security Copilot
"promptbook" pattern, not the Wiz "learn a query language" trap). Rationale:

- The ICP is a non-security founder — a blank prompt is intimidating and they don't know what to ask.
- Seeded one-click actions ("Triage everything", "Auto-fix the criticals", "Investigate this", "Generate
  evidence", "Am I SOC 2-ready?") are discoverable, fast, and map to real backend agents we already have.
- Grounding (§10) is easier to keep: each action runs a bounded agent over real findings, never free-form.

So every AI surface is a set of **action cards**, each: a clear label, what it does, a button → a running
state → an inline grounded result (and, where it mutates, it routes through the HITL gate).

---

## 3. The target post-login IA (what we ship)

```
Overview            Dashboard · Inbox (pending agent actions awaiting you)

SECURITY            Issues · Findings · Incidents · Attack paths ·
  (substrate out)   External exposure · Coverage · Asset posture · SaaS & identity

COMPLIANCE          Compliance (frameworks + controls) · Reports & evidence
  (substrate out)

✦ AI SECURITY       ONE console of agentic actions over the whole estate:
  ENGINEER            Triage & prioritize · Auto-fix the criticals · Investigate an issue ·
  (premium)           Cloud deep-dive · Plain-English brief · Compliance narrative
                      (folds today's /brief + /cloud-engineer)

✦ AI PENTESTER      Scope → launch → exploitation-proven report (autonomous, XBOW/NodeZero model)
  (premium)

GOVERNANCE (HITL)   Risks · Audits · Program · Expert reviews

WORKSPACE           Assets · Your security team · Activity · Settings
```

- **Marketing leads with the two AI personas** (the premium differentiator); **the app leads with the two
  outcomes** (Security/Compliance, what every plan gets) + the AI consoles as the power layer. No conflict —
  that's the free-substrate / paid-AI split already in `plan.go`.
- **Auto-fix is everywhere a finding lives** (Security/Issues/Inbox), not only in the engineer console — the
  agentic flow meets the user at the finding.

---

## 4. Phases (one PR per phase; each verified + shipped)

| Phase | Scope | Layer | Risk |
|---|---|---|---|
| **P1 — Outcome-led nav** | Sidebar `NAV_GROUPS` → Overview / **Security** / **Compliance** / AI Security Engineer / AI Pentester / Governance / Workspace. Dashboard hero reframed around the two outcomes. | frontend | low |
| **P2 — AI Security Engineer agentic console** | New `/engineer` console of action cards (Triage · Brief · Cloud deep-dive · Compliance narrative), each triggering an existing agent endpoint (translate / cloud-investigate). Folds `/brief` + `/cloud-engineer`. NOT a chat. | frontend + light API | med |
| **P3 — Auto-fix agentic flow on findings** | "AI Fix" button on an issue/finding → `remediate.Propose` (AI remediation) → generated fix (PR/config/runbook) → HITL gate → Inbox. The Aikido-AutoFix parity + the explicit "auto-fix button". | frontend + API wiring | med |
| **P4 — Two-image backend split** | `docker/sandbox` (scan tools, current) + new `docker/pentest-sandbox` (exploit/browser/OAST). Runtime image selection by mode (`TSENGINE_PENTEST_SANDBOX_IMAGE`); pentest driver uses the pentest image. | backend / infra | med |
| **P5 — AI Pentester console reframe** | Polish `/pentest` into the explicit scope→launch→report console (close already after #740); frame as the autonomous-pentest surface. | frontend | low |
| **P6 — Marketing expresses it** | Homepage / product / pricing / nav lead with Security + Compliance outcomes + the two agentic AI consoles (auto-fix, launch-and-prove) + the substrate-vs-AI split. | frontend | low |

**Invariants (every phase):** engine detection logic untouched (§18.2 inv.1); grounding §10 (agentic
actions run bounded agents over real findings, never fabricate); ship via PR (main protected); frontend
verified with `npx tsc --noEmit` (never `next build` while dev running); backend with `go build ./... &&
go test` the affected packages; agent live quality still gated on a frontier LLM (qwen3:8b is the floor).

---

## 5. Competitor grounding (why this shape wins)

- **Aikido** — one clean unified dashboard, "fix and get back to building"; AutoFix is a *button on a
  finding*. Built for the people who fix. → our Security tab + per-finding Auto-fix.
- **Wiz** — powerful graph but a complex query language; cautionary tale — don't make the user learn a DSL.
- **Vanta / Drata / Sprinto** — framework-centric compliance, no real detection. → our Compliance tab off
  the same substrate is the wedge (we own both outcomes).
- **Microsoft Security Copilot** — chat **+ promptbooks** (grouped, one-click agent workflows) **+ agents**
  (autonomous, trigger-driven). "Prompts for ad-hoc, agents for structured." → our agentic action cards.
- **CrowdStrike Charlotte AI / Dropzone** — conversational agentic SOC analyst. → the engineer console.
- **XBOW / Horizon3 NodeZero** — autonomous pentest: scope → launch → proof-backed report (not chat). → the
  AI Pentester console + the separate pentest image.
