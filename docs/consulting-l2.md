# The L2 agentic layer through the consulting lens

tsengine is sold two ways, and the **only** difference is *who employs the human-in-the-loop*:

| Model | Who runs the product | Who does the HITL judgment | ICP |
|---|---|---|---|
| **MSP / consulting** (channel) | a partner firm / consultancy | **their** expert | the MSP's clients |
| **Managed** (we are the consultant) | us | **our hired** expert, on the customer's behalf | a founder who needs security + compliance |
| **Internal** (self-serve) | the tenant | the tenant's own team | teams with in-house security |

This is the **practitioner layer** (`pkg/platform.Tenant.ServiceModel` ∈ internal/msp/managed; §18.5). One
engine, three employers of the same human.

## What the human-in-the-loop actually does (the top layer)

The automatable bulk — detection, triage, fix-drafting, evidence collection — is the engine's job. The
**top layer** is the judgment a consultant is *paid for* and that can't be automated (§18.4):

- **Independent audit attestation** (legal) — a named external auditor renders each control verdict.
- **Seasoned vCISO judgment** — a named owner accepts/mitigates/transfers/avoids each residual risk.
- **Named accountability on a pentest** — a named human signs the VAPT report.
- **vCISO program** — a named owner publishes the policy set.

Each is *required-by-API* (400 without the named human) and ledger-signed. The engine **proposes/seeds**;
the human **decides/attests/signs/publishes**.

## So what should the L2 agentic layer be?

**The L2 agent is the junior consultant; the HITL human is the senior consultant.** The agent does the
grounded prep — investigate, prove, prioritize, draft — and hands a *decision-ready package* to the named
human. Three design rules follow:

1. **Agent proposes, named human disposes.** Every L2 agent's output must land on the right human's desk
   as a *proposal*, never an executed decision. The agent never accepts risk, never signs, never attests.
   (This is the §10 grounding rule applied to the consulting acts.)
2. **Bring-your-own-brain.** In the MSP model the partner runs the product, so the *agent's model* should
   be the partner's/tenant's choice — their own LLM key (cloud or local). The per-tenant LLM config
   (`Settings → LLM`) drives the agents; the operator-global model is the fallback.
3. **Route to the right desk.** In the managed/MSP models the human is *cross-tenant* (one expert, many
   clients) — the operator desk (`/operator`, the practitioner queue) aggregates every pending HITL item
   across the expert's book, gated by the roster (`matchPractitioner`), so isolation holds.

### What Claude Code / competitors do that maps here
- **Tool-use loop + plan + verify + human-approval gate** (Claude Code): we have the loop (`internal/l2`,
  the agents), the verify (deterministic predicate / `cloudiam.Authorize`), and the approval gate (HITL
  desk). The consulting framing just makes the *approver* a named, accountable role.
- **"AI pentester / AI SOC analyst / AI GRC analyst"** (competitors): each is an agent that produces a
  *consultant deliverable* and routes the *judgment* to a human. We have the deliverables (VAPT report,
  compliance report, attack-path analysis); the gap was wiring the agent's *reasoning* into the human's
  decision queue.

## The gaps (audited) and their status

| Gap | Status |
|---|---|
| Per-tenant LLM config was **dormant** (built, never used at runtime) | **Fixed** — `Deps.resolveAgentLLM` + `cloudengine.ClientFor`; the tenant's own model now drives cloud-investigate + the pentest D-agent (PR #511). MSP "bring your own brain." |
| L2 agent output did **not feed** the vCISO risk desk | **Fixed** — a cloud investigation now auto-proposes candidate Risks (`seedRisks`) for the named vCISO to judge (PR #511). Agent proposes → human disposes. |
| The open-ended XBOW agent wasn't wired into the product | **Fixed earlier** — `LLMSpecGen` D-agent behind ModeDeep (PR #509). |
| The cloud agent was CLI-only | **Fixed earlier** — `/cloud-engineer` + `/v1/cloud/investigate` (PR #510). |
| L2 agents not testable on a local model | **Fixed earlier** — OpenAI-compat adapters; qwen3:8b drives them (PRs #504–506). |
| **Remaining**: agent **provenance** in the VAPT deliverable (agent-proposed vs deterministic), and the cross-tenant operator-console *frontend* surface | open follow-ons |

## The end-to-end consulting loop (today)

```
L2 agent (tenant's own model)  →  proven findings (stored, grounded)
        ↓                                   ↓
  candidate Risks  ───────────────→  the named vCISO's desk  (accept/mitigate/transfer/avoid)
  VAPT report      ───────────────→  the named human signs   (pentest sign-off)
  control posture  ───────────────→  the named external auditor attests
                                            ↓
              MSP expert (operator desk, cross-tenant)  OR  our hired expert  OR  the tenant's own team
                                            ↓
                                   ledger-signed, named, accountable
```

The agent does the grounded prep with whichever brain the tenant/MSP brings; its discoveries land on a
named human's desk for the judgment that is the consulting value. The three GTM models are one engine
differing only in who that named human works for.
