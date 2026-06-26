# Product-menu × agent audit (the consulting lens)

For each product-menu surface: is an agent solving the customer problem, is it wired correctly, and does
it serve the ICP (founder needing security + compliance; MSP/managed expert owning the HITL judgment)?

## The map

| Route | Customer problem | Backend | Agent or deterministic | Status |
|---|---|---|---|---|
| `/dashboard` | one-page status | findings/incidents/posture/issues | deterministic (crossdetect, grc.Posture) | wired |
| `/inbox` | fixes needing approval | /v1/approvals | deterministic + HITL (hitl.Desk) | wired |
| `/issues` | noise-reduced issues | /v1/issues | deterministic (crossdetect.UnifiedIssues) | wired |
| `/findings` | raw findings | /v1/findings | deterministic | wired |
| **`/brief`** | **plain-English consultant report** | **POST /v1/l2/translate** | **LLM agent (l2.Agent.Run)** | **wired (#518/#519)** |
| **`/pentest`** | **autonomous exploitation** | **POST /v1/pentest/{id}/run** | **LLM agent (ModeDeep D-agent) + deterministic (passive/active)** | **wired (#509)** |
| **`/cloud-engineer`** | **cloud attack paths** | **POST /v1/cloud/investigate** | **LLM agent (cloudagent.Investigate)** | **wired (#510)** |
| `/attack-paths` | cross-surface chains | /v1/attack-paths | deterministic (crossdetect.Correlate) | wired |
| `/osint` | external exposure | /v1/osint(/scan) | deterministic (osint.Assess + CT) | wired |
| `/incidents` | detections + status | /v1/incidents | deterministic (detect.Reconcile) | wired |
| `/compliance` | audit-readiness | /v1/posture, /report | deterministic (grc.Posture/Report) | wired |
| `/risks` | vCISO judgment | /v1/risks(+decision) | deterministic seed (grc.CandidateRisks) + **HITL** | wired (agent→vCISO #511) |
| `/audits` | external attestation | /v1/audits(+attest) | deterministic seed + **HITL** | wired |
| `/program` | policies | /v1/program(+publish/ack) | deterministic + **HITL** | wired |
| `/reports` | deliverables | /v1/compliance/.../report | deterministic (grc.Report) | wired |
| `/assets`,`/saas-apps`,`/reviews`,`/activity` | ops surfaces | various GET | deterministic | wired |

## The four questions, answered

1. **Enough agents wired correctly?** Yes for the core. The three open-ended-reasoning problems each have a
   correctly-wired, LLM-gated agent: translate (`/brief`), exploit (`/pentest` ModeDeep), cloud attack-paths
   (`/cloud-engineer`). Every other surface is *correctly deterministic* (§10 grounding — correlation,
   dedup, control-mapping, OSINT, detection don't need an LLM and must not hallucinate). The HITL desks
   (risks/audits/program) take the agent's grounded proposals and route them to the named human.

2. **Is the XBOW agent (ModeDeep) working as supposed?** Yes. The run path is correctly gated and
   degrades gracefully — no silent-nothing path:
   - entitlement gate (plan) → consent gate (`RoE.ActiveAuthorized` + a live `Prober`) → LLM resolution
     (`resolveAgentLLM`, tenant's own model first) → **deterministic predicate validation** (`DemoFromSpec`).
   - With an LLM: the D-agent proposes specs for ANY class (open-ended). Without: the deterministic
     `HeuristicSpecGen`. **Either way the model can never upgrade a finding by itself** — `DemoFromSpec`
     re-validates with the benign predicate library. qwen3:8b verified it proposes a valid open-redirect
     DemoSpec; the standalone webagent drives the loop + sends real probes.

3. **Is the harness correct + working?** Yes. `go test ./internal/l2 ./internal/pentest ./internal/webagent
   ./internal/cloudagent ./internal/llmredteam` all green — the loop, token budget, context compaction, the
   ≤12-tool cap, and the tool catalog are unit-tested. Five CI-safe live tests (skip without LLM_BASE_URL)
   drive each agent against a real model.

4. **Does each agent work + serve the ICP?** All five verified on a local qwen3:8b (see
   [docs/testing-l2-agents.md](testing-l2-agents.md)). Structured-tool agents (cloud, D-agent) prove
   end-to-end on an 8B model; open-ended exploitation (webagent) drives the loop but needs a bigger
   model/budget to land a proof.

## Per-asset agent coverage (the asset-type lens)

| Asset | L2 agent | Status |
|---|---|---|
| web_application / api | webagent (XBOW) + ModeDeep D-agent + **apiauthz discovery** | ✓ (#509, #525) |
| cloud_account | cloudagent | ✓ (#510) |
| repository | **AI autofix** (LLM code patch) + the L2 Lead translator | ✓ (#523/#524) |
| container_image / ip_address / domain / mobile_application | L1 detection + the L2 Lead translator (`/brief`) | deterministic-detection assets; the generic translator + autofix cover them (a dedicated deep agent is low-value here) |

Cross-cutting agents: the L2 Lead translator (`/brief`, all assets), the vCISO compliance-remediation
agent (all frameworks), AI autofix (any code finding).

## Enhancement gaps — status

These were *optional LLM lifts* on deterministic surfaces; the top ones are now built:

1. ✅ **Compliance remediation guidance** (most ICP-aligned) — built (#521/#522): the vCISO "how do I fix CC7.2?".
2. ✅ **AI autofix** — built (#523/#524): LLM code patch for a finding (Snyk/Aikido/Copilot parity).
3. ✅ **API BOLA/BFLA discovery** — built (#525): LLM proposes authz tests, the deterministic validator confirms.
4. Issue-triage narrative — partly covered by `/brief` (lower value).
5. Incident root-cause narrative — the A-RSP future slice (CLAUDE.md notes it).
6. Dashboard attack-narrative card — nice-to-have.

All built agents are grounded-by-construction (cite findings/controls/operations) and ride the
agent-proposes → named-human-disposes model. The remaining items are genuinely lower-value.
