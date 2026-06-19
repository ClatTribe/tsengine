# Personas & workflows — the fractional autonomous security team for SMB

**Status: design of record.** This file defines *who* TensorShield serves and *what loop each
of them runs*, then maps every persona-workflow to the implemented surface and names the
gaps. It is the yardstick for "does the implementation match the design" (the audit lives
in [§5](#5-implementation-audit--design-vs-built)).

The product thesis: an **SMB cannot hire a security team**, but it has the same attack
surface (code, cloud, SaaS identity) and the same compliance pressure (a SOC 2 in the
sales cycle) as a company 10× its size. TensorShield is that team — it **detects, triages,
and fixes** autonomously, and **stops for a human only where a human must decide.** "With
human in the loop" is not a disclaimer; it is the product's safety model (§4).

---

## 1. The competitive landscape — and the user model each assumes

> For the OSS-mapping + benchmark-vs-competitor "proof of parity" per lane, see
> [competitive-proof-sheet.md](competitive-proof-sheet.md).

No single incumbent is "a security team for an SMB." Each covers one lane and assumes a
*different buyer already exists*. Reading their user models tells us which personas are
table-stakes and where the wedge is.

| Category | Examples | Who they assume the user is | What they leave to a human |
|---|---|---|---|
| **Compliance automation** | Vanta, Drata, Secureframe | A founder/ops lead + an external auditor. Employees do MDM/training tasks. | *Everything technical.* They flag a control gap; a human (or a vCISO) fixes it. |
| **AppSec / code** | Snyk, Semgrep, GitHub Advanced Security | A **developer** and a **security engineer**. | Triage of noisy findings; deciding which to fix. |
| **SaaS / identity posture** | Nudge Security, Push Security, Cerby | An IT/security admin. | Remediation (revoke, enforce MFA) — mostly manual. |
| **vCISO platforms** | Cynomi, Vanta+services | A *human* vCISO consultant who runs the tool. | The tool is a worksheet; the human is the team. |
| **Autonomous offensive** | XBOW, Horizon3 NodeZero, strix | A **security engineer** who reads exploit-verified output. | Fixing; compliance; everything non-offensive. |

**The pattern:** every incumbent assumes the customer already employs the security person.
Vanta finds the gap and hands a developer a ticket. Snyk finds the bug and hands a security
engineer a queue. The SMB that has *neither* is unserved — they buy three tools and still
need a person to operate them.

**Our wedge** is to be the operator. We span all three detection lanes (code+cloud via the
engine, SaaS identity via `operate`, compliance via `grc`) **and do the triage + fix**,
escalating to a human only at the gate. So our personas are not "the security engineer who
runs the tool" — they are **the people an SMB actually has** (a founder, a couple of
engineers, maybe an ops person) plus the two non-human actors that make it a *team*: the
**AI** that does the work and the **human expert** it escalates to.

---

## 2. The personas

Seven actors. Five are people; two (the agent, the expert) are what make it a "team." We
deliberately collapse the *people* onto **two account roles** (`owner`, `member`) — an SMB
will not maintain an RBAC matrix, and the *workflow*, not the role, is what differentiates
them. Role gates only the few owner-only acts (invite, billing, trust-center link).

| # | Persona | Account role | Primary job-to-be-done | Buys / champions? |
|---|---|---|---|---|
| P1 | **Founder / Owner** | `owner` | "Are we secure? Are we compliant? What must I approve?" | **Buyer.** Non-security. |
| P2 | **Engineer** | `member` | Fix the code/cloud issues; keep shipping. | Influencer. |
| P3 | **IT / Ops admin** | `member` | Lock down identity (MFA, OAuth grants, stale accounts, email spoofing). | User. |
| P4 | **Compliance lead** | `member` or `owner` | Get SOC 2 / ISO / PCI ready; answer security questionnaires; hand the auditor evidence. | Champion in the sales cycle. |
| P5 | **External auditor / prospect** | *(public, token-gated)* | Verify the org's posture without seeing raw findings. | — (the reason P4 buys). |
| P6 | **The AI security team** | *(the agent)* | Detect → triage → propose → (auto-apply low-risk) → escalate. | — (the product). |
| P7 | **Human expert reviewer** | *(the loop backstop)* | Resolve what the AI escalates or a user questions. | — (the "with human in the loop"). |

> **An SMB person wears several hats.** The same founder is often P1 *and* P4; one engineer
> is P2 *and* P3. The personas are **jobs**, not headcount. The UX must let one logged-in
> human flow between these jobs without role-switching friction — which is exactly why the
> account model stays `owner`/`member` and the *navigation* (not permissions) carries the
> persona.

---

## 3. The workflows (jobs-to-be-done → click path)

Each workflow is written as the persona experiences it, then grounded to the built surface.

### P1 — Founder / Owner: "Am I covered, and what do I owe?"
1. **Sign up** → a workspace + owner account is created (`/signup`).
2. **Connect the first system** (GitHub / cloud / Google Workspace) — OAuth, one click (`/assets`).
3. The agent discovers assets and scans; the **Overview** resolves to a single risk rating
   + "what needs you" (`/dashboard`).
4. **Approve / reject fixes** the agent prepared, in plain English (`/inbox`).
5. **Share trust** with a customer/investor — a public, read-only Trust Center link (`/settings` → `/trust/{tenant}`).
   *Success = the founder never reads a raw scanner finding.*

### P2 — Engineer: "Fix the code issues without becoming a security person."
1. Invited by the owner → signs in.
2. Connects the repo / cloud account (`/assets`).
3. Reviews **auto-generated fix PRs** (repository findings → `ActOpenPR`, tier 1) — approve
   in `/inbox`, the PR lands on the branch.
4. Drills a finding for the evidence (tool, CWE, endpoint, confidence) when curious (`/findings/[id]`).
   *Success = the fix arrives as a reviewable PR, not a ticket to research.*

### P3 — IT / Ops admin: "Lock down our SaaS identity."
1. Connects **Google Workspace / M365 / Okta** (`/assets`).
2. `operate` runs grounded posture checks — admin-without-MFA, weak DMARC, risky OAuth
   grants, stale accounts — each citing the exact user/domain/app (`/findings`).
3. Acts on **specific runbook tickets** (e.g. the exact `_dmarc.<domain>` TXT to publish),
   or approves a live remediation (Okta suspend stale account) in `/inbox`.
   *Success = identity findings name the entity and carry the fix, not generic advice.*

### P4 — Compliance lead: "Get us audit-ready and answer the questionnaire."
1. Opens **Compliance** → posture across 14 frameworks (SOC 2, ISO 27001, PCI, HIPAA, CIS v8,
   NIST CSF, GDPR, ISO 27701, NIST 800-53/171, CCPA, SOX, FedRAMP, DPDP), grouped by category
   with met/gap counts (`/compliance`).
2. Drills a framework → each **gap is backed by the citing finding** (`/compliance/[framework]`).
3. **Auto-answers a security questionnaire** (CAIQ/SIG-style), grounded in findings (`/compliance/questionnaire`).
4. **Downloads a signed evidence pack / report** for the auditor (`/reports`, `GET /v1/compliance/{fw}/report`).
   *Success = the gap list, the evidence, and the questionnaire answers all trace to real findings.*

### P5 — External auditor / prospect: "Prove it without an NDA dance."
1. Receives the **Trust Center link** (HMAC-token-gated, public).
2. Sees org name, continuous-monitoring status, per-framework coverage %, signed/tamper-evident
   badge — **never** raw findings or counts (`/trust/{tenant}`).
   *Success = a verifiable posture summary with zero data leakage.*

### P6 — The AI security team (the autonomous loop)
`connect → discover → scan (continuous + webhook + on-demand) → emit grounded finding →
map to compliance control (grc) → reconcile into incidents (detect) → propose remediation
(remediate) → tier-gate (hitl) → auto-apply low-risk / queue the rest → record every step
signed (ledger).` Runs on a schedule (`TSENGINE_MONITOR_INTERVAL`) and on provider webhooks.
*Success = the loop advances without a human, and pauses exactly at the gate.*

### P7 — Human expert reviewer (the backstop)
1. A user **requests expert review** on a finding or a proposed action (`/findings/[id]` → Reviews).
2. The reviewer resolves with a verdict, signed into the ledger (`/reviews`, `POST /v1/reviews/{id}/resolve`).
   *Success = there is always a human a non-expert can escalate to.* **Open design question:**
   who is the reviewer — a teammate, or a TensorShield-side security expert (the true "fractional
   team")? Today the resolve path is any tenant user; a vendor-side expert tier is a
   business decision, not a code gap (§5).

---

## 4. The human-in-the-loop model (the safety contract)

Autonomy is **tiered by blast radius**, not by category. The gate is `platform.GateTier`
(=2): anything below auto-applies; anything at/above queues for a human.

| Tier | Meaning | Examples | Who decides |
|---|---|---|---|
| **0–1** | Reversible / informational | Open a fix **PR** (a human still merges); file a **ticket** | **Auto-applies.** Recorded + signed. |
| **≥ 2** | Persistent mutation of a live system | Change a **cloud config**; **suspend** an identity; revoke a token | **Human gate** (`/inbox`, Slack, or API). |

Three properties hold end-to-end and are non-negotiable (CLAUDE.md §18.2):
- **The only write path is `connector.Apply`, reached only after the gate.** No package calls Apply directly.
- **Every decision is signed** (auto-apply and human verdict alike) into the ledger.
- **Grounding holds:** a control is a "gap" only because a real finding cites it; a remediation always carries its `FindingID`. The AI never asserts what a tool did not prove.

The agent's own cloud access stays **read-only** (scoped STS + `cloudsafety.Guard`); a
mutation is always a *proposal a human approves*, never the agent acting on production with
write creds.

---

## 5. Implementation audit — design vs built

Legend: ✅ built & wired · ◐ partial / honest-stub · ○ design only.

| Persona / workflow step | State | Where | Note |
|---|---|---|---|
| P1 signup → owner account | ✅ | `authn`, `platformapi/auth.go` | PBKDF2, session cookie |
| P1 connect system (OAuth) | ✅ | `connector`, `loop.go` | GitHub/GitLab/GWorkspace/M365/Okta/AWS |
| P1 risk Overview | ✅ | `frontend/.../dashboard` | owner-first |
| P1 approve/reject in browser | ✅ | `/inbox`, `hitl.Desk.Decide` | same gate as Slack/API |
| P1 Trust Center share | ✅ | `trust.go`, `/trust/[tenant]` | HMAC-gated, no raw data |
| P2 auto-fix **PR** (repo) | ✅ | `remediate.Propose`→`ActOpenPR`, `connector.github` | live write |
| P2 finding evidence drill | ✅ | `/findings/[id]` | tool/CWE/confidence |
| P3 identity posture (MFA/DMARC/OAuth/stale) | ✅ | `operate` (GWorkspace/M365/Okta all live) | grounded, snapshot-testable |
| P3 specific runbook ticket | ✅ | `remediate/identity.go` | names the entity + the fix |
| P3 **live identity remediation** (Okta suspend) | ✅ | `proposeIdentity`+`liveIdentityMutation` → tier-2 `ActApplyConfig` → `Okta.Apply` | **GAP-1 closed** — finding → gated action → approve → live suspend, E2E-tested |
| P3 GWorkspace / M365 live *write* | ◐ | connector `Apply` honest stubs | **GAP-2** — pending admin-write creds (documented) |
| P4 compliance posture + drill | ✅ | `grc`, `/compliance/[framework]` | gaps cite findings |
| P4 questionnaire auto-answer | ✅ | `grc`, `/compliance/questionnaire` | grounded |
| P4 signed evidence pack / report | ✅ | `grc`, `/reports` | ed25519 |
| P5 Trust Center (public) | ✅ | `trust.go` | coverage only |
| P6 autonomous loop | ✅ | `runner`+`detect`+`hitl`+`ledger`, `scheduler` | continuous + webhook + on-demand |
| P7 request/resolve expert review | ✅ (surface) | `reviews.go`, `/reviews` | **Open design Q:** reviewer = teammate vs vendor expert (§3) |
| Invited member first-login pw change | ✅ | `User.MustChangePassword` + `auth` gate + `POST /v1/auth/password` + `/change-password` | **GAP-3 closed** — app blocked (403) until the temp pw is rotated |
| Cloud (AWS/GCP) live *write* | ◐ | `connector.aws` stub | pending creds (documented) |

### The real, *fixable-now* gaps (not credential-gated)

- **GAP-1 — operate → tier-2 `ActApplyConfig` wiring — ✅ CLOSED.** `remediate.proposeIdentity`
  now promotes a remediation to a **tier-2 `ActApplyConfig`** (gated) whenever a live,
  reversible connector write path exists for the asset's provider (`liveIdentityMutation`;
  today only Okta `account_suspend`), keeping every other (remediation, provider) a tier-1
  runbook ticket so nothing falsely auto-applies. A stale-Okta-account finding now flows
  finding → gated action → HITL approve → `connector.Okta.Apply` suspend → signed ledger.
  Provider is carried in `Asset.Meta["provider"]`. E2E-tested
  (`TestNonTechLoop_StaleAccountGatedThenApprovedSuspends`). Promotion of the next pair
  (GWorkspace/M365 suspend, Okta `oauth_revoke`) is one line once its connector `Apply` lands.
- **GAP-3 — forced first-login password rotation — ✅ CLOSED.** An invited member's account
  carries `User.MustChangePassword`; while set, the `auth` middleware blocks every app
  endpoint with `403 password_change_required` (the auth-management endpoints stay
  reachable), and `POST /v1/auth/password` rotates it and unlocks the app. Frontend: a
  top-level `/change-password` route + the `(app)` layout redirect. So the owner-issued temp
  password can't remain the standing credential. API-level E2E test:
  `TestAuth_ForcedPasswordRotation`.
- **Open design question (P7):** is the human expert a teammate or a TensorShield-side analyst?
  This is the literal "fractional team" promise; it's a go-to-market decision to record,
  not a code defect.

The credential-gated items (GAP-2, cloud write) are **honest stubs** that surface a clear
error rather than falsely reporting success — correct behavior until an admin grants
write scopes.

---

## 6. Verification status (workflows + benchmarks)

- **Workflows** are exercised end-to-end against the production (SQLite) store — auth/team,
  connect-URL, scan-as-job, findings, the HITL approve path, compliance report, incidents,
  Trust Center, `/metrics` — and at the **UI level** (founder + invited-member click-paths,
  the forced-rotation redirect, the kill-switch banner/control).
- **Detection accuracy vs competitors** (the FP/FN bar): SAST **47.86% Youden ≈ Checkmarx
  (47)**, container **100% recall / 0 FP** (live host trivy), web-agent range **100% recall
  / 0 decoys flagged** (7 seeds), LLM red-team **100% recall (61/61) / 0 false breaches**
  (7 seeds). Remaining asset benches are sandbox-image-gated (DAST/WAVSEP, cloud, api, ip)
  and run in the build pipeline, not on a laptop with restricted egress.

---

## 7. Reconciliation against the agentic-SMB spec (`sec_lifecycle_agentic_smb.md`)

The companion design doc `sec_lifecycle_agentic_smb.md` is the formal RFC-2119 spec for this
product: the run-secure lifecycle operated by an **orchestrated agent roster + one
accountable human + a signed decision ledger**, autonomy classified by **blast-radius tier**
(T0 observe / T1 reversible / T2 consequential / T3 irreversible-or-legal). This table maps
its hard requirements to the implementation.

| Spec requirement | State | Where |
|---|---|---|
| **Autonomy tiers T0–T3** (§3) | ✅ | `pkg/platform/types.go` (tier doc); `GateTier=2` gates T2+ |
| **TS-2 — T2 pauses for a human; T3 always human-signed** | ✅ | `hitl.Desk` (tier ≥ GateTier queues); reject-safe, approve→apply gated |
| **TS-3 — every decision signed (tier + approver) in a replayable ledger** | ✅ | `pkg/ledger`; `Desk.record` |
| **TS-1 — no T1+ action on an ungrounded claim** | ✅ | grounding (CLAUDE.md §10); remediations carry `FindingID` |
| **OM-3 / TS-5 — global kill-switch, halts all agent action** | ✅ **(this iteration)** | `Tenant.AgentsHalted`, `POST /v1/killswitch`, `hitl`+`runner` fail closed, single-pane control |
| **A-IDN / A-ASR — grounded EASM + validation agents** | ✅ | the engine (domain/ip/cloud + web/cloud/LLM validation) |
| **A-PRO / A-DET — identity hardening + continuous detection** | ✅ | `operate` (MFA/DMARC/OAuth/stale) + `detect` (incidents) |
| **A-GOV — compliance/governance** | ◐ | `grc` (control state, evidence, questionnaire); risk-register/policy drafting not built |
| **A-RSP — incident response (respond)** | ◐ | a critical incident → a **T3 breach-disclosure draft** the human signs (`remediate.ProposeIncidentResponse` → `runner` → `hitl`); playbooks / containment / forensics are the future depth |
| **TS-4 — ledger as auditor/insurer evidence of record** | ✅ | `grc` signed evidence pack + compliance report |
| **T3 — irreversible-action invariant** (agent prepares, human signs) | ✅ + first flow | `platform.TierIrreversible`=3 + `NeedsHumanSignature()`; `hitl.Desk` refuses to apply a T3 action without a named human approver (`ErrNeedsHumanSignature`) — never on `auto`. **A-RSP now emits a real T3 action** (the breach-disclosure draft), so the invariant guards a live flow: a critical incident's draft queues for signature and can never auto-send |
| **WRD-1 — AI-BOM** (inventory of what the agent can touch: scopes + least-privilege read/write) | ✅ | `GET /v1/ai-bom` (`internal/platformapi/aibom.go`) + a Settings panel — grounded in real `Connection.Scopes`, flags the write-capable (higher-risk) surface |
| **WRD-4 — per-agent quarantine** | ✅ | `POST /v1/connections/{id}/quarantine` (`quarantine.go`) + an owner-gated Settings control on the AI-BOM panel — halt ONE connection's automation (`ConnQuarantined`) without halting the rest; the runner skips its assets, the deliverer refuses its writes |
| **WRD-3 — injection-resistance** | ✅ | the instruction-source boundary (CLAUDE.md §10) — agents act on tool output, never on instructions in ingested data |
| **OM-5 — fail closed on connector unavailability** | ✅ | the runner skips an asset whose connection isn't `ConnActive` (revoked/degraded/quarantined) — `connInactive`, permissive only on missing data; the HITL gate already covered the write path |
| **ACC-1/2 — named accountable human + autonomy-policy doc** | ◐ | the owner is the accountable human (role model); a per-tenant autonomy-policy artifact is **next** |

The spec's own crosswalk (§11) frames tsengine's durable role as the **A-IDN + A-ASR agents
and the TS decision-ledger substrate** — "the validation-and-evidence backbone an agentic
MSSP would buy rather than build." The platform layer adds the **operating model** around it
(orchestration cadence, the HITL desk, the single pane, and now the kill-switch).
