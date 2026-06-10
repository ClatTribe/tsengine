# Implementation Proposal — Autonomous Security Team for SMBs

> **What we're building:** an autonomous-first, human-backstopped security + GRC team
> for SMBs. The OSS-powered agentic engine (this repo) **finds & proves** issues →
> autonomously **fixes** the easy ones → a **human desk** fixes/approves the hard ones →
> **continuous compliance evidence**, all on a **signed ledger**.
>
> **Core principle:** *reuse the brain, build the body.* The detection/validation/
> prioritization engine already exists (`asset/*`, agents, `reachability`, `correlate`,
> `gate`, `ledger`). This proposal adds the **platform** (multi-tenant, connectors,
> continuous), the **human desk** (HITL + fix delivery), and **GRC** — without rewriting
> the engine.

---

## 1. Target architecture (CLI engine → platform)

```
                         ┌──────────── PLATFORM (new) ────────────┐
   Customer / operator ──┤  cmd/platform: multi-tenant API + UI    │
   + Human desk          │  onboarding · dashboard · Slack         │
                         └───────┬───────────────┬────────────────┘
                                 │               │
         ┌───────────────────────▼──┐   ┌────────▼────────────────┐
         │ connector (new)          │   │ scheduler (new)         │
         │ GitHub/AWS/GCP/Google/   │   │ cron + webhook triggers │
         │ M365/Slack · OAuth+watch │   └────────┬────────────────┘
         └───────────┬──────────────┘            │ fires
                     │ discovers assets / applies fixes
         ┌───────────▼──────────────────────────────────────────────┐
         │                THE ENGINE (exists, reused)                │
         │  orchestrator → asset/* (OSS tools) → agents (grounded)   │
         │  → reachability · correlate · gate · tracer/hooks         │
         └───────────┬───────────────────────────────┬──────────────┘
                     │ findings + proposed actions    │ every step
         ┌───────────▼──────────┐   ┌─────────────────▼─────────────┐
         │ hitl (new)           │   │ grc (new)                     │
         │ approval queue ·     │   │ control-state SoR · evidence  │
         │ remediate/fix-deliver│   │ pack · questionnaire          │
         └───────────┬──────────┘   └─────────────────┬─────────────┘
                     └──────────────┬─────────────────┘
                          ┌─────────▼─────────┐
                          │ store (new, MT) + │  ← system-of-record
                          │ ledger (exists)   │     + signed trust
                          └───────────────────┘
```

**New packages:** `pkg/ledger` (promoted), `pkg/platform` (domain types), `internal/store`
(multi-tenant), `internal/connector`, `internal/scheduler`, `internal/hitl`,
`internal/remediate`, `internal/grc`, `cmd/platform`.
**Reused unchanged:** `orchestrator`, `asset/*`, `tool/*`, agents, `reachability`,
`correlate`, `gate`, `tracer/hooks`, `report`, `importers`, `exporter`, `attest`.

---

## 2. Domain model (`pkg/platform/types.go`, new)

Multi-tenant entities the platform persists. Engine types (`pkg/types.Scan`,
`types.Finding`) are embedded, not replaced.

```go
type Tenant struct {
    ID, Name string
    Plan     string
    CreatedAt time.Time
}

// Connection is an OAuth-linked external system the agent watches + acts on.
type Connection struct {
    ID, TenantID string
    Kind     string // github | aws | gcp | gworkspace | m365 | slack
    Scopes   []string
    Status   string // active | degraded | revoked
    // token ref → secret store, never stored inline
    SecretRef string
}

// Asset is something discovered under a Connection (a repo, an account, a domain).
type Asset struct {
    ID, TenantID, ConnectionID string
    Type   string // repository | cloud_account | web_application | ...  (engine asset type)
    Target string
    Meta   map[string]string
}

// Engagement is one continuous-monitoring run over an Asset (wraps an engine Scan).
type Engagement struct {
    ID, TenantID, AssetID string
    Trigger   string // schedule | push | deploy | manual
    ScanID    string // links to the engine's types.Scan
    StartedAt, CompletedAt time.Time
    LedgerRef string // the signed decision ledger for this run
}

// Action is a remediation the agent proposes; tier decides if it needs approval.
type Action struct {
    ID, TenantID, FindingID string
    Kind   string // open_pr | apply_config | revoke_token | file_ticket
    Tier   int    // 0..3 (autonomy tier — gate at 2+)
    Status string // proposed | pending_approval | approved | applied | rejected
    Payload  map[string]any
    Approver string
    LedgerRef string
}

// ControlState is the GRC system-of-record: one control's live status per framework.
type ControlState struct {
    TenantID, Framework, ControlID string // soc2 | iso27001 | dpdp ...
    State    string // met | gap | exception
    EvidenceRefs []string // → ledger / findings
    UpdatedAt time.Time
}
```

---

## 3. The new packages

### 3.1 `internal/store` — multi-tenant persistence
The lock-in / system-of-record. Replaces single-tenant `findingstore`.

```go
type Store interface {
    // tenant-scoped CRUD; every call carries tenantID for isolation.
    PutFinding(ctx context.Context, tenantID string, f types.Finding) error
    ListFindings(ctx context.Context, tenantID string, filter Filter) ([]types.Finding, error)
    PutAction(ctx context.Context, a platform.Action) error
    PendingApprovals(ctx context.Context, tenantID string) ([]platform.Action, error)
    UpsertControlState(ctx context.Context, cs platform.ControlState) error
    // ... Tenant/Connection/Asset/Engagement CRUD
}
```
Impl: start with `sqlite` (single-binary, dev) → `postgres` (prod). Reuse
`findingstore`'s lifecycle logic; add `tenant_id` to every row + row-level scoping.

### 3.2 `internal/connector` — the #1 new capability (and #1 moat)

```go
type Connector interface {
    Kind() string
    OAuthURL(state string) string
    Exchange(ctx context.Context, code string) (Connection, error)
    Discover(ctx context.Context, c Connection) ([]platform.Asset, error)
    // Watch turns provider webhooks/events into engagement triggers.
    Watch(ctx context.Context, c Connection, ev []byte) ([]Trigger, error)
    // Apply executes an approved remediation (write path; gated upstream).
    Apply(ctx context.Context, c Connection, a platform.Action) error
}
```
First impls (ordered): `github` (repos + push webhook + open-PR), `aws`/`gcp`
(read-only config + apply IAM/SG fix), `gworkspace`/`m365` (read posture; for non-tech),
`slack` (notify + approve). Tokens → a secret store (Vault/KMS), referenced by
`Connection.SecretRef`.

### 3.3 `internal/scheduler` — continuous operation
```go
type Scheduler interface {
    Schedule(ctx, tenantID, assetID string, cron string) error
    OnEvent(ctx, t connector.Trigger) error // webhook → engagement
    Run(ctx context.Context) error          // the loop
}
```
Fires the **existing** `orchestrator.Run` per asset, debounced + concurrency-capped per
tenant. This is the "works while you sleep" layer; it changes nothing in the engine.

### 3.4 `internal/hitl` — the human desk
```go
type Desk interface {
    Enqueue(ctx context.Context, a platform.Action) error          // gated action → queue
    Pending(ctx context.Context, tenantID string) ([]platform.Action, error)
    Decide(ctx context.Context, actionID, approver, verdict string, edit map[string]any) error
}
```
Tier gating: `Action.Tier >= 2` → `Enqueue` (pause); else auto-apply. Every decision →
`ledger.Recorder` (already built). MVP surface: REST API + **Slack approve/reject
buttons** (no web console needed to start). The desk is staffed from Kanpur.

### 3.5 `internal/remediate` — fix delivery
Generalize `cloudengine/remediate.go` (which already generates + self-verifies cloud
fixes) into a delivery layer:
```go
type Fixer interface {
    Propose(ctx context.Context, f types.Finding) (platform.Action, error) // generate the fix
    // delivery via the connector: open_pr | apply_config | file_ticket
}
```
`open_pr` uses the github connector; `apply_config` uses cloud connectors (gated);
`file_ticket` → Jira/Linear. Closes the loop from "found+proved" to "fixed."

### 3.6 `internal/grc` — compliance system-of-record
```go
type GRC interface {
    // map a finding+evidence onto control state (extends tracer/hooks/compliance.map)
    Apply(ctx context.Context, tenantID string, f types.Finding) error
    Posture(ctx context.Context, tenantID, framework string) ([]platform.ControlState, error)
    EvidencePack(ctx context.Context, tenantID, framework string) ([]byte, error) // signed (ledger scheme)
    AnswerQuestionnaire(ctx context.Context, tenantID string, q []string) ([]Answer, error)
}
```
Reuses `compliance.map` (finding→control) and the `attest`/`ledger` signing for the
exportable, auditor-consumable evidence pack.

### 3.7 `cmd/platform` — the multi-tenant API
Extends `internal/server` (which already has auth + health + graceful drain) to:
onboarding (`POST /connect/:kind` → OAuth), `GET /findings`, `GET /approvals` +
`POST /approvals/:id`, `GET /posture/:framework`, the Slack app webhook. The web
dashboard is a separate front-end (Next.js) consuming this API — out of Go scope.

---

## 4. Changes to existing code (minimal, additive)

| Existing | Change | Why |
|---|---|---|
| `internal/ledger` | **promote → `pkg/ledger`** (update imports) | the platform + future products must import the trust substrate; `internal/` blocks that |
| `internal/orchestrator` | add a `Run` entrypoint callable per-(tenant,asset) with a `ledger.Recorder` + `Store` sink | wire continuous + multi-tenant without touching the scan logic |
| `internal/findingstore` | fold into `internal/store` (add `tenant_id`) | one multi-tenant store |
| `internal/cloudengine/remediate.go` | factor the generate+verify into `internal/remediate` | reuse for code/web fixes, not just cloud |
| `internal/tracer/hooks/compliance.go` | call `grc.Apply` on emit | feed the GRC system-of-record continuously |
| `cmd/tsengine` | unchanged (stays the engine CLI) | the platform is `cmd/platform`; engine keeps its identity |
| `CLAUDE.md` | add a "Platform layer" section when Phase 1 lands | architecture-invariant doc must track the new layer |

No engine detection logic changes. The grounding, the OSS tools, the agents, the
benches — untouched.

---

## 5. Phased PR plan (small, squash-merged, CI-green)

**Phase 0 — kernel + skeleton** *(safe, no behavior change)*
- PR-A: `internal/ledger` → `pkg/ledger` (move + reimport). Pure refactor.
- PR-B: `pkg/platform/types.go` — the domain model (§2).
- PR-C: `internal/store` — `Store` interface + sqlite impl (port `findingstore`).

**Phase 1 — platform MVP (tech SMB, the wedge)**
- PR-D: `internal/connector` interface + **github** connector (OAuth, discover, push-webhook, open-PR).
- PR-E: `internal/scheduler` (cron + webhook → `orchestrator.Run`).
- PR-F: `cmd/platform` multi-tenant API (onboarding/connect, findings) + tenant auth.
- *Ships:* connect GitHub → continuous grounded scanning → findings in an API/dashboard.

**Phase 2 — the human desk + fixes**
- PR-G: `internal/hitl` approval queue + Slack approve/reject + ledger wiring.
- PR-H: `internal/remediate` (generalize cloud fix → open-PR / ticket).
- *Ships:* expert-backed autonomy — agent fixes the easy, Kanpur human approves the gated.

**Phase 3 — GRC built-in**
- PR-I: `internal/grc` control-state SoR + posture API (SOC 2/ISO).
- PR-J: signed evidence-pack export + questionnaire auto-answer.
- *Ships:* compliance as a byproduct → renewal + lock-in.

**Phase 4 — non-tech operate layer (later, second audience)**
- New connectors (gworkspace/m365/EDR write) + new agents (identity/email/detect-respond)
  + DPDP/RoPA. Reuses the kernel + desk + GRC; large, so deliberately last.

---

## 6. MVP cut (what to build first)

> **Phase 0 + Phase 1 + PR-G/PR-H** = the minimum "autonomous security team."

A tech SMB connects GitHub + cloud → the engine continuously finds & proves issues →
the fixer opens PRs for the easy ones → gated actions queue to the Kanpur desk via Slack
→ everything is signed in the ledger. That's the whole promise, shippable on top of the
existing engine, reaching the tech-SMB market via PLG/OSS. GRC (Phase 3) and non-tech
(Phase 4) layer on the same kernel.

**Reuse vs build:** ~70% of the *engine* is reused as-is; the new build is the
**platform + desk + GRC** — which is exactly the non-code moat (connectors, continuous
data, the human desk, the system-of-record), the part better models don't erode.

---

## 7. Open decisions (need a call before Phase 1)

1. **Repo strategy:** same repo (`cmd/platform` here) for velocity, or a new repo
   importing `pkg/ledger` + the engine as a module? *Recommend: same repo now, split later.*
2. **Store backend:** sqlite-first (single binary) vs Postgres day one. *Recommend: sqlite → Postgres at first real tenant.*
3. **Secret store:** Vault vs cloud KMS vs encrypted-column for OAuth tokens. *Recommend: KMS-envelope in the store column for MVP.*
4. **Front-end:** API-only + Slack for MVP, web dashboard when the desk needs it. *Recommend: defer the UI.*
