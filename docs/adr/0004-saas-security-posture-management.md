# ADR 0004 — SaaS Security Posture Management (SSPM)

- **Status:** Proposed
- **Date:** 2026-06-20
- **Affects:** CLAUDE.md §8 (compliance emission paths), §18 (platform); a new `internal/sspm`; the non-tech posture surface alongside `internal/operate`

## Context

An SMB's attack surface is increasingly **SaaS configuration**, not just code,
cloud, and identity. The engine already covers:

- **Identity / email posture** (`internal/operate`) — Google Workspace, M365,
  Okta: MFA, OAuth grants, stale accounts, DMARC/SPF/DKIM.
- **Code / cloud / web / containers** — the engine asset types.

The gap (flagged "Partial" in the asset-coverage analysis) is **SaaS app
configuration posture** — is each SaaS the company runs configured securely?
This is the SSPM category (competitors: Nudge Security, Wing, AppOmni, Vanta's
SaaS checks). It is distinct from identity posture: operate answers "who can log
in and how"; SSPM answers "is the app itself configured safely".

## Decision

Add **`internal/sspm`** — a SaaS posture engine that **mirrors the `operate`
architecture** (and the deterministic `cloudengine`): a **snapshot** of an app's
security configuration → **grounded checks** → **findings mapped to compliance
controls** → the same store / grc / hitl / ledger loop. It is **LLM-free and
deterministic**, so a hardened app yields **zero** findings (the testability
invariant) and every finding cites the offending setting/entity (grounding §10).

This is **not a new in-house detector** (§13): there is no dominant OSS SSPM
tool, and the checks are deterministic evaluations of first-party config the
provider's own API returns — the same shape as `operate` and `cloudengine`,
which §13 already sanctions as orchestration/evaluation logic, not detection
scanners.

## Top SaaS apps to support (priority)

Ranked by SMB prevalence × security-control density × API availability:

| # | App | Status | Why |
|---|---|---|---|
| 1 | **GitHub org** | ✅ built (this ADR) | Highest value for a dev SMB; org 2FA, repo perms, secret scanning, third-party apps, webhooks. Connector already exists. |
| 2 | Slack | next | Workspace 2FA, guest/external accounts, app governance, retention, DLP. |
| 3 | Atlassian (Jira/Confluence) | planned | Public spaces, app tokens, external sharing, admin sprawl. |
| 4 | Zoom | planned | Meeting security defaults, recording/retention, SSO. |
| 5 | Salesforce | planned | Profiles/permission sets, connected apps, session policy. |
| — | Google Workspace / M365 / Okta | ✅ via `operate` | Identity posture already covered. |

Each new app = **one snapshot type + its `Assess*` function** in `internal/sspm`,
exactly like adding a check to `operate`.

## GitHub org checks (built)

Grounded evaluations of real org settings, each compliance-mapped:

- `2fa-not-enforced` (org-wide 2FA off) — **high**
- `member-without-2fa` (per member; owners rated higher) — high/medium
- `broad-default-repo-permission` (base write/admin) — medium
- `members-can-create-public-repos` — medium
- `secret-scanning-disabled` (org default off) — high
- `outside-collaborators` (external repo access) — low
- `owner-sprawl` (> N org owners) — medium
- `app-admin-scope` / `app-unverified` (third-party / shadow-admin) — high/medium
- `webhook-no-ssl-verify` — medium

## Wiring roadmap (follow-up phases)

Phase 1 (this ADR) ships the **engine + GitHub checks + tests** — the host-verified
core, snapshot-driven (`AssessGitHubOrg`), exactly how `operate` landed before its
live fetchers. Remaining, each a small follow-up:

1. **Asset routing** — a `saas` asset (or a provider-tagged `workspace` asset)
   routed through `runner.MuxRunner` to `sspm`, so findings flow into the loop.
2. **Live fetch** — `connector.GitHub` org/admin API → `GitHubOrg` snapshot
   (mirrors `operate.GWorkspace.Fetch`), behind a `Source` like
   `runner.LiveWorkspaceSource`.
3. **Remediation** — map each check to a runbook (`internal/remediate`), e.g.
   `2fa-not-enforced` → "enable org 2FA requirement"; a future live `Apply` via
   the GitHub admin API (HITL-gated, §18.2 inv. 3).

## Consequences

- SSPM findings carry compliance annotations → they flow into the **same `grc`
  evidence pack + compliance report** as every other source (§8 gains a 4th
  emission path: CWE crosswalk · identity · cloud attack-paths · **SaaS posture**).
- Deterministic + testable: a hardened org is provably clean; no LLM in the loop.
- Grounded: every finding is a real config fact, never a guess.
