# Platform operations guide

How to deploy, configure, and operate the **autonomous security team** platform
(`cmd/platform`) — the multi-tenant product layer that wraps the tsengine detection
engine into a continuous, human-backstopped service for tech *and* non-tech SMBs.

This is the operator manual. For the architecture invariants see
[CLAUDE.md §18](../CLAUDE.md); for the design rationale see
[docs/autonomous-team.md](autonomous-team.md).

---

## 1. What it does

One server runs the full loop, for both audiences, on the untouched engine:

```
onboard → connect a system → scan → detect change → open incident → alert
        → propose a fix → human approves → record signed compliance
```

- **Tech tenants** connect code/cloud (GitHub, GitLab) → the sandbox engine scans repos.
- **Non-tech tenants** connect identity/email (Google Workspace, Microsoft 365, Okta) →
  the `operate` posture engine assesses MFA, email-auth (DMARC/SPF/DKIM), stale/over-
  privileged accounts, and risky OAuth grants.

Every write is **human-gated** (HITL desk), every decision is **signed into the ledger**,
and OAuth tokens are **encrypted at rest**.

---

## 2. Prerequisites

| Need | Why |
|---|---|
| The `platform` binary | `go build -o platform ./cmd/platform` |
| Docker | The detection engine runs each scan in a sandbox container |
| The sandbox image | `tsengine/sandbox:<digest>` — built from the repo `Dockerfile` (has nuclei/semgrep/trivy/… baked in). Set `TSENGINE_SANDBOX_IMAGE` |
| A public HTTPS URL | For OAuth redirect URIs + Slack/webhook callbacks (`TSENGINE_PLATFORM_PUBLIC`) |

Non-tech-only deployments can run **without** Docker/the engine — set
`TSENGINE_PLATFORM_NO_ENGINE=1` and only `operate` (identity/email) tenants scan.

---

## 3. Quick start (minimal)

```sh
export TSENGINE_PLATFORM_TOKEN="$(openssl rand -hex 32)"   # the platform bearer token
export TSENGINE_SECRET_KEY="$(openssl rand -base64 32)"    # AES-256 key to seal OAuth tokens
export TSENGINE_PLATFORM_DB=/var/lib/tsengine/platform.json # durable store (else in-memory)
./platform
# → [platform] listening on :8090
```

Then provision a tenant and connect a system (§8). With no connector credentials set, the
server still boots — you just can't start OAuth flows until you configure at least one
provider (§5–§6).

---

## 4. Environment variables

### Core
| Var | Required | Default | Purpose |
|---|:---:|---|---|
| `TSENGINE_PLATFORM_TOKEN` | ✅ | — | Static bearer token for the API + console. Treat as a root secret. |
| `TSENGINE_SECRET_KEY` | strongly rec. | — (unsealed!) | base64 32-byte AES-256-GCM key. **Without it, OAuth tokens are stored in plaintext** (a startup WARNING is logged). |
| `TSENGINE_PLATFORM_DB` | rec. | in-memory | Path to a JSON store file (atomic, crash-safe). Without it the store is in-memory and lost on restart. |
| `TSENGINE_PLATFORM_ADDR` | | `:8090` | Listen address. |
| `TSENGINE_PLATFORM_PUBLIC` | for OAuth | — | Public base URL (e.g. `https://app.example.com`) used to build OAuth `redirect_uri`s. |
| `TSENGINE_SANDBOX_IMAGE` | | `tsengine/sandbox:latest` | Engine sandbox image ref. |
| `TSENGINE_PLATFORM_NO_ENGINE` | | unset | `1` → boot without the sandbox engine (non-tech `operate` tenants still scan). |
| `TSENGINE_MONITOR_INTERVAL` | | `12h` | Continuous re-scan cadence (e.g. `6h`). `0` disables the scheduler. |

### Connectors (set the pair for each provider you want to offer)
| Var | Provider |
|---|---|
| `GITHUB_CLIENT_ID` / `GITHUB_CLIENT_SECRET` | GitHub |
| `GITLAB_CLIENT_ID` / `GITLAB_CLIENT_SECRET` | GitLab |
| `BITBUCKET_CLIENT_ID` / `BITBUCKET_CLIENT_SECRET` | Bitbucket Cloud (OAuth consumer key/secret; grant repository + pullrequest scopes) |
| `AZURE_DEVOPS_CLIENT_ID` / `AZURE_DEVOPS_CLIENT_SECRET` / `AZURE_DEVOPS_ORG` | Azure DevOps (App ID + client secret; `vso.code`/`vso.code_write` scopes). `ORG` is the organization (`dev.azure.com/{ORG}`) — required, since the org isn't carried in the OAuth flow. |
| `GWORKSPACE_CLIENT_ID` / `GWORKSPACE_CLIENT_SECRET` | Google Workspace |
| `M365_CLIENT_ID` / `M365_CLIENT_SECRET` | Microsoft 365 |
| `OKTA_ORG_URL` / `OKTA_CLIENT_ID` / `OKTA_CLIENT_SECRET` | Okta (org URL e.g. `https://dev-123.okta.com`) |
| `AWS_REMEDIATION_ROLE_ARN` / `AWS_REMEDIATION_EXTERNAL_ID` / `AWS_REGION` | Enables the **live AWS remediation write path** (`connector.AWS.Apply` → S3 Block Public Access). `ROLE_ARN` is a scoped, cross-account **write** role the platform assumes via STS (distinct from the read-only onboarding role); `EXTERNAL_ID` is its tenant-binding ExternalId. Unset (and `AWS_REMEDIATION_ENABLED≠1`) → `Apply` stays an honest stub. The write is reached only after the HITL approval gate. |
| `GCP_REMEDIATION_IMPERSONATE_SA` | Enables the **live GCP remediation write path** (`connector.GCP.Apply` → GCS Public Access Prevention). The platform impersonates this scoped **write** service account in the customer project (distinct from the read-only Security Reviewer grant). Unset (and `GCP_REMEDIATION_ENABLED≠1`) → `Apply` stays an honest stub. HITL-gated. |

### Notifications + ticketing (optional)
| Var | Purpose |
|---|---|
| `TSENGINE_SLACK_WEBHOOK` | Slack Incoming Webhook — posts approvals (with buttons) + new-incident alerts. |
| `TSENGINE_SLACK_SIGNING_SECRET` | Verifies Slack approve/reject button callbacks (`POST /v1/slack/interactive`). |
| `TSENGINE_WEBHOOK_SECRET` | Verifies inbound provider webhooks (GitHub HMAC-SHA256 / GitLab token) before any re-scan. **Unset → webhooks are NOT verified** (a startup warning is logged); set it and configure the same secret on the provider's webhook. |
| `TSENGINE_DISCORD_WEBHOOK` | Discord Incoming Webhook — posts a colour-coded embed for each new high/critical incident to a Discord channel. Unset → off. |
| `TSENGINE_WEBHOOK_URL` | Generic **outbound** webhook — POSTs a signed JSON event (`incident.opened`) per new incident, so a tenant can wire TensorShield into anything (Zapier / n8n / a SIEM / a custom endpoint) without a bespoke connector. Unset → no outbound webhook. |
| `TSENGINE_WEBHOOK_SIGNING_SECRET` | HMAC-SHA256 key for the outbound webhook above; the receiver recomputes it over the raw body to verify the `X-TensorShield-Signature: sha256=<hex>` header. Unset → events are sent unsigned (the header is omitted). |
| `JIRA_BASE_URL` / `JIRA_EMAIL` / `JIRA_API_TOKEN` / `JIRA_PROJECT` | Files `file_ticket` remediations as Jira issues. |
| `LINEAR_API_KEY` / `LINEAR_TEAM_ID` | Files `file_ticket` remediations as Linear issues (GraphQL `issueCreate`). One ticket filer is active per platform — precedence is Jira → ServiceNow → Linear, by whichever env set is present. |

---

## 5. Connector OAuth-app setup

Register one OAuth app per provider. Every callback URL is
`${TSENGINE_PLATFORM_PUBLIC}/v1/connect/<kind>/callback`.

| Provider | `kind` | Callback URL | Onboarding scopes |
|---|---|---|---|
| GitHub | `github` | `…/v1/connect/github/callback` | `repo`, `read:org` |
| GitLab | `gitlab` | `…/v1/connect/gitlab/callback` | `read_api`, `api` |
| Google Workspace | `gworkspace` | `…/v1/connect/gworkspace/callback` | `admin.directory.user.readonly` |
| Microsoft 365 | `m365` | `…/v1/connect/m365/callback` | `User.Read.All`, `AuditLog.Read.All`, `offline_access` |
| Okta | `okta` | `…/v1/connect/okta/callback` | `okta.users.read`, `okta.factors.read`, `okta.roles.read` |

### Optional: broader consent for live OAuth-grant detection

The shadow-admin **OAuth-grant** check (a third-party app holding admin/directory scope)
needs extra read permission. It is **best-effort** — absent the broader consent, grant
detection simply yields nothing and the rest of the posture fetch is unaffected. To enable
it, also grant:

- **Google Workspace**: a scope that allows reading users' issued tokens
  (`admin.directory.user.security`).
- **Microsoft 365**: `Directory.Read.All` (to read `oauth2PermissionGrants` +
  `servicePrincipals`).
- **Okta**: `okta.users.read` already covers `/users/{id}/grants` + `okta.apps.read` for
  app labels.

---

## 6. Slack setup

1. Create a Slack app → **Incoming Webhooks** → install to the channel your security desk
   watches → set the URL as `TSENGINE_SLACK_WEBHOOK`.
2. For interactive Approve/Reject buttons: enable **Interactivity**, set the Request URL to
   `${TSENGINE_PLATFORM_PUBLIC}/v1/slack/interactive`, and copy the app's **Signing
   Secret** to `TSENGINE_SLACK_SIGNING_SECRET`. The server verifies Slack's `v0` signature
   (HMAC-SHA256, 5-minute replay window) before acting.

With Slack configured you get: a buttoned approval message when a tier-2+ fix queues, and a
:rotating_light: heads-up when continuous monitoring opens a new at/above-threshold
incident.

---

## 7. Onboarding a tenant

```sh
H="Authorization: Bearer $TSENGINE_PLATFORM_TOKEN"

# 1) provision the tenant (operator token; no tenant header)
curl -sX POST -H "$H" -d '{"name":"Acme Inc","plan":"pro"}' \
  https://app.example.com/v1/tenants
# → {"id":"ten-…", ...}

# 2) get a provider consent URL (tenant-scoped) and send the user to it
curl -s -H "$H" -H "X-Tenant-ID: ten-…" \
  https://app.example.com/v1/connect/github
# → {"authorize_url":"https://github.com/login/oauth/authorize?…&state=ten-…"}
```

The OAuth `state` carries the tenant id, so the callback attributes the connection, seals
the token, **discovers the tenant's assets, and scans them immediately**. From the
**dashboard**, the same flow is one click: sign in → *Connect a system*.

---

## 8. The dashboard (`/ui`)

A server-rendered, read-mostly console sharing the platform token via a browser session
cookie (a browser can't send a bearer header on navigation).

- **`GET /ui`** → token login → posture dashboard: risk rating, severity counts, *New
  since last scan* (incidents), *Awaiting your approval* (Approve/Reject buttons), top
  findings, *Monitored assets* (+ **Scan now**), connected systems, compliance posture.
- **Approve/Reject** drives the **same gated `hitl.Desk.Decide`** the API/Slack use — the
  console is a UI onto the gate, not a second write path. The operator name (captured at
  login) is recorded as the ledger approver.
- **Compliance posture cards** link to `GET /ui/compliance/{framework}` — the per-control
  drill-down (each gap backed by its citing findings).
- **Connect a system** → `GET /ui/connect` → provider OAuth.

---

## 9. API reference

Auth: every `/v1/*` call (except the OAuth callback + Slack endpoint) needs
`Authorization: Bearer $TSENGINE_PLATFORM_TOKEN`. Tenant-scoped calls also need
`X-Tenant-ID: <id>` (or `?tenant=<id>` on the console).

| Method + path | Purpose |
|---|---|
| `GET /healthz` | Liveness. |
| `POST /v1/tenants` | Provision a tenant (operator token; no tenant header). |
| `GET /v1/connect/{kind}` | Get a provider OAuth consent URL. |
| `GET /v1/connect/{kind}/callback` | OAuth redirect target (no bearer; tenant in `state`). |
| `POST /v1/webhooks/{kind}` | Provider webhook → event-driven re-scan. |
| `GET /v1/findings` | The tenant's findings. |
| `GET /v1/findings/export` | Export findings — SARIF (default; GitHub code-scanning) or CSV (`?format=csv`). |
| `GET /v1/engagements` | Scan history. |
| `GET /v1/connections` | Connected systems (`SecretRef` redacted). |
| `GET /v1/incidents` | Open incidents (`?status=all` includes resolved). |
| `GET /v1/apps` | Third-party OAuth app inventory (all SaaS apps with access — SOC2 vendor/app review). |
| `POST /v1/rescan` | Re-scan all the tenant's assets now. |
| `GET /v1/approvals` | The HITL approval queue. |
| `POST /v1/approvals/{id}` | Decide an action: `{"approver":"…","approve":true}`. |
| `GET /v1/posture/{framework}` | Raw control state for a framework. |
| `GET /v1/compliance/{framework}/report` | Auditor report — Markdown (`?format=json` for the structured report). |
| `POST /v1/slack/interactive` | Slack button callback (Slack-signed, not bearer). |

Frameworks (14, defined in `grc.Frameworks`): `soc2`, `iso27001`, `pci`, `hipaa`, `cis_v8`, `nist_csf`, `gdpr`, `iso27701`, `nist_800_53`, `nist_800_171`, `ccpa`, `sox`, `fedramp`, `dpdp`.

---

## 10. Continuous monitoring

The scheduler re-scans every tenant on `TSENGINE_MONITOR_INTERVAL` (default 12h; `0`
disables; webhooks also trigger event-driven re-scans). Each pass **reconciles findings
into incidents**: a new finding at/above the severity threshold (default `high`) opens a
signed `Incident`; an issue that stops appearing resolves its incident. A newly-opened
incident fires the Slack alert. So the platform always knows *what's new since the last
pass* and *what's now fixed* — the raw findings (overwritten each scan) can't tell you
that.

---

## 11. Security model

- **Tenant isolation** is the security boundary — every store call is tenant-scoped; a
  tenant never reads another's data (asserted at the store *and* the API).
- **The only write path is `connector.Apply`, reached only after the HITL gate.** Tier 0/1
  actions auto-apply; tier ≥ 2 queue at the desk for a human.
- **Every decision is signed** (auto-apply + human verdicts + incident open/resolve) into
  the ed25519 ledger; the GRC evidence pack uses the same scheme.
- **Secrets never sit in plaintext** when `TSENGINE_SECRET_KEY` is set: OAuth tokens are
  AES-256-GCM-sealed at the callback before they touch the store, and `SecretRef` is
  redacted by the API + console.
- **Grounding holds end to end**: the platform only asserts what the engine proved — a
  compliance gap exists because a real finding cites it; a remediation always carries its
  `FindingID`.

---

## 12. Operations

- **Persistence**: the file store (`TSENGINE_PLATFORM_DB`) is a single atomic JSON
  snapshot — back it up like any state file. It is single-node-durable; a sqlite/Postgres
  store is the scale-out successor behind the same interface.
- **The secret key** (`TSENGINE_SECRET_KEY`) decrypts every stored OAuth token — back it up
  securely and keep it stable; losing it orphans the sealed tokens (tenants must
  reconnect). A cloud-KMS vault is the production successor to the env-key MVP.
- **Shutdown** is graceful (SIGINT/SIGTERM drains in-flight requests + stops the
  scheduler).
- **Scaling note**: today's store + env-key vault target single-node. For HA, move to the
  Postgres store + KMS vault (both behind today's interfaces).
