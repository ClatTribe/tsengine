# Integrations — what we connect to, what we cannot, and what is worth building next

**Read this instead of grepping the codebase.** If it disagrees with the code, the code is right and
this file is a bug — fix it in the same PR, the way `arch.md` should have been and was not (see
`internal/archcheck`, added after a six-week doc drift cost a whole vulnerability class).

Last verified against the running platform: **2026-09-02**.

---

## 1. What actually connects today

**Ten OAuth connectors**, registered in `cmd/platform/main.go` and gated on their provider
credentials being configured. Each one discovers assets and scans them on a schedule.

| Category | Connectors | What it unlocks |
|---|---|---|
| **Code** | GitHub · GitLab · Bitbucket · Azure DevOps | SAST, SCA, leaked secrets, IaC, fix PRs |
| **Cloud** | AWS · GCP · Azure | CSPM, IAM blast radius, attack paths, drift |
| **Identity** | Google Workspace · Microsoft 365 · Okta | MFA gaps, OAuth grants, stale accounts, offboarding |

That is the cross-surface wedge — code, cloud and identity — and it is complete for the ICP's core.

**Five credential-configured sources** sit beside the OAuth connectors. They are not `Connection`
records (no OAuth consent screen — the customer pastes an API credential in Settings, sealed by the
vault) but they fetch live, on the Sync button and on every monitoring pass:

| Category | Sources | Package | What it unlocks |
|---|---|---|---|
| **Devices (MDM)** | Kandji · Jamf Pro · Microsoft Intune | `internal/mdm` → `internal/deviceposture` | laptop disk encryption, tampering, OS version — SOC 2 CC6.7, HIPAA 164.312(a)(2)(iv) |
| **People (HRIS)** | Merge.dev · Finch (unified APIs, fronting most HR products) | `internal/hris` | the joiner/leaver join: a leaver whose account is still enabled; an account no employee record explains — SOC 2 CC1.4, CC6.2, CC6.3 |

Intune with no token of its own borrows the onboarded Microsoft 365 connection's token (it needs
`DeviceManagementManagedDevices.Read.All`; a 403 is surfaced as itself). Each MDM fetcher declares the
settings its provider cannot report per device — Intune's device record says nothing about screen
lock, firewall, EDR or auto-update; Kandji enforces those through Library items and does not report
them — and the sync response carries that in `checks_not_run`. Read them: a fleet with zero findings
from Intune has said nothing about screen locks.

**`slack` is a declared connection kind but is NOT in the connector registry.** It is a notification
channel (an incoming webhook), not a scanned surface. Do not read the constant as coverage.

---

## 2. What arrives by posted snapshot, with no connector

These surfaces are fully assessed — same findings, same compliance mapping, same approval desk — but
**someone has to send us the data**. There is no OAuth flow that fetches it.

| Surface | Endpoint | Who sends it today |
|---|---|---|
| Device / MDM posture | `POST /v1/devices/ingest` | an MDM we do not fetch (Mosyle, Kolide, Fleet …) — Kandji / Jamf / Intune are fetched live, §1 |
| Vendor risk (TPRM) | `POST /v1/tprm/ingest` | export from procurement / a spreadsheet |
| Identity events (ITDR) | `POST /v1/identity/events` | IdP audit-log stream |
| SaaS configuration | `POST /v1/saas/{provider}/snapshot` | provider admin API |
| Cloud inventory | `POST /v1/cloud/inventory` | a CI job holding cloud creds |
| Kubernetes | `POST /v1/cloud/inventory?provider=kubernetes` | `kubectl` + a mapper |
| External exposure | `POST /v1/osint/ingest` | theHarvester / SpiderFoot output |
| Existing backlog | `POST /v1/import` | Snyk / Dependabot / any SARIF |

**GitHub org SaaS posture is the one exception** — `POST /v1/saas/github_org/sync` fetches live,
reusing the already-onboarded GitHub token. It is the template every other connector should copy: no
new credential, no new consent screen.

---

## 3. The gaps that actually matter for Series A/B

Ranked by how often they block a real deal, not by how interesting they are to build.

### 3.1 MDM / device posture — **BUILT (2026-09-02)**

Was: "highest value, lowest effort" — the assessment existed and the fetch did not. Now `internal/mdm`
reads Kandji, Jamf Pro and Intune (§1), configured at `PUT /v1/settings/mdm`, synced by
`POST /v1/devices/sync` and by `runner.syncDevices` every pass. What remains honest gaps, stated in the
code and in `checks_not_run` rather than silently: no fetcher sets `os_end_of_life` (there is no
vendor-support version table yet), Jamf reads computers only (mobile devices are a different
endpoint), and no MDM reports EDR presence or screen lock as device state — those stay "not assessed"
from a live sync. There is still **no endpoint agent of our own**; Oneleet ships one, and that is a
build-or-partner product decision, not a connector.

### 3.2 HRIS — **BUILT (2026-09-02)**

Was: "the one thing we have nothing for". Now `internal/hris` fetches the roster through Merge.dev or
Finch (one unified API each, deliberately not fifty HRIS integrations), stores it per source
(`Store.ReplaceEmployees`), and `Correlate` joins it against every connected identity provider's
accounts — on `POST /v1/hris/sync` and on every monitoring pass from the stored roster
(`OperateRunner.Employees`). The finding is the one this section promised: *"left in June, account
still enabled, holds an admin role"* at CRITICAL, promoting to the live HITL-gated suspend on Okta /
Google Workspace / M365 through the same path as a stale account. Identity is matched on email
equality against addresses the HRIS asserts — never a name, never a resemblance. What is NOT
inferred: onboarding timeliness (an account existing before a start date is not a defect), and
anything about an account the HRIS does not mention beyond "no record — record an owner" at low.

### 3.3 Amazon ECR — **advertised as "coming soon", and it reuses a credential we already hold**

`/integrations` lists Docker Hub and GHCR as live and ECR as coming soon. ECR needs no new
credential: the onboarded AWS role can list repositories and image digests, and
`internal/registrywatch` already does the digest-diff that decides what to re-scan.

### 3.4 Security training / background checks — **know that we do not, and say so**

KnowBe4-style training and Checkr-style background checks are standard Vanta/Drata integrations for
SOC 2 CC1.4. We have nothing, and there is no scanning story here — it is pure evidence collection.
Worth a deliberate decision rather than a silent gap: either integrate, or state plainly that this
part of CC1.4 is the customer's to evidence.

---

## 4. What we deliberately do not integrate

| | Why |
|---|---|
| **SIEM ingest** (pulling Splunk/Datadog alerts in) | We are not a SIEM. We export findings *to* yours as NDJSON. Triaging your logs is a different product. |
| **In-app firewall / RASP SDK** | Dropped as a product decision — it means shipping an SDK into the customer's app and supporting it per-runtime. We consume runtime events if a sensor posts them, and never claim to block. |
| **Fifty individual HRIS systems** | See 3.2 — a unified API is the right shape for this team's size. |

---

## 5. How to add a connector

1. Implement `connector.Connector` (OAuth `AuthURL`/`Exchange`, `Discover`, optionally `Watch`/`Apply`)
2. Register it in `cmd/platform/main.go`'s `connector.NewRegistry(...)`
3. Add the kind constant to `pkg/platform/types.go`
4. Add the card to `frontend/lib/connectors.ts`
5. Seal the token — the vault handles it at the callback; never store a raw token
6. **Update this file in the same PR**

Write scopes are opt-in and separate. A connector is read-only until a customer explicitly grants the
write scope for a fix path, and the desk still gates every apply.
