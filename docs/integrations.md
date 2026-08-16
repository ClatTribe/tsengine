# Integrations — what we connect to, what we cannot, and what is worth building next

**Read this instead of grepping the codebase.** If it disagrees with the code, the code is right and
this file is a bug — fix it in the same PR, the way `arch.md` should have been and was not (see
`internal/archcheck`, added after a six-week doc drift cost a whole vulnerability class).

Last verified against the running platform: **2026-08-16**.

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

**`slack` is a declared connection kind but is NOT in the connector registry.** It is a notification
channel (an incoming webhook), not a scanned surface. Do not read the constant as coverage.

---

## 2. What arrives by posted snapshot, with no connector

These surfaces are fully assessed — same findings, same compliance mapping, same approval desk — but
**someone has to send us the data**. There is no OAuth flow that fetches it.

| Surface | Endpoint | Who sends it today |
|---|---|---|
| Device / MDM posture | `POST /v1/devices/ingest` | a script against your MDM's API |
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

### 3.1 MDM / device posture — **highest value, lowest effort**

SOC 2 CC6.7 asks whether laptops are encrypted. We can already *assess* that
(`internal/deviceposture` — disk encryption, screen lock, OS support, EDR, firewall) and we already
report honestly which checks a submission could not answer. What is missing is the fetch.

**How to get it:** Kandji, Jamf Pro, and Intune all expose a REST device inventory behind an API
token or OAuth client-credentials. The work is one `Fetcher` per provider with the same shape as
`operate.GWorkspace.Fetch` — auth, page, map to `deviceposture.Device`, hand to the existing ingest.
The assessment, compliance mapping and UI already exist, so this is genuinely a connector and nothing
else.

### 3.2 HRIS — **the one thing we have nothing for**

Vanta and Drata both lead with it, because employee onboarding/offboarding is the evidence an auditor
asks for first: was access granted on a start date, and removed on a leave date (SOC 2 CC1.4, CC6.2).
We can see *accounts* through the IdP, but we cannot see *employment* — so we cannot tell a
contractor from a leaver from a service account.

**How to get it:** do not build fifty HRIS integrations. **Merge.dev** and **Finch** are unified HRIS
APIs — one integration covers most of the market, which is how competitors got breadth with small
teams. A single `Fetcher` produces employee records; joining them to IdP accounts is then a
deterministic correlation on the host, exactly like `crossdetect`.

That correlation is also the interesting product bit: *"this person left in June and still has an
admin role"* is a much stronger finding than either source alone, and it falls straight out of the
join.

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
