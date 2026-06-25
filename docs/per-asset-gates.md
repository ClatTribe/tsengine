# Per-asset gates & buckets — what's live, what we fixed, what's configurable, what's gated

This is the consolidated answer to: *for each asset type, what are the gates/stubs to go live
end-to-end on one machine securely via Docker, and which of those did **we fix** (Bucket A), which
are **customer configuration via UX** (Bucket B), and which are an **operator/deployment decision**
(Bucket C)?*

It is descriptive — the implementation lives in the engine (§1–§17) and the platform (§18) of
[CLAUDE.md](../CLAUDE.md). Where a row says "gated", that is the **honest boundary**: it needs a real
provider credential or a deployed target and cannot be made live on a single laptop without one.

---

## The three buckets

| Bucket | Meaning | Who acts | Where it lives |
|---|---|---|---|
| **A — WE FIX** | Our missing code/stubs the customer should never see | us | engine / platform code |
| **B — EXPOSE AS CONFIG** | The customer's own secret/decision, surfaced via sealed per-tenant UX | the customer | `Settings` + `/v1/settings/*`, `Asset.Meta`, `Connection.Config` |
| **C — OPERATOR / DEPLOYMENT** | Build/run decisions for the deployment | the operator | env vars, `make demo-secure`, `deploy-prod` |

**Decision test:** *"Could we ship this working for every customer without asking them for anything?"*
Yes → Bucket A. No, it needs their secret/consent/account → Bucket B. It's an infra/deploy choice → Bucket C.

---

## Bucket C — secure local scanning via Docker (the operator path)

The scan-execution boundary is the **hardened sandbox container** (`tsengine/sandbox:0.1.0`, every OSS
scanner baked in). The host has no scanner binaries by design; each scan runs in a sandbox with a
read-only rootfs, an isolated no-egress network, and resource/PID caps. Loopback targets are rewritten
to `host.docker.internal` so a scan can reach a local target.

- **`make demo-secure`** — brings up the demo (one asset of every type) with the **engine ON** and
  hardened sandboxes. (`scripts/demo-secure.sh`)
- **`make demo-scan-asset`** — proves the path per asset type with one-shot CLI scans, no creds.
  (`scripts/demo-scan-asset.sh`)
- **`make deploy-prod`** — the fully hardened containerized posture (docker-socket-proxy so there is no
  raw socket, Caddy TLS edge).

---

## Per-asset matrix

| Asset | Runs locally in the sandbox, no creds? | Bucket A (we fixed) | Bucket B (customer config via UX) | Honest gate |
|---|---|---|---|---|
| **repository** | ✅ **proven** — single-stage (gitleaks/semgrep/trivy/grype/osv/checkov/hadolint/syft); planted secret caught by 4 tools + command-injection by semgrep (#387) | PR-review bot (`internal/prbot`) builds inline comments + merge-gating check-run | PR-bot policy `GET/PUT /v1/settings/pr-bot` | live GitHub **post** needs the GitHub App PR-write scope |
| **container_image** | ✅ **proven** — single-stage (trivy/grype/dockle/syft/cosign); `alpine:3.18` → 27 real CVEs (#383) | registry scan-on-push reconcile (`internal/registrywatch`) | registry connection | live registry listing (e.g. ECR) needs the registry/cloud creds |
| **web_application** | ✅ **proven** — recon→fan-out (katana→nuclei/dalfox/sqlmap/httpx→OAST/ffuf); local exposed-`/.git/` target (#392) | authenticated-scan reliability core (`internal/webauth`) | login-flow `POST /v1/assets/{id}/login-flow` (sealed) | a reachable **target URL** (provide it); live authed replay |
| **api** | ✅ **proven** — spec-ingest → per-method fan-out; scanned a local VAmPI (16-operation OpenAPI spec) → `openapi_spec_ingest` + schemathesis + nuclei + kiterunner all fanned out in the sandbox | BOLA/BFLA authz differential (`internal/apiauthz`) | authz-test `POST /v1/assets/{id}/authz-test` (sealed) | a reachable API + OpenAPI spec; the deeper **business-logic** authz vulns (BOLA/BFLA) need the gated `apiauthz` active prober — generic schemathesis/nuclei fuzzing surfaces only spec/conformance issues |
| **ip_address** | ✅ same sandbox path (naabu port discovery → per-port nuclei) | — | — | a reachable **target IP/CIDR** |
| **domain** | ✅ same sandbox path (subfinder/amass/crt.sh → child-asset pivot) | — | — | a real **domain** (DNS reachable) |
| **cloud_account** | ⛔ needs read-only cloud creds (prowler) | live remediation writers **AWS/GCP/Azure** public-storage (`*remediate` SDK packages) | **cloud-remediation role** `POST /v1/connections/{id}/cloud-remediation` (#386) + the cloud connection (read-only scan creds) | the customer's **cloud account + cross-account role** |
| **identity** (workspace) | ✅ host-side (operate, LLM-free) — Workspace/M365/Okta snapshot → grounded findings | live **account-suspend** writers for **Okta + Google Workspace + M365** (#385 + prior Okta) | provider OAuth onboarding + the IdP **write scope** | a connected IdP + the admin-granted write scope |
| **SaaS posture** | ✅ host-side (sspm, LLM-free) — snapshot ingest `POST /v1/saas/{provider}/snapshot` (#382) | **live GitHub-org fetcher** reusing the onboarded token (#389) + **autonomous** sync each monitoring pass (#390) | provider OAuth (the connection) | other providers' live fetchers (Slack/Zoom/Atlassian/Salesforce) need that provider's admin token |

### Cross-cutting Bucket-B config (notification / ticketing destinations)

| Destination | What | Endpoint + UX |
|---|---|---|
| **Slack** | per-tenant incident webhook, sealed; `notify.TenantRouter` routes each tenant's incidents to its own channel (operator channels = fallback) | `GET/PUT /v1/settings/notifications` + Settings (#388) |
| **Jira** | per-tenant ticketing destination, token sealed; `remediate.TenantFiler` routes each `file_ticket` to the tenant's own project (operator tracker = fallback) | `GET/PUT /v1/settings/jira` + Settings (#391) |

---

## What "proven" means

`make demo-scan-asset` runs, with **no external credentials**, on this machine:

- `container_image` — `alpine:3.18` → 27 real CVE findings (grype/trivy).
- `repository` — a generated tree with a planted secret + command injection → 7 findings; the secret is
  caught by semgrep + gitleaks + trufflehog + trivy (4-tool corroboration), the injection by semgrep.
- `web_application` — a throwaway local nginx exposing `/.git/` → the full recon→fan-out pipeline runs
  and ffuf content-discovery surfaces the exposed `/.git/`. All info-severity: a static target has the
  exposed path but no injectable backend, so the engine reports what's there and **invents no
  high-severity finding** (grounded — detection *and* no false positives).

- `api` — a local **VAmPI** (a deliberately-vulnerable API) → `openapi_spec_ingest` fetched its OpenAPI
  spec and ingested **16 operations** as the surface, then schemathesis (spec-driven fuzz) + nuclei +
  kiterunner all fanned out per-method in the sandbox. The L1 anchors surfaced info-level findings (the
  exposed spec); VAmPI's headline **BOLA/auth** bugs are business-logic authz issues that the gated
  `apiauthz` differential test handles, not generic fuzzing — so the *pipeline* is proven end-to-end
  even though a high-severity finding needs the consent-gated active path. VAmPI is a heavy image, so
  this proof is run ad-hoc (not baked into `make demo-scan-asset`).

`ip_address`/`domain` use the **same** recon→fan-out orchestrator path as `web_application`/`api`; they
differ only in the recon shape and need a reachable target of that kind.

---

## The honest boundary

`cloud_account` (read-only cloud creds), the per-provider **SaaS live fetchers** beyond GitHub, the
**identity write paths** (gated on the IdP write scope), and live `web`/`api`/`ip`/`domain` scans
(reachable target) cannot be exercised end-to-end on one laptop without a real provider credential or a
deployed target. Those are the gates we **identify** rather than fake — the engine surfaces the
provider's own error (e.g. a 403 for an ungranted scope) and never reports a false success (§10).
