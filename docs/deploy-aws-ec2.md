# Deploying tsengine on AWS EC2 (Docker)

The end-to-end runbook for a single EC2 instance running the whole product — engine on, TLS
terminated, secrets sealed. It assumes you have a domain you can point at the instance.

For the threat model behind these choices see [production-single-box.md](production-single-box.md);
this document is the operational path.

---

## 1. What you are deploying

Five containers on one box, orchestrated by `docker-compose.prod.yml`:

| Container | Role | Published? |
|---|---|---|
| `caddy` | TLS edge — the **only** public surface. Terminates HTTPS, sets security headers | **:80, :443** |
| `frontend` | Next.js console | no (internal `edge` network) |
| `platform` | Go API + engine orchestrator | no |
| `docker-socket-proxy` | Restricted Docker API, so the platform spawns sandboxes **without host root** | no |
| *(per-scan)* `sandbox` | Ephemeral, resource-capped container that runs the OSS tools | no |

The platform and frontend ports are deliberately unpublished — a request reaches them only
through Caddy.

---

## 2. Instance sizing

The sandbox runs real scanners (nuclei, trivy, semgrep, prowler…), which are memory-hungry.

| Workload | Instance | Disk |
|---|---|---|
| Evaluation / a few assets | `t3.large` (2 vCPU, 8 GB) | 40 GB gp3 |
| Production, small tenant base | `t3.xlarge` (4 vCPU, 16 GB) | 80 GB gp3 |

**Do not use a `t3.micro`/`small`.** The sandbox image alone is multi-GB and scans will OOM.

Disk matters more than it looks: the sandbox image, the tool corpora (nuclei templates, trivy
DB), and the threat-intel corpus all live on the instance volume.

---

## 3. Security group

Inbound — only these three:

| Port | Source | Why |
|---|---|---|
| 80 | `0.0.0.0/0` | **Required** for the Let's Encrypt HTTP-01 challenge. Caddy redirects to 443. |
| 443 | `0.0.0.0/0` | The product. |
| 22 | **your IP only** | Administration. Never `0.0.0.0/0`. |

Outbound: allow all. The engine must reach scan targets, provider APIs, and the KEV/EPSS feeds.

> Closing port 80 is the most common cause of "TLS won't provision". ACME validates over port 80;
> HTTPS alone is not enough for the initial issuance.

---

## 4. Host preparation

```bash
sudo dnf install -y docker git            # Amazon Linux 2023 (use apt on Ubuntu)
sudo systemctl enable --now docker
sudo usermod -aG docker "$USER"           # log out and back in for this to take effect
docker compose version                    # must be v2
```

Point an A record at the instance's **Elastic IP** — allocate one, because a stopped instance
loses its public IP and the certificate is bound to the name.

---

## 5. Configure

```bash
git clone https://github.com/ClatTribe/tsengine.git && cd tsengine
cp .env.example .env && chmod 600 .env
```

Edit `.env`. The deploy generates `TSENGINE_SECRET_KEY` and `TSENGINE_PLATFORM_TOKEN` if absent;
everything below is yours to set.

**Required for a public deploy**

```bash
TSENGINE_SITE_ADDRESS=app.yourdomain.com              # must match the DNS A record
TSENGINE_ACME_EMAIL=ops@yourdomain.com                # ACME contact; without it → self-signed
TSENGINE_PLATFORM_PUBLIC=https://app.yourdomain.com   # OAuth redirect_uri + webhook callbacks
```

**Strongly recommended** — each is a feature that is silently OFF if unset, which is exactly what
`--check` warns about:

```bash
SMTP_HOST=... SMTP_PORT=587 SMTP_USERNAME=... SMTP_PASSWORD=... SMTP_FROM=no-reply@yourdomain.com
GITHUB_CLIENT_ID=... GITHUB_CLIENT_SECRET=...     # at least one connector, or nobody can onboard
LLM_API_KEY=...                                    # else both AI agents fall back to the substrate
TSENGINE_WEBHOOK_SECRET=$(openssl rand -hex 32)    # else inbound webhooks are unverified
```

**Legal identity** — build-time, and required before you take real customers. These are inlined
into the bundle, so changing them later needs a frontend rebuild, not a restart:

```bash
NEXT_PUBLIC_LEGAL_ENTITY="Your Company Pvt Ltd"
NEXT_PUBLIC_LEGAL_JURISDICTION_CITY="Bengaluru"
NEXT_PUBLIC_SMTP_SUBPROCESSOR="Amazon SES"   # GDPR Art. 28(2) requires naming it
```

OAuth callback URLs to register with each provider:
`https://app.yourdomain.com/v1/connect/{github|gitlab|gworkspace|m365|okta}/callback`

---

## 6. Deploy

```bash
make prod-validate          # or: scripts/deploy-single-box.sh --check
```

`--check` is a real preflight, not a formality. It **fails hard** when the site address is a
public domain but `TSENGINE_ACME_EMAIL` is missing — you would otherwise serve a browser-rejected
self-signed cert — and warns for every capability that would be silently off.

```bash
make deploy-prod            # builds the sandbox image, brings the stack up, waits for /readyz
```

First run takes 10–20 minutes: the sandbox image bakes in every OSS tool.

Create the first workspace at `https://app.yourdomain.com/signup`.

---

## 7. Verify

```bash
curl -fsS https://app.yourdomain.com/readyz     # {"status":"ready","store":"ok"}
docker compose -f docker-compose.prod.yml ps    # all Up; platform "healthy"
```

`/readyz` reaches the store, so a green response means the box can actually serve a request —
unlike `/healthz`, which is static liveness only. Note the absence of `-k` above: if that
succeeds, TLS is genuinely trusted rather than the self-signed fallback.

Then prove the engine works end to end: add a container asset (e.g. `alpine:3.18`) and scan it.
Real CVE findings should appear. **Zero findings on `alpine:3.18` means something is wrong** —
the sandbox image did not build, or the socket proxy is misconfigured. Check
`docker compose -f docker-compose.prod.yml logs platform`.

---

## 8. Operating

**Backups.** `platform-data` holds the SQLite database *and* the ed25519 signing key — losing it
invalidates every signed evidence pack.

```bash
scripts/backup.sh /var/backups/tsengine
```

Schedule it and copy off-box (S3). If you move `TSENGINE_PLATFORM_DB` to a `postgres://` DSN the
script also `pg_dump`s the database and **fails loudly** if that dump fails — a volume-only backup
would otherwise capture almost nothing while reporting success.

**Upgrades.**

```bash
git pull && make deploy-prod     # take a backup first; data persists in the named volumes
```

**Logs and metrics.**

```bash
docker compose -f docker-compose.prod.yml logs -f platform
```

Prometheus metrics are on the platform's internal `:8090/metrics`. They are **not** routed through
Caddy and are **not** auth-gated — scrape them from inside the Docker network or a private
interface; do not publish that port.

---

## 9. Known limits at this scale

Honest boundaries of a single box. None block launch; all are the next step:

- **One instance, no HA.** A reboot is downtime. The store interface already supports Postgres
  (`TSENGINE_PLATFORM_DB=postgres://…` → RDS) when you outgrow SQLite.
- **Secrets are sealed with an env key**, not a cloud KMS. `internal/secret.Vault` is the seam a
  KMS implementation drops into.
- **Sandboxes are containers, not microVMs.** Hardened (cap-drop ALL, no-new-privileges,
  read-only rootfs, non-root, resource caps, isolated network) but not a hypervisor boundary.
- **Billing is contact-sales.** There is no self-serve checkout; an operator sets a tenant's plan
  via `POST /v1/tenants/{id}/plan` once payment is arranged.
