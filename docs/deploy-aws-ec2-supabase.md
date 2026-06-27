# Deploy: AWS EC2 (backend + engine) + Supabase (Postgres) + Vercel (frontend)

This runs the **full product on one EC2 box**: the platform backend **and** the live tech‑asset scanning
engine (nuclei/trivy/sqlmap/… in per‑scan sandbox containers), with data in **Supabase Postgres** and the
**frontend on Vercel**.

```
  Browser ──► Vercel (frontend)
                  │ server-side /api/*
                  ▼
   ┌──────────── EC2 (Docker) ─────────────┐        ┌──────────────┐
   │ Caddy (TLS :443) → platform + frontend │  ───►  │  Supabase    │
   │ platform ── docker-socket-proxy ──► per│        │  Postgres    │
   │ scan sandbox containers (isolated net) │        └──────────────┘
   └────────────────────────────────────────┘
```

Why one box with the engine: live scanning shells out to Docker sandbox containers (CLAUDE.md §12), which
managed PaaS can't host. EC2 gives you a real Docker host, so the engine runs. Supabase keeps the *data*
durable + managed (and lets you add more boxes later — the backend is stateless on Postgres).

---

## 0. Prerequisites

- An AWS account, a domain you can point at the box (for HTTPS), and a Supabase project.
- **Supabase**: Settings → Database → Connection string (URI). Add `?sslmode=require`. This is your
  `TSENGINE_PLATFORM_DB`:
  ```
  postgresql://postgres:PASSWORD@db.<ref>.supabase.co:5432/postgres?sslmode=require
  ```

---

## 1. Launch the EC2 instance

- **AMI:** Ubuntu 22.04 LTS (or Amazon Linux 2023).
- **Type:** `t3.large` minimum (2 vCPU / 8 GB) — scanning is CPU/RAM hungry and pulls large tool images.
  `t3.xlarge` if you'll run many concurrent scans.
- **Storage:** root EBS **50 GB gp3** (the sandbox image + pulled scan targets need disk).
- **Security group (inbound):**
  | Port | Source | Why |
  |---|---|---|
  | 22 | your IP only | SSH |
  | 80 | 0.0.0.0/0 | HTTP → Caddy (ACME + redirect to 443) |
  | 443 | 0.0.0.0/0 | HTTPS → the app |

  Do **not** open 8090/3000 — the backend + frontend are reachable only via Caddy on the internal Docker
  network.
- **DNS:** point an A record (e.g. `app.yourdomain.com`) at the instance's Elastic IP (allocate one so the
  IP is stable).

---

## 2. Install Docker

SSH in, then:
```bash
sudo apt-get update && sudo apt-get install -y docker.io docker-compose-plugin git make
sudo usermod -aG docker $USER && newgrp docker      # run docker without sudo
docker --version && docker compose version           # sanity
```

---

## 3. Get the code + configure

```bash
git clone https://github.com/ClatTribe/tsengine.git && cd tsengine
cp .env.example .env
```

Edit `.env`:
```bash
TSENGINE_SECRET_KEY=$(openssl rand -base64 32)          # paste the value
TSENGINE_PLATFORM_TOKEN=$(openssl rand -hex 32)          # paste the value
# Supabase Postgres (the whole point — data is managed, the box is replaceable):
TSENGINE_PLATFORM_DB=postgresql://postgres:PASSWORD@db.<ref>.supabase.co:5432/postgres?sslmode=require
# HTTPS domain (Caddy gets a real cert via ACME):
TSENGINE_SITE_ADDRESS=app.yourdomain.com
TSENGINE_ACME_EMAIL=you@yourdomain.com
TSENGINE_PLATFORM_PUBLIC=https://app.yourdomain.com
```
Also drop `tls internal` from `docker/caddy/Caddyfile` so Caddy uses public ACME (Let's Encrypt) instead of
its localhost CA.

> The five vars above are the **minimum**. For a full launch also fill in the grouped sections in
> `.env.example`: **SMTP_\*** (so password‑reset + invite emails actually send — unset just logs the link),
> **LLM_\*** (the AI brief + L2 agents — unset turns AI features off), and the **connector OAuth** pairs
> (GitHub/GitLab/Okta/M365/…) for the systems you want customers to connect. Each is optional and degrades
> honestly if blank.

> With `TSENGINE_PLATFORM_DB` set to the Supabase DSN, the box no longer needs its data disk — all state is
> in Supabase. (The compose still mounts a `platform-data` volume; it just goes unused for the DB.)

---

## 4. Build the sandbox image + bring the stack up (engine ON)

```bash
make sandbox-image          # builds tsengine/sandbox:<tag> — the OSS-tool image the engine spawns (~minutes)
make deploy-prod            # docker-compose.prod.yml: Caddy(TLS) + platform(engine ON) + frontend + socket-proxy
```
`docker-compose.prod.yml` already sets `TSENGINE_PLATFORM_NO_ENGINE=0` (engine on) and routes sandbox spawns
through the de‑privileged `docker-socket-proxy` (the platform never holds the raw Docker socket — threat T3).

Verify:
```bash
docker compose -f docker-compose.prod.yml ps           # all healthy
curl -fsS https://app.yourdomain.com/healthz            # {"status":"ok"}
```

---

## 5. Point Vercel at the box

Vercel project → Settings → Environment Variables (Production):
```
TSENGINE_API_URL      = https://app.yourdomain.com
NEXT_PUBLIC_SITE_URL  = https://tsengine-zeta.vercel.app
```
Then redeploy on Vercel.

> You now have the frontend in **two** places: on Vercel (your public marketing + app domain) *and* served
> by Caddy on the EC2 box. Pick one as canonical. If Vercel is canonical, you can run the EC2 stack
> backend‑only (still fine — Caddy routes `/v1` to the platform; the EC2 frontend is just unused).

---

## 6. Smoke test — including a real scan

1. **Sign up** on the live site → dashboard loads.
2. Supabase → Table editor → confirm rows in `tenants` / `users` (proves Postgres is wired).
3. **Add an asset** (e.g. a container image `alpine:3.18` or a web URL) → **Scan now**. Within a minute,
   real findings appear under Issues — that proves the **engine** is running (the box is spawning sandbox
   containers). `docker ps` during a scan shows a transient `tsengine/sandbox` container.

---

## 7. Operate

- **Logs:** `docker compose -f docker-compose.prod.yml logs -f platform`
- **Update:** `git pull && make deploy-prod` (rebuilds + restarts; data is safe in Supabase).
- **Backups:** Supabase does automated Postgres backups (Settings → Database → Backups). No box‑side DB
  backup needed since the DB is remote.
- **Scale later:** because the data is in Supabase, you can run a second EC2 box (or an ECS service) against
  the same `TSENGINE_PLATFORM_DB` and put both behind a load balancer — the backend is stateless.

## Troubleshooting

| Symptom | Cause / fix |
|---|---|
| "Sign‑in failed" on the live site | `TSENGINE_API_URL` wrong, or the box can't reach Supabase — check the DSN + `sslmode=require`, and `curl https://app.yourdomain.com/healthz`. |
| Scans produce 0 findings | sandbox image not built (`make sandbox-image`), or `TSENGINE_PLATFORM_NO_ENGINE` was forced to `1`. Check `docker compose logs platform` for `NO_ENGINE mode`. |
| Caddy cert errors | DNS A record not pointing at the box yet, port 80 closed (ACME needs it), or `tls internal` still in the Caddyfile. |
| Postgres connect refused | Supabase requires SSL — keep `?sslmode=require`; for many instances use the Supabase pooler host (port 6543, session mode). |
