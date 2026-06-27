# Deploy: Vercel (frontend) + Render/AWS (backend) + Supabase (Postgres)

This is the full production stack:

```
  Browser ──► Vercel (Next.js frontend)
                  │  server-side /api/* routes
                  ▼
            Backend: the Go platform API   ──►  Supabase Postgres
            (Render or AWS, Docker)              (durable, multi-node)
```

The frontend (`frontend/`) is already on Vercel. It's a shell until the backend is live and pointed at
Postgres. Three pieces, in order.

---

## 1. Supabase — the database

1. supabase.com → **New project**. Pick a region near your backend. Set a strong DB password.
2. Project → **Settings → Database → Connection string → URI**. Copy it; it looks like:
   ```
   postgresql://postgres:[YOUR-PASSWORD]@db.<project-ref>.supabase.co:5432/postgres
   ```
3. Append SSL (Supabase requires it):
   ```
   postgresql://postgres:[YOUR-PASSWORD]@db.<project-ref>.supabase.co:5432/postgres?sslmode=require
   ```
   This whole string is your **`TSENGINE_PLATFORM_DB`**. The backend auto‑creates its schema on first
   boot (no migrations to run). For a serverless/many‑instance backend, use Supabase's **connection
   pooler** host (Settings → Database → Connection pooling, port `6543`, *session* mode) instead of the
   direct `5432` host.

> The store routes by DSN: `store.Open()` sends a `postgres://`/`postgresql://` value to the Postgres
> impl (`internal/store/postgres.go`), which passes the same conformance suite as SQLite — so it's the
> identical behavior, just multi‑node‑capable.

---

## 2. The backend — Render **or** AWS

Both run `docker/platform/Dockerfile`. Required env for either:

| Var | Value |
|---|---|
| `TSENGINE_PLATFORM_DB` | the Supabase URI from step 1 (`postgresql://…?sslmode=require`) |
| `TSENGINE_PLATFORM_TOKEN` | a strong random string (operator bearer) |
| `TSENGINE_SECRET_KEY` | `openssl rand -base64 32` (seals OAuth tokens; must decode to 32 bytes) |
| `TSENGINE_PLATFORM_NO_ENGINE` | `1` (managed host — see "Engine note" below) |
| `TSENGINE_APP_URL` | `https://tsengine-zeta.vercel.app` |

With Postgres you **do not need a persistent disk** — the data lives in Supabase, so the backend is
stateless and can scale to multiple instances.

### Option A — Render

1. Render → **New → Blueprint** → connect this repo → **Apply** (uses `render.yaml`).
2. In the service → **Environment**: set `TSENGINE_PLATFORM_DB` to the Supabase URI and
   `TSENGINE_SECRET_KEY` to your `openssl` value. (The blueprint defaults `TSENGINE_PLATFORM_DB` to local
   SQLite — override it with the Supabase URI to use Postgres, and you can then drop the disk.)
3. Deploy → note the URL, e.g. `https://tsengine-platform.onrender.com`.
4. `curl https://<svc>.onrender.com/healthz` → `{"status":"ok"}`.

### Option B — AWS

Pick whichever you already run; all use the same image + env:

- **App Runner** (simplest): create a service from the image (push `docker/platform/Dockerfile` to ECR,
  or point App Runner at this repo). Port `8090` (or App Runner's `$PORT` — the server binds it
  automatically). Set the env vars above. Gives you an HTTPS URL out of the box.
- **ECS Fargate**: a task from the image, an ALB on `:8090` with `/healthz` as the health check, env
  via the task definition (put secrets in AWS Secrets Manager). Scale the service to N tasks — they all
  share the Supabase DB.
- **EC2 / single box** (if you want the **engine** too — see below): `docs/production-single-box.md`
  (`make deploy-prod`).

Build + push to ECR:
```bash
docker build -t <acct>.dkr.ecr.<region>.amazonaws.com/tsengine-platform:latest -f docker/platform/Dockerfile .
docker push <acct>.dkr.ecr.<region>.amazonaws.com/tsengine-platform:latest
```

### Engine note (`NO_ENGINE`)

On a managed host (Render, App Runner, Fargate) run with `TSENGINE_PLATFORM_NO_ENGINE=1`. The whole
product loop works — auth, dashboard, approvals, compliance, vendor/device/OSINT posture, the HITL desk.
**Live tech‑asset scanning** (nuclei/trivy/sqlmap/etc.) shells out to per‑scan Docker sandbox containers,
which a managed runtime can't host — for that, run the EC2/single‑box path (`docs/production-single-box.md`)
with the Docker socket, and unset `NO_ENGINE`. You can do both: managed backend for the app + a separate
worker box for scans, sharing the same Supabase DB.

---

## 3. Vercel — point the frontend at the backend

Vercel project → **Settings → Environment Variables** (Production):
```
TSENGINE_API_URL      = https://<your-backend-url>        # Render/AWS URL from step 2 — REQUIRED
NEXT_PUBLIC_SITE_URL  = https://tsengine-zeta.vercel.app  # canonical/sitemap SEO
```
Then **redeploy** (Deployments → Redeploy, or push to the connected branch). Env changes only take effect
on a rebuild.

> CORS: none needed — the browser only calls Vercel's own `/api/*` routes, which call the backend
> server‑side.

---

## 4. Smoke test (go/no‑go)

On the live site:
1. **Free scan** a domain → questionnaire‑readiness result (exercises the public `/v1/assess`).
2. **Sign up** → dashboard loads.
3. In Supabase → **Table editor**, confirm rows appear in `tenants` / `users` after sign‑up — that proves
   the backend is writing to Postgres.

If sign‑in fails: `TSENGINE_API_URL` is unset/wrong, the backend can't reach Supabase (check the DSN +
`sslmode=require`), or `TSENGINE_SECRET_KEY` isn't set.

---

## Why this stack

- **Vercel** — the Next.js frontend's native host (already deployed).
- **Render / AWS** — runs the stateless Go backend; scale horizontally (Postgres makes the backend
  stateless).
- **Supabase** — managed Postgres with backups + a dashboard; the backend's `store.Store` Postgres impl
  targets it directly. Swap to RDS/Neon/any Postgres by changing only `TSENGINE_PLATFORM_DB`.
