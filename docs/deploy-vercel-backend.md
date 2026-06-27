# Deploy: connect the Vercel frontend to a live backend

The frontend (`frontend/`) is deployed on Vercel (https://tsengine-zeta.vercel.app). It is a **shell
without the backend** — login, signup, the free scan, and every post-login page call the Go platform
API. Marketing pages render fine; anything dynamic shows empty states / "Sign-in failed" until the
backend is live and Vercel is pointed at it.

This is purely a **deployment** step — the code is release-ready. Two parts: deploy the backend, then
set one Vercel env var.

## 1. Deploy the backend (the Go platform API)

### Option A — Render (easiest, one click, managed)

`render.yaml` in the repo root is a Render Blueprint.

1. Render dashboard → **New → Blueprint** → connect this GitHub repo → **Apply**. Render builds
   `docker/platform/Dockerfile` and runs it with a 1 GB persistent disk.
2. In the new service → **Environment**, set the one secret the blueprint leaves blank:
   - `TSENGINE_SECRET_KEY` = output of `openssl rand -base64 32` (seals OAuth tokens at rest; must
     decode to 32 bytes).
   `TSENGINE_PLATFORM_TOKEN` is auto-generated; leave it.
3. Wait for the deploy → note the service URL, e.g. `https://tsengine-platform.onrender.com`.
4. Health check: `curl https://tsengine-platform.onrender.com/healthz` → `{"status":"ok"}`.

This runs in **NO_ENGINE** mode: auth, dashboard, approvals, compliance, vendor/device/OSINT posture,
and the whole HITL loop work. **Live tech-asset scanning** (nuclei/trivy/sqlmap/etc.) needs the sandbox
engine + a Docker host, which a managed PaaS can't give — use Option B for that.

### Option B — Single box with the engine (full product, Docker)

For live tech-asset scanning, deploy on one VM with Docker (see `docs/production-single-box.md`):

```bash
cp .env.example .env          # set TSENGINE_SECRET_KEY (openssl rand -base64 32) + TSENGINE_PLATFORM_TOKEN
make sandbox-image            # build the scanner sandbox
make deploy-prod              # docker-compose.prod.yml: platform + Caddy TLS + docker-socket-proxy
# → https://api.<your-domain> with the engine ON
```

### Required backend env (both options)

| Var | Required? | Value |
|---|---|---|
| `TSENGINE_PLATFORM_TOKEN` | **yes** | any strong random string (operator/admin bearer) |
| `TSENGINE_SECRET_KEY` | strongly recommended | `openssl rand -base64 32` — without it, OAuth tokens are stored unsealed |
| `TSENGINE_PLATFORM_DB` | yes | a path on a **persistent** volume, e.g. `/data/platform.db` (SQLite) |
| `TSENGINE_PLATFORM_NO_ENGINE` | Option A only | `1` |
| `TSENGINE_APP_URL` | for OAuth | the Vercel URL, `https://tsengine-zeta.vercel.app` |
| `PORT` | auto on PaaS | the server binds `$PORT` when set, else `:8090` |

## 2. Point Vercel at the backend

Vercel project → **Settings → Environment Variables** (Production):

```
TSENGINE_API_URL      = https://tsengine-platform.onrender.com   # the backend from step 1 — REQUIRED
NEXT_PUBLIC_SITE_URL  = https://tsengine-zeta.vercel.app         # canonical/sitemap SEO
```

Then **redeploy** on Vercel (Deployments → Redeploy, or push to the connected branch) — env changes only
apply on a rebuild.

> CORS: none needed. The browser only calls Vercel's own `/api/*` routes, which call the backend
> server-side. The backend never sees the browser origin.

## 3. Smoke test (the go/no-go)

On the live site:
1. **Free scan** a domain → returns a questionnaire-readiness result (exercises the public `/v1/assess`).
2. **Sign up** → lands on the dashboard with empty-but-loading sections (no "Sign-in failed").
3. **Connect** a system or post a snapshot → findings appear under Issues / Asset posture.

If sign-in fails: `TSENGINE_API_URL` is unset/wrong, the backend isn't reachable, or `TSENGINE_SECRET_KEY`
isn't set.
