# Deploy: connect the Vercel frontend to a live backend

The frontend (`frontend/`) is deployed on Vercel (https://tsengine-zeta.vercel.app). It is a **shell
without the backend** — login, signup, the free scan, and every post-login page call the Go platform
API. Marketing pages render fine; anything dynamic shows empty states / "Sign-in failed" until the
backend is live and Vercel is pointed at it.

This is purely a **deployment** step — the code is release-ready. Two parts: deploy the backend, then
set one Vercel env var.

## 1. Deploy the backend (the Go platform API)

Deploy on **AWS EC2** with Docker — runs the backend **and** the live scanning engine on one box, with
the database in Supabase Postgres. Full runbook:
**[docs/deploy-aws-ec2-supabase.md](deploy-aws-ec2-supabase.md)**.

In short:
```bash
cp .env.example .env          # set TSENGINE_SECRET_KEY, TSENGINE_PLATFORM_TOKEN, and the DB (below)
make sandbox-image            # build the scanner sandbox image (engine)
make deploy-prod              # docker-compose.prod.yml: platform + Caddy TLS + docker-socket-proxy
# → https://app.<your-domain> with the engine ON
```

### Required backend env

| Var | Required? | Value |
|---|---|---|
| `TSENGINE_PLATFORM_TOKEN` | **yes** | any strong random string (operator/admin bearer) |
| `TSENGINE_SECRET_KEY` | strongly recommended | `openssl rand -base64 32` — without it, OAuth tokens are stored unsealed |
| `TSENGINE_PLATFORM_DB` | the one DB switch | **unset → local SQLite** (the "currently" path); a **`postgres://` DSN → Supabase/RDS/Neon** at deploy time. See `.env.example`. |
| `TSENGINE_PLATFORM_PUBLIC` | for OAuth | your HTTPS domain, e.g. `https://app.yourdomain.com` |

> **SQLite now → Postgres to deploy** is a single line: leave `TSENGINE_PLATFORM_DB` unset for durable
> local SQLite while building; set it to the Supabase DSN when you deploy (the backend auto-creates its
> schema and becomes stateless). Nothing else changes.

## 2. Point Vercel at the backend

Vercel project → **Settings → Environment Variables** (Production):

```
TSENGINE_API_URL      = https://app.yourdomain.com              # the backend from step 1 — REQUIRED
NEXT_PUBLIC_SITE_URL  = https://tsengine-zeta.vercel.app        # canonical/sitemap SEO
```

Then **redeploy** on Vercel (Deployments → Redeploy, or push to the connected branch) — env changes only
apply on a rebuild.

> CORS: none needed. The browser only calls Vercel's own `/api/*` routes, which call the backend
> server-side. The backend never sees the browser origin.

## 3. Smoke test (the go/no-go)

On the live site:
1. **Free scan** a domain → returns a questionnaire-readiness result (exercises the public `/v1/assess`).
2. **Sign up** → lands on the dashboard with empty-but-loading sections (no "Sign-in failed").
3. **Add an asset** + **Scan now** → real findings appear under Issues (proves the engine is running).

If sign-in fails: `TSENGINE_API_URL` is unset/wrong, the backend isn't reachable, or `TSENGINE_SECRET_KEY`
isn't set.
