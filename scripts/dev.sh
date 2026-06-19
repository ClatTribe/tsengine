#!/usr/bin/env bash
#
# dev.sh — bring up the full Sentinel demo stack locally, reliably.  →  `make dev`
#
# Starts the platform API (seeded with demo data) + the Next.js frontend, and ALWAYS
# clears the Next build cache first so styling can never go stale. Idempotent: re-run any
# time the local app looks broken or "unstyled".
#
#   make dev            # or: ./scripts/dev.sh
#   → sign in at http://localhost:3000/login · founder@northwind.io / sentinel123 (or /signup)
#   make dev-down       # stop the stack
#
# ──────────────────────────────────────────────────────────────────────────────────────
# WHY STYLING GOES STALE (the root cause this script + `make dev` exist to prevent):
# `next dev` serves CSS from .next/static/css/<hash>; `next build` (the PRODUCTION build)
# OVERWRITES that same .next with differently-hashed chunks. So running `next build` while
# the dev server is live makes the running page reference a chunk the build deleted → the
# CSS 404s and the app renders UNSTYLED. RULE: never `next build` against a live dev
# server's .next. To type-check the frontend without clobbering it, use:
#       npm --prefix frontend exec tsc -- --noEmit
# and run `next build` only in CI / a clean checkout. This script clears .next on every
# start so a stale cache can't carry over between runs.
# ──────────────────────────────────────────────────────────────────────────────────────
#
# Dev-only. NO_ENGINE mode (no Docker sandbox); the seeded store shows the full UX.
set -euo pipefail
cd "$(dirname "$0")/.."

DB="${TSENGINE_PLATFORM_DB:-/tmp/tsengine-demo.json}"
API_PORT=8090
WEB_PORT=3000

# kill_port <port> — free a TCP port regardless of what holds it (a built binary, a
# `go run` temp child, or a stray next-server). More robust than pkill-by-name.
kill_port() { local p="$1"; local pids; pids=$(lsof -nP -iTCP:"$p" -sTCP:LISTEN -t 2>/dev/null || true); [ -n "$pids" ] && kill -9 $pids 2>/dev/null || true; }

echo "→ stopping any stale dev servers (ports $API_PORT, $WEB_PORT)"
pkill -f 'next dev' 2>/dev/null || true
pkill -f 'next-server' 2>/dev/null || true
kill_port "$API_PORT"
kill_port "$WEB_PORT"
sleep 1

echo "→ building platform + seeding demo data ($DB)"
go build -o platform ./cmd/platform
[ -f "$DB" ] || go run ./cmd/seed-demo "$DB"

echo "→ starting platform API on :$API_PORT (logs → /tmp/platform.log)"
TSENGINE_PLATFORM_TOKEN="${TSENGINE_PLATFORM_TOKEN:-dev-token}" \
TSENGINE_PLATFORM_NO_ENGINE=1 \
TSENGINE_PLATFORM_DB="$DB" \
TSENGINE_SECRET_KEY="${TSENGINE_SECRET_KEY:-$(openssl rand -base64 32)}" \
TSENGINE_MONITOR_INTERVAL=0 \
  ./platform > /tmp/platform.log 2>&1 &
sleep 2

echo "→ clearing Next cache (prevents stale CSS) + starting frontend on :$WEB_PORT"
rm -rf frontend/.next
echo
echo "  ┌──────────────────────────────────────────────────────────────┐"
echo "  │  Sign in:  http://localhost:$WEB_PORT/login                        │"
echo "  │  email: founder@northwind.io   ·   password: sentinel123      │"
echo "  │  …or create a fresh workspace at /signup                      │"
echo "  └──────────────────────────────────────────────────────────────┘"
echo
# the frontend calls the API server-side; point it at the local platform explicitly.
TSENGINE_API_URL="http://localhost:$API_PORT" exec npm --prefix frontend run dev
