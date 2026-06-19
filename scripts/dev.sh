#!/usr/bin/env bash
#
# dev.sh — bring up the full Sentinel demo stack locally, reliably.
#
# Starts the platform API (seeded with demo data) + the Next.js frontend, and ALWAYS
# clears the Next build cache first so styling can never go stale (a long-running dev
# server occasionally drops its compiled CSS chunk → the app renders unstyled). Idempotent:
# re-run it any time the local app looks broken or "unstyled".
#
#   ./scripts/dev.sh
#   → sign in at http://localhost:3000/login  ·  founder@northwind.io / sentinel123  (or /signup)
#
# Dev-only. NO_ENGINE mode (no Docker sandbox); the seeded store shows the full UX.
set -euo pipefail
cd "$(dirname "$0")/.."

DB="${TSENGINE_PLATFORM_DB:-/tmp/tsengine-demo.json}"

echo "→ stopping any stale dev servers"
pkill -x platform 2>/dev/null || true       # the built ./platform binary (exact name)
pkill -f 'next dev' 2>/dev/null || true
pkill -f 'next-server' 2>/dev/null || true
sleep 1

echo "→ building platform + seeding demo data ($DB)"
go build -o platform ./cmd/platform
[ -f "$DB" ] || go run ./cmd/seed-demo "$DB"

echo "→ starting platform API on :8090 (logs → /tmp/platform.log)"
TSENGINE_PLATFORM_TOKEN="${TSENGINE_PLATFORM_TOKEN:-dev-token}" \
TSENGINE_PLATFORM_NO_ENGINE=1 \
TSENGINE_PLATFORM_DB="$DB" \
TSENGINE_SECRET_KEY="${TSENGINE_SECRET_KEY:-$(openssl rand -base64 32)}" \
TSENGINE_MONITOR_INTERVAL=0 \
  ./platform > /tmp/platform.log 2>&1 &
sleep 2

echo "→ clearing Next cache (prevents stale CSS) + starting frontend on :3000"
rm -rf frontend/.next
echo
echo "  ┌──────────────────────────────────────────────────────────────┐"
echo "  │  Sign in:  http://localhost:3000/login                        │"
echo "  │  email: founder@northwind.io   ·   password: sentinel123      │"
echo "  │  …or create a fresh workspace at /signup                      │"
echo "  └──────────────────────────────────────────────────────────────┘"
echo
exec npm --prefix frontend run dev
