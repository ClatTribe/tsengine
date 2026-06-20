#!/usr/bin/env bash
# One-command PRODUCTION single-box deploy (docs/production-single-box.md §7).
#
# Brings up the hardened stack from docker-compose.prod.yml: the TLS edge (Caddy), the
# de-privileged Docker socket-proxy, the platform + frontend (unpublished), and the engine
# ON so real OSS-tool scans run in isolated, hardened sandboxes.
#
#   scripts/deploy-single-box.sh           # full deploy
#   scripts/deploy-single-box.sh --check   # prereqs + config validation only (no build/up)
#
# Idempotent: re-running re-builds + rolls the stack; it never regenerates an existing .env.
set -euo pipefail

cd "$(dirname "$0")/.."

CHECK_ONLY=0
[ "${1:-}" = "--check" ] && CHECK_ONLY=1

SITE_ADDRESS="${TSENGINE_SITE_ADDRESS:-localhost}"
COMPOSE=(docker compose -f docker-compose.prod.yml)

say() { printf '\033[1;36m▸ %s\033[0m\n' "$*"; }
die() { printf '\033[1;31m✗ %s\033[0m\n' "$*" >&2; exit 1; }

# --- 1. prerequisites ---
say "checking prerequisites"
command -v docker >/dev/null || die "docker is required"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required (got: $(docker --version))"
command -v openssl >/dev/null || die "openssl is required (to generate secrets)"
docker info >/dev/null 2>&1 || die "the docker daemon is not reachable"

# --- 2. secrets / .env (generated once, never overwritten) ---
if [ ! -f .env ]; then
  if [ "$CHECK_ONLY" = 1 ]; then
    say ".env absent (would be generated on a real deploy)"
  else
    say "generating .env with fresh secrets"
    umask 077
    {
      echo "# tsengine production secrets — generated $(date -u +%FT%TZ). Keep private; back up."
      echo "TSENGINE_SECRET_KEY=$(openssl rand -base64 32)"
      echo "TSENGINE_PLATFORM_TOKEN=$(openssl rand -hex 24)"
      echo "TSENGINE_SITE_ADDRESS=${SITE_ADDRESS}"
    } > .env
    chmod 600 .env
    echo "  → wrote .env (chmod 600)"
  fi
else
  say ".env present — reusing existing secrets"
fi

# --- 3. validate the hardened stack config (no secrets needed) ---
say "validating docker-compose.prod.yml + Caddyfile"
TSENGINE_SECRET_KEY=validate TSENGINE_PLATFORM_TOKEN=validate "${COMPOSE[@]}" config -q \
  || die "docker-compose.prod.yml is invalid"
docker run --rm -e TSENGINE_SITE_ADDRESS="$SITE_ADDRESS" \
  -v "$(pwd)/docker/caddy/Caddyfile:/etc/caddy/Caddyfile:ro" \
  caddy:2-alpine caddy validate --config /etc/caddy/Caddyfile --adapter caddyfile >/dev/null 2>&1 \
  || die "Caddyfile is invalid"
echo "  → config valid"

if [ "$CHECK_ONLY" = 1 ]; then
  say "--check passed (prereqs + config OK); skipping build/up"
  exit 0
fi

# --- 4. build the OSS-tool sandbox image (the engine needs it) ---
say "building the sandbox image (OSS scan tools)"
make sandbox-image

# --- 5. bring up the hardened stack ---
say "starting the hardened stack"
"${COMPOSE[@]}" up --build -d

# --- 6. smoke test via the TLS edge (-k: the default uses Caddy's internal CA) ---
say "waiting for the edge to become healthy"
ok=0
for _ in $(seq 1 45); do
  if curl -fsSk "https://${SITE_ADDRESS}/healthz" >/dev/null 2>&1; then ok=1; break; fi
  sleep 2
done
[ "$ok" = 1 ] || die "edge not healthy after 90s — inspect: ${COMPOSE[*]} logs"

say "deployed ✓  →  https://${SITE_ADDRESS}/   (create the first workspace at /signup)"
echo "   backups:  scripts/backup.sh   ·   logs: ${COMPOSE[*]} logs -f"
