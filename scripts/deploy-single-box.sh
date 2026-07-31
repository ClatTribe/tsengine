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

# --- 2b. public-deploy preflight -------------------------------------------
# Everything below is a MISCONFIGURATION THAT ONLY BITES IN PRODUCTION, and whose failure mode
# is quiet: a browser-untrusted cert, a customer who cannot connect anything, an AI agent that
# silently degrades to the deterministic substrate. Catching them here is the whole point of
# --check. Hard errors are things that make the deploy wrong; warnings are things you can
# legitimately defer.
warn() { printf '\033[1;33m! %s\033[0m\n' "$*"; WARNED=1; }
WARNED=0

# Read a key from .env without sourcing it (values may contain spaces/specials).
envget() { [ -f .env ] && grep -E "^$1=" .env | tail -1 | cut -d= -f2- || true; }

IS_PUBLIC=0
case "$SITE_ADDRESS" in
  localhost|127.0.0.1|"") ;;
  *[!0-9.]*) IS_PUBLIC=1 ;;   # has a non-numeric char → a hostname, not a bare IP
esac

if [ "$IS_PUBLIC" = 1 ]; then
  say "public domain detected ($SITE_ADDRESS) — checking TLS + identity"
  ACME_EMAIL="${TSENGINE_ACME_EMAIL:-$(envget TSENGINE_ACME_EMAIL)}"
  if [ -z "$ACME_EMAIL" ]; then
    die "TSENGINE_SITE_ADDRESS is a public domain but TSENGINE_ACME_EMAIL is unset.
     Without it the edge serves a SELF-SIGNED cert that every browser rejects.
     Set TSENGINE_ACME_EMAIL=ops@${SITE_ADDRESS#*.} in .env and re-run."
  fi
  # Hand the ACME contact to the Caddyfile's `tls` directive (see docker/caddy/Caddyfile).
  export TSENGINE_TLS="$ACME_EMAIL"
  echo "  → TLS: automatic Let's Encrypt (contact $ACME_EMAIL)"

  # Let's Encrypt validates over HTTP/HTTPS, so DNS must already resolve to this box.
  if command -v getent >/dev/null 2>&1 || command -v dig >/dev/null 2>&1; then
    RESOLVED="$( (getent hosts "$SITE_ADDRESS" 2>/dev/null || dig +short "$SITE_ADDRESS" 2>/dev/null) | head -1 )"
    [ -z "$RESOLVED" ] && warn "$SITE_ADDRESS does not resolve yet — Let's Encrypt will fail until DNS points at this instance (EC2: allow inbound 80 AND 443)."
  fi

  # Legal identity is load-bearing for a public, customer-facing deploy.
  [ -z "$(envget NEXT_PUBLIC_LEGAL_ENTITY)" ] && \
    warn "NEXT_PUBLIC_LEGAL_ENTITY is unset — Terms/Privacy will publish without naming the contracting entity (see .env.example §8; requires a frontend rebuild to change)."
  [ -z "$(envget NEXT_PUBLIC_LEGAL_JURISDICTION_CITY)" ] && \
    warn "NEXT_PUBLIC_LEGAL_JURISDICTION_CITY is unset — the Terms will omit the governing-forum clause."
else
  echo "  → TLS: internal self-signed CA (no public domain configured)"
fi

# Capability warnings — each of these means a feature is silently OFF in production.
[ -z "$(envget SMTP_HOST)" ] && \
  warn "SMTP_HOST is unset — password resets and email invites will not be delivered."
[ -z "$(envget LLM_API_KEY)$(envget LLM_BASE_URL)" ] && \
  warn "no LLM configured — the AI Security Engineer and AI Pentester will degrade to the deterministic substrate."
if [ -z "$(envget GITHUB_CLIENT_ID)$(envget GITLAB_CLIENT_ID)$(envget GWORKSPACE_CLIENT_ID)$(envget M365_CLIENT_ID)$(envget OKTA_CLIENT_ID)" ]; then
  warn "no OAuth connector is configured — customers will not be able to connect any system (see .env.example §3)."
fi
[ -z "$(envget TSENGINE_WEBHOOK_SECRET)" ] && \
  warn "TSENGINE_WEBHOOK_SECRET is unset — inbound webhooks are accepted UNVERIFIED (spoofable)."

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
  if [ "$WARNED" = 1 ]; then
    say "--check passed with warnings above (config is VALID; some features will be off)"
  else
    say "--check passed (prereqs + config OK); skipping build/up"
  fi
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
  # /readyz, not /healthz: the latter is static and would report success even if the store
  # never came up, so the deploy would "succeed" onto a box that cannot serve a request.
  if curl -fsSk "https://${SITE_ADDRESS}/readyz" >/dev/null 2>&1; then ok=1; break; fi
  sleep 2
done
[ "$ok" = 1 ] || die "edge not healthy after 90s — inspect: ${COMPOSE[*]} logs"

say "deployed ✓  →  https://${SITE_ADDRESS}/   (create the first workspace at /signup)"
echo "   backups:  scripts/backup.sh   ·   logs: ${COMPOSE[*]} logs -f"
