#!/usr/bin/env bash
# demo-secure.sh — bring up the demo account with the scan ENGINE ON, securely, on this machine
# using Docker. This is the Bucket-C (operator/deployment) path: the demo seeds one asset of every
# type, and the platform spawns the OSS scanners inside hardened, resource-limited, network-isolated
# sandbox containers (read-only rootfs, PID/memory caps, dedicated network) — so a tech-asset scan
# (repository / web / api / container / ip / domain) runs locally with no external credentials.
#
# Security posture here: the per-scan SANDBOX is hardened (the scan-execution boundary). The platform
# itself runs on the host with the local Docker socket — fine for a single-box demo. For the fully
# hardened, containerized posture (docker-socket-proxy so there is NO raw socket, Caddy TLS edge),
# use `make deploy-prod` instead.
#
# Asset coverage by where it runs:
#   - repository / web_application / api / container_image / ip_address / domain → Docker sandbox (this script)
#   - cloud_account  → needs read-only cloud creds (prowler); see AWS/GCP/Azure connector onboarding
#   - workspace (identity) / SaaS posture → host-side, no sandbox (already live)
set -euo pipefail
cd "$(dirname "$0")/.."

SANDBOX_IMAGE="${TSENGINE_SANDBOX_IMAGE:-tsengine/sandbox:latest}"
SANDBOX_NET="${TSENGINE_SANDBOX_NETWORK:-tsengine-sandbox}"
DB="${TSENGINE_PLATFORM_DB:-/tmp/tsengine-demo-secure.json}"
API_PORT="${API_PORT:-8090}"

echo "→ checking Docker is available"
docker version --format '{{.Server.Version}}' >/dev/null 2>&1 || {
  echo "  ✗ Docker is not running. Start Docker Desktop / the daemon and re-run." >&2; exit 1; }

echo "→ ensuring the sandbox image exists ($SANDBOX_IMAGE)"
if ! docker image inspect "$SANDBOX_IMAGE" >/dev/null 2>&1; then
  echo "  building it (one-time, a few minutes — all OSS scanners are baked in)…"
  make sandbox-image
fi

echo "→ ensuring the isolated sandbox network exists ($SANDBOX_NET)"
docker network inspect "$SANDBOX_NET" >/dev/null 2>&1 || docker network create --internal "$SANDBOX_NET" >/dev/null

echo "→ building the platform binary"
go build -o ./platform ./cmd/platform

echo "→ seeding the demo (one asset of every type) → $DB"
[ -f "$DB" ] || go run ./cmd/seed-demo "$DB"

echo "→ starting the platform with the ENGINE ON (hardened sandboxes) on :$API_PORT (logs → /tmp/platform-secure.log)"
TSENGINE_PLATFORM_TOKEN="${TSENGINE_PLATFORM_TOKEN:-dev-token}" \
TSENGINE_PLATFORM_NO_ENGINE=0 \
TSENGINE_PLATFORM_DB="$DB" \
TSENGINE_SECRET_KEY="${TSENGINE_SECRET_KEY:-ZGVtby1zZWN1cmUta2V5LTMyYnl0ZXMtZm9yLXRzZW5n}" \
TSENGINE_MONITOR_INTERVAL=0 \
TSENGINE_SANDBOX_IMAGE="$SANDBOX_IMAGE" \
TSENGINE_SANDBOX_NETWORK="$SANDBOX_NET" \
TSENGINE_SANDBOX_READONLY=1 \
  ./platform > /tmp/platform-secure.log 2>&1 &
PLAT_PID=$!
sleep 3

if ! kill -0 "$PLAT_PID" 2>/dev/null; then
  echo "  ✗ platform exited — see /tmp/platform-secure.log" >&2; tail -20 /tmp/platform-secure.log >&2; exit 1
fi

cat <<EOF

  ┌──────────────────────────────────────────────────────────────────────┐
  │  Secure demo is UP — engine ON, hardened Docker sandboxes              │
  │  Platform API:  http://localhost:$API_PORT   (token: dev-token)            │
  │  Sign in (UI):  run \`make dev\` in another shell, then /login           │
  │                 founder@northwind.io  ·  sentinel123                    │
  └──────────────────────────────────────────────────────────────────────┘

  Trigger a scan for the demo tenant (each asset type), e.g.:
    curl -s -XPOST localhost:$API_PORT/v1/rescan \\
      -H 'Authorization: Bearer dev-token' -H 'X-Tenant-ID: ten-1'

  The platform spawns a hardened sandbox per tool: --read-only rootfs + writable /tmp tmpfs,
  --pids-limit, --memory/--cpus caps, --ulimit nofile, on the internal '$SANDBOX_NET' network
  (no egress). Point the web/api/repository asset targets at a local sibling container
  (reachable as host.docker.internal). For the fully hardened socket-proxy posture: make deploy-prod.

  Stop:  kill $PLAT_PID   ·   logs: tail -f /tmp/platform-secure.log
EOF
