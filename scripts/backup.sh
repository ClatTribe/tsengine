#!/usr/bin/env bash
# Back up the tsengine platform-data volume (the SQLite DB + the ed25519 signing key — the
# only stateful, irreplaceable data) to a timestamped tarball.
#
#   scripts/backup.sh [out-dir] [volume-name]
#     out-dir      where to write the archive (default ./backups)
#     volume-name  the docker volume (default tsengine_platform-data — compose prefixes the
#                  project name; override if your compose project name differs)
#
# Restore with scripts/restore.sh. Schedule via cron for off-box copies.
set -euo pipefail

OUT_DIR="${1:-./backups}"
VOLUME="${2:-${TSENGINE_DATA_VOLUME:-tsengine_platform-data}}"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
if ! docker volume inspect "$VOLUME" >/dev/null 2>&1; then
  echo "volume '$VOLUME' not found — pass the right name (docker volume ls)" >&2
  exit 1
fi

mkdir -p "$OUT_DIR"
OUT_ABS="$(cd "$OUT_DIR" && pwd)"
TS="$(date +%Y%m%d-%H%M%S)"
ARCHIVE="tsengine-${TS}.tar.gz"

# Read-only mount of the volume; tar it from a throwaway alpine into the host out-dir.
docker run --rm \
  -v "${VOLUME}:/data:ro" \
  -v "${OUT_ABS}:/backup" \
  alpine:3 \
  tar czf "/backup/${ARCHIVE}" -C /data .

echo "✓ volume backup → ${OUT_ABS}/${ARCHIVE}"

# ---------------------------------------------------------------------------
# Postgres.
#
# The tarball above captures the SQLite DB and the signing key. But if this deployment points
# TSENGINE_PLATFORM_DB at a postgres:// DSN, the tenant data does NOT live in the volume at all
# — it lives in Postgres, and a volume-only backup would capture almost nothing while still
# printing a reassuring success line. Dump it too.
#
# Managed Postgres (RDS/Supabase/Neon) usually has its own automated backups; this is the
# portable off-box copy that makes a restore reproducible.
# ---------------------------------------------------------------------------
DB_DSN="${TSENGINE_PLATFORM_DB:-}"
if [ -z "$DB_DSN" ] && [ -f .env ]; then
  DB_DSN="$(grep -E '^TSENGINE_PLATFORM_DB=' .env | tail -1 | cut -d= -f2- || true)"
fi

case "$DB_DSN" in
  postgres://*|postgresql://*)
    PG_DUMP="tsengine-pg-${TS}.sql.gz"
    echo "· Postgres DSN detected — dumping the database as well"
    # pg_dump from a throwaway container, so the host needs no postgres client.
    # --no-owner/--no-acl keep the dump restorable into a differently-owned database.
    if docker run --rm --network host \
        -v "${OUT_ABS}:/backup" \
        postgres:16-alpine \
        sh -c "pg_dump --no-owner --no-acl '${DB_DSN}' | gzip > '/backup/${PG_DUMP}'"; then
      echo "✓ postgres dump → ${OUT_ABS}/${PG_DUMP}"
    else
      # Loud and non-zero: a half-succeeded backup must never look like a success.
      echo "✗ postgres dump FAILED — the volume tarball above does NOT contain your tenant data" >&2
      exit 1
    fi
    ;;
  *)
    # SQLite/file store: the volume tarball is the complete backup.
    ;;
esac
