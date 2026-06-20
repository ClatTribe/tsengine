#!/usr/bin/env bash
# Restore the tsengine platform-data volume from a backup tarball (made by scripts/backup.sh).
#
#   scripts/restore.sh <archive.tar.gz> [volume-name]
#
# STOP the stack first (docker compose -f docker-compose.prod.yml down) so nothing is writing
# to the volume, then restore, then bring it back up. This REPLACES the volume contents.
set -euo pipefail

ARCHIVE="${1:?usage: restore.sh <archive.tar.gz> [volume-name]}"
VOLUME="${2:-${TSENGINE_DATA_VOLUME:-tsengine_platform-data}}"

command -v docker >/dev/null || { echo "docker is required" >&2; exit 1; }
[ -f "$ARCHIVE" ] || { echo "archive '$ARCHIVE' not found" >&2; exit 1; }

ARCHIVE_DIR="$(cd "$(dirname "$ARCHIVE")" && pwd)"
ARCHIVE_NAME="$(basename "$ARCHIVE")"

# Create the volume if absent (fresh box).
docker volume inspect "$VOLUME" >/dev/null 2>&1 || docker volume create "$VOLUME" >/dev/null

printf 'This REPLACES all data in volume %s. Continue? [y/N] ' "$VOLUME"
read -r ans
case "$ans" in y | Y | yes) ;; *) echo "aborted"; exit 1 ;; esac

docker run --rm \
  -v "${VOLUME}:/data" \
  -v "${ARCHIVE_DIR}:/backup:ro" \
  alpine:3 \
  sh -ec 'rm -rf /data/* /data/..?* /data/.[!.]* 2>/dev/null; tar xzf "/backup/'"${ARCHIVE_NAME}"'" -C /data'

echo "✓ restored ${ARCHIVE} → ${VOLUME} (now bring the stack back up)"
