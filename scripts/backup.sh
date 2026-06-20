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

echo "✓ backup → ${OUT_ABS}/${ARCHIVE}"
