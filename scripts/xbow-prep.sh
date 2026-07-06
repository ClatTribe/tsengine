#!/usr/bin/env bash
# xbow-prep.sh — make the XBOW validation-benchmarks suite build+run on a modern Docker /
# Apple-Silicon host, WITHOUT touching the challenge logic (so the benchmark stays valid).
#
# It closes the three ENVIRONMENT-ROT buckets that make ~60 of the 104 fail to build/up on a
# fresh clone (grounded by probing every base image + compose in the suite):
#
#   1. DEAD IMAGE    — mysql:5.7.15 (x13): its 2016 layer won't extract on the modern containerd
#                      snapshotter (fails identically on both arches, even on a clean re-pull).
#                      Fix: retag a working mysql:5.7 into the local store under the pinned tag.
#   2. AMD64-ONLY    — mysql:5.7 (and other x86-only tags) have no arm64 manifest. Fix: the RUNNER
#                      exports DOCKER_DEFAULT_PLATFORM=linux/amd64 (Rosetta emulation); this script
#                      pre-pulls the dead-image substitute under that platform.
#   3. COMPOSE ROT   — ~19 compose files use `expose: [ "NNNN:NNNN" ]` (a host:container map, which
#                      is invalid for `expose:` — it takes a bare port). Old Compose tolerated it;
#                      Compose v2/v29 rejects it with `invalid start port`. `expose` only documents a
#                      port (never publishes), so dropping the host half is behaviour-preserving.
#   4. FIXED HOSTPORT — ~15 compose files publish to a FIXED host port (`ports: - "5000:5000"`) that
#                      is often already bound on a dev host (macOS AirPlay Receiver owns :5000), so
#                      `up` dies with `address already in use`. Dropping the host half → Docker
#                      auto-assigns an ephemeral host port (the harness reads it via `docker inspect`,
#                      like every already-working benchmark), so it's behaviour-preserving.
#
# Idempotent + safe to re-run. Prints a summary. Does NOT run any benchmark — that's `tsbench xbow`.
#
# Usage:  scripts/xbow-prep.sh [SUITE_DIR]
#         SUITE_DIR defaults to $XBOW_SUITE, else ../validation-benchmarks relative to the repo.
set -euo pipefail

SUITE="${1:-${XBOW_SUITE:-}}"
if [ -z "$SUITE" ]; then
  here="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
  SUITE="$(cd "$here/.." && pwd)/validation-benchmarks"
fi
if [ ! -d "$SUITE/benchmarks" ]; then
  echo "xbow-prep: no benchmarks/ under '$SUITE' — pass the validation-benchmarks path" >&2
  exit 2
fi
echo "xbow-prep: suite = $SUITE"

# --- bucket 1+2: pre-seed the dead mysql image with a working amd64 substitute -----------------
# Every mysql:5.7.x tag these benchmarks pin resolves to the same broken-layer image; mysql:5.7
# (currently 5.7.44) extracts fine under amd64 emulation. Retag it under each pinned tag the suite
# references so `docker compose build` finds it locally and never hits the broken registry layer.
seed_mysql() {
  local want="$1"
  if docker image inspect "$want" >/dev/null 2>&1; then
    echo "  image ok: $want (already present)"; return
  fi
  echo "  pulling mysql:5.7 (amd64) -> retag $want"
  docker pull --platform linux/amd64 mysql:5.7 >/dev/null
  docker tag mysql:5.7 "$want"
}
echo "xbow-prep: pre-seeding dead mysql images…"
# Collect the exact mysql:5.7.* tags the suite pins, so we cover 5.7.15 and any siblings.
# (bash 3.2 on macOS has no mapfile — use a while-read loop.)
mysql_seeded=0
while IFS= read -r t; do
  [ -n "$t" ] || continue
  seed_mysql "$t"; mysql_seeded=$((mysql_seeded+1))
done < <(grep -rhoE 'mysql:5\.7\.[0-9]+' "$SUITE/benchmarks" 2>/dev/null | sort -u)
[ "$mysql_seeded" -eq 0 ] && echo "  (no pinned mysql:5.7.x tags found)"

# --- bucket 3: normalize `expose: NNNN:NNNN` -> `expose: NNNN` --------------------------------
# In-place, behaviour-preserving. Only rewrites a list item that is a bare host:container number
# pair (e.g. "- 3306:3306"); leaves ports:, healthchecks, and real mappings untouched. We scope
# the rewrite to lines inside an `expose:` block so a `ports:` mapping is never altered.
echo "xbow-prep: normalizing malformed 'expose:' port maps…"
fixed=0
while IFS= read -r cf; do
  if perl -0777 -i -pe '
    s{(^[ \t]*expose:[ \t]*\n)((?:[ \t]*-[ \t]*[^\n]*\n)+)}{
      my ($h,$body)=($1,$2);
      $body =~ s/^([ \t]*-[ \t]*)(\d+):\d+([ \t]*)$/$1$2$3/mg;
      $h.$body;
    }gme;
  ' "$cf" 2>/dev/null; then
    :
  fi
  # count as fixed only if the malformed pattern is now gone but was present before is hard to
  # track post-hoc; instead re-scan and report remaining offenders below.
  fixed=$((fixed+1))
done < <(grep -rlE 'expose:' "$SUITE/benchmarks" --include='docker-compose*.y*ml' 2>/dev/null)

# Re-scan for any remaining malformed expose map (portable awk, no grep -P/-z).
remaining=0
while IFS= read -r cf; do
  if awk '/expose:/{e=1;next} e&&/^[[:space:]]*-[[:space:]]*[0-9]+:[0-9]+/{f=1;exit} e&&/^[[:space:]]*[a-z_]+:/{e=0} END{exit !f}' "$cf"; then
    remaining=$((remaining+1))
  fi
done < <(grep -rlE 'expose:' "$SUITE/benchmarks" --include='docker-compose*.y*ml' 2>/dev/null)
echo "xbow-prep: scanned $fixed compose file(s) with an expose: block; malformed remaining = $remaining"

# --- bucket 4: normalize FIXED host ports `ports: - "N:N"` -> `ports: - "N"` -------------------
# ~15 compose files publish to a FIXED host port (e.g. `- "5000:5000"`). On a dev host that fixed
# port is often already taken — macOS Control Center / AirPlay Receiver listens on :5000, so every
# Flask-on-5000 benchmark dies at `up` with `bind: address already in use` (grounded: XBEN-096).
# Dropping the host half lets Docker publish the container port to an EPHEMERAL host port, exactly
# like the benchmarks that already work; the harness discovers the published port via `docker
# inspect` either way, so this is behaviour-preserving. Only rewrites a list item that is a bare
# host:container number pair inside a `ports:` block (a host-IP form like "127.0.0.1:5000:5000" or a
# range/protocol is left untouched — it won't collide the same way). Idempotent: `- "5000"` is a
# no-op on re-run.
echo "xbow-prep: normalizing fixed host ports (ports: N:N -> N, so Docker auto-assigns)…"
ports_fixed=0
while IFS= read -r cf; do
  perl -0777 -i -pe '
    s{(^[ \t]*ports:[ \t]*\n)((?:[ \t]*-[ \t]*[^\n]*\n)+)}{
      my ($h,$body)=($1,$2);
      # "N:N" or N:N (bare host:container, no host-IP, no extra colon) -> just the container port
      $body =~ s/^([ \t]*-[ \t]*)"?(\d+):(\d+)"?([ \t]*)$/$1"$3"$4/mg;
      $h.$body;
    }gme;
  ' "$cf" 2>/dev/null || true
  ports_fixed=$((ports_fixed+1))
done < <(grep -rlE '^[[:space:]]*ports:' "$SUITE/benchmarks" --include='docker-compose*.y*ml' 2>/dev/null)
# Re-scan for any remaining bare N:N host map inside a ports: block.
ports_remaining=0
while IFS= read -r cf; do
  if awk '/^[[:space:]]*ports:/{p=1;next} p&&/^[[:space:]]*-[[:space:]]*"?[0-9]+:[0-9]+"?[[:space:]]*$/{f=1;exit} p&&/^[[:space:]]*[a-z_]+:/{p=0} END{exit !f}' "$cf"; then
    ports_remaining=$((ports_remaining+1))
  fi
done < <(grep -rlE '^[[:space:]]*ports:' "$SUITE/benchmarks" --include='docker-compose*.y*ml' 2>/dev/null)
echo "xbow-prep: scanned $ports_fixed compose file(s) with a ports: block; fixed-host-port remaining = $ports_remaining"

# --- bucket 5: EOL Debian base with archived apt (python:2.7.18-slim = Debian buster) ---------
# The 23 XSS benchmarks (and any other python:2.7.18-slim challenge) `apt-get install` a package
# (e.g. phantomjs, the server-side XSS checker's headless browser) at build time. Buster left
# deb.debian.org / security.debian.org in 2023, so `apt-get update` now 404s and the image fails
# to build. archive.debian.org still serves buster; pointing sources.list there + disabling the
# Valid-Until check (the archive's Release is intentionally stale) restores the build. This rewrites
# only the apt SOURCE (never a package version or the app code), so it's behaviour-preserving — the
# same phantomjs 2.1.1 installs. Idempotent via a marker line. Grounded: patches only a Dockerfile
# whose base is exactly python:2.7.18-slim (the pinned archived-buster tag the suite uses).
echo "xbow-prep: applying archive.debian.org fix to EOL python:2.7.18-slim Dockerfiles…"
eol_fixed=0
while IFS= read -r df; do
  [ -n "$df" ] || continue
  grep -q 'xbow-prep: archive.debian.org' "$df" && continue
  python3 - "$df" <<'PY' || true
import sys
df = sys.argv[1]
lines = open(df).read().splitlines()
out, done = [], False
for l in lines:
    out.append(l)
    if not done and l.strip().startswith('FROM python:2.7.18-slim'):
        out.append('# xbow-prep: archive.debian.org (EOL buster apt fix — build-env only, behaviour-preserving)')
        out.append("RUN printf 'deb [check-valid-until=no] http://archive.debian.org/debian buster main\\n' > /etc/apt/sources.list && printf 'Acquire::Check-Valid-Until \"false\";\\n' > /etc/apt/apt.conf.d/99no-check")
        done = True
open(df, 'w').write("\n".join(out) + "\n")
PY
  eol_fixed=$((eol_fixed+1))
done < <(grep -rlE '^FROM python:2\.7\.18-slim' "$SUITE/benchmarks" --include='Dockerfile' 2>/dev/null)
echo "xbow-prep: patched $eol_fixed python:2.7.18-slim Dockerfile(s) for archived-buster apt"

echo "xbow-prep: DONE. Now run the suite with amd64 emulation, e.g.:"
echo "    DOCKER_DEFAULT_PLATFORM=linux/amd64 \\"
echo "    ANTHROPIC_BASE_URL=<proxy> ANTHROPIC_API_KEY=<key> ANTHROPIC_MODEL=claude-opus-4-8 \\"
echo "    ./bin/tsbench xbow --suite \"$SUITE\" --out xbow-104 --prune-images"
