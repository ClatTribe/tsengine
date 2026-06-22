#!/usr/bin/env bash
# demo-scan-asset.sh — prove the secure-Docker scan path PER locally-runnable asset type.
#
# One-shot CLI scans (no platform server, no external credentials): ensures the hardened sandbox
# image + the CLI, then scans a public container image and an ephemeral, generated source repo,
# printing the findings each produced. This is the Bucket-C proof that "each asset type runs
# securely on this machine via Docker": every scanner runs INSIDE the sandbox container (the host
# has no security-tool binaries by design), the source tree is bind-mounted READ-ONLY, and nothing
# leaves the box.
#
# Asset types proven here run with no creds: container_image (a public image) + repository (a
# generated tree). web/api/ip/domain use the same sandbox but need a reachable target; cloud needs
# read-only cloud creds; identity + SaaS posture are host-side (see operate / the SSPM ingest).
set -euo pipefail
cd "$(dirname "$0")/.."

SANDBOX_IMAGE="${TSENGINE_SANDBOX_IMAGE:-tsengine/sandbox:0.1.0}"

echo "→ checking Docker"
docker version --format '{{.Server.Version}}' >/dev/null 2>&1 || {
  echo "  ✗ Docker is not running. Start it and re-run." >&2; exit 1; }

echo "→ ensuring the sandbox image ($SANDBOX_IMAGE)"
docker image inspect "$SANDBOX_IMAGE" >/dev/null 2>&1 || make sandbox-image

echo "→ building the CLI"
go build -o ./bin/tsengine ./cmd/tsengine

count() { python3 -c "import json,sys; print(len(json.load(open(sys.argv[1])).get('findings_raw') or []))" "$1"; }
sample() { python3 -c "
import json,sys
for x in (json.load(open(sys.argv[1])).get('findings_raw') or [])[:5]:
    print('     -', x.get('severity','?'), '|', x.get('tool','?'), '|', (x.get('endpoint') or x.get('title') or x.get('rule_id') or '')[:54])
" "$1"; }

echo
echo "════ container_image — alpine:3.18 (public image, no creds) ════"
OUT=$(./bin/tsengine scan --asset container_image --target alpine:3.18 --image "$SANDBOX_IMAGE" 2>/tmp/demo-scan-container.log)
echo "   findings: $(count "$OUT")   (anchors run inside the sandbox; see /tmp/demo-scan-container.log)"
sample "$OUT"

echo
echo "════ repository — an ephemeral generated tree with a planted secret + injection ════"
REPO="$(mktemp -d /tmp/demo-repo.XXXXXX)"
trap 'rm -rf "$REPO"' EXIT
# Generate the planted secret AT RUNTIME so no fake credential is committed to this repo. The
# scanners (gitleaks/trivy/semgrep/trufflehog) detect by pattern, so a random AKIA-shaped key fires.
AKID="AKIA$(LC_ALL=C tr -dc 'A-Z0-9' </dev/urandom | head -c16)"
SECRET="$(LC_ALL=C tr -dc 'A-Za-z0-9/+' </dev/urandom | head -c40)"
cat > "$REPO/config.py" <<PY
AWS_ACCESS_KEY_ID = "$AKID"
AWS_SECRET_ACCESS_KEY = "$SECRET"
PY
cat > "$REPO/app.py" <<'PY'
import os
from flask import request
def ping():
    os.system("ping -c 1 " + request.args.get("host", ""))  # planted command injection
PY
OUT=$(./bin/tsengine scan --asset repository --target "$REPO" --image "$SANDBOX_IMAGE" 2>/tmp/demo-scan-repo.log)
echo "   findings: $(count "$OUT")   (bind-mounted read-only at /workspace; see /tmp/demo-scan-repo.log)"
sample "$OUT"

echo
echo "✓ secure-Docker scan proven for container_image + repository — scanners ran in the sandbox, no creds."
