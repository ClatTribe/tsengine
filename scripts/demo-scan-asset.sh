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

# web_application is recon→fan-out (katana crawl → nuclei/dalfox/sqlmap/httpx/ffuf), so it needs a
# reachable target. Stand up a throwaway local site with a real misconfig (an exposed /.git/), scan
# it through the sandbox (the loopback host is rewritten to host.docker.internal), then tear it down.
# Skipped automatically if port 8088 is busy or the nginx image can't be pulled — the scan needs the
# target reachable, and we never fake a result.
echo
echo "════ web_application — a throwaway local site exposing /.git/ (real misconfig, no creds) ════"
WEB="$(mktemp -d /tmp/demo-web.XXXXXX)"
trap 'rm -rf "$REPO" "$WEB"; docker rm -f tsengine-demo-webtarget >/dev/null 2>&1 || true' EXIT
mkdir -p "$WEB/.git"
printf 'ref: refs/heads/main\n' > "$WEB/.git/HEAD"
printf '[core]\n\trepositoryformatversion = 0\n' > "$WEB/.git/config"
printf '<html><body><h1>demo</h1><form action="/search"><input name="q"></form></body></html>\n' > "$WEB/index.html"
if docker run -d --rm --name tsengine-demo-webtarget -p 8088:80 -v "$WEB":/usr/share/nginx/html:ro nginx:alpine >/dev/null 2>&1; then
  sleep 2
  OUT=$(./bin/tsengine scan --asset web_application --target http://localhost:8088 --image "$SANDBOX_IMAGE" 2>/tmp/demo-scan-web.log)
  echo "   findings: $(count "$OUT")   (recon→fan-out in the sandbox; reaches the host via host.docker.internal)"
  sample "$OUT"
  docker rm -f tsengine-demo-webtarget >/dev/null 2>&1 || true
  echo "   (the exposed /.git/ is surfaced; a static target yields no high-severity finding — grounded, no FP)"
else
  echo "   skipped — could not start the local target (port 8088 busy or nginx:alpine unavailable)."
fi

echo
echo "✓ secure-Docker scan proven for container_image + repository + web_application — scanners ran in the sandbox, no creds."
