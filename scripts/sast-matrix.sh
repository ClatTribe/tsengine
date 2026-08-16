#!/usr/bin/env bash
# Per-class, per-language SAST recall — run the shipped semgrep config against planted cases.
#
# WHY: the neutral SAST benchmark we cite (OWASP Benchmark v1.2) is a Java corpus, and our customers
# write Go, JavaScript and Python. A command injection missed in Python surfaced only because a demo
# fixture happened to plant one. This turns "did we miss a class?" into a number.
#
# This is a REGRESSION TEST, not a neutral benchmark — we wrote the cases. See cases.json.
#
#   scripts/sast-matrix.sh [image]
set -euo pipefail
IMG="${1:-tsengine/sandbox:0.1.0-container-repository}"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
FIX="$ROOT/fixtures/repo/sast-matrix"  # cases live in $FIX/testdata (Go toolchain ignores testdata/)
CLEAN="$ROOT/fixtures/repo/clean"

# Keep in step with internal/tool/semgrep/semgrep.go. If they drift, this measures a config we do
# not ship, which is worse than not measuring at all.
CONFIGS="--config p/security-audit --config p/secrets --config p/owasp-top-ten --config p/default"

echo "== planted-case recall =="
docker run --rm -v "$FIX:/workspace:ro" --entrypoint sh "$IMG" -c \
  "semgrep $CONFIGS --json --quiet /workspace 2>/dev/null" \
| python3 -c "
import sys, json, os
hits = {os.path.basename(r['path']) for r in json.load(sys.stdin).get('results', [])}
cases = json.load(open('$FIX/cases.json'))['cases']
found = [c for c in cases if os.path.basename(c['file']) in hits]
for c in cases:
    mark = 'HIT ' if os.path.basename(c['file']) in hits else 'MISS'
    print(f\"  {mark}  {c['lang']:<11} {c['class']:<26} {c['cwe']}\")
print(f\"\n  recall: {len(found)}/{len(cases)}\")
"

echo
echo "== FP-control (must be 0) =="
docker run --rm -v "$CLEAN:/workspace:ro" --entrypoint sh "$IMG" -c \
  "semgrep $CONFIGS --json --quiet /workspace 2>/dev/null" \
| python3 -c "import sys, json; n=len(json.load(sys.stdin).get('results',[])); print(f'  findings on the clean tree: {n}'); sys.exit(1 if n else 0)"
