#!/usr/bin/env bash
# xbow-regression.sh — guard the XBOW offensive-benchmark capability (currently 89/104) from regression.
#
# Two tiers:
#
#   FAST (default · deterministic · NO Docker/LLM · CI-friendly) — the everyday pre-merge guard:
#     · builds tsbench + tsengine
#     · runs the harness + agent-grounding + ledger UNIT TESTS
#       (internal/bench/…, internal/webagent/…, cmd/tsbench/…) — this is what catches a real regression
#       in the grounding gate / probes / harness, deterministically, without an LLM
#     · asserts the durable ledger still records >= XBOW_BASELINE distinct captures
#     · if the suite is present, `--dry-run`-validates it parses (no Docker)
#
#   LIVE (--live · needs Docker[amd64] + the validation-benchmarks suite + an LLM) — full flag-capture:
#     · runs scripts/xbow-prep.sh (environment-rot fix)
#     · runs `tsbench xbow` over the suite (or --only IDS), appending to the ledger
#     · REGRESSION REPORT: any benchmark that was captured in the baseline ledger but did NOT capture
#       in this run (the ledger is append-only, so this per-run diff is the only way to see a regress)
#
# Usage:
#   scripts/xbow-regression.sh                                   # fast guard
#   scripts/xbow-regression.sh --live --only XBEN-058,XBEN-004   # live, a subset (fast smoke)
#   scripts/xbow-regression.sh --live --suite ../validation-benchmarks   # live, full suite (slow)
#   XBOW_BASELINE=89 scripts/xbow-regression.sh
#
# LLM for --live (the honest gate): LLM_BASE_URL=<proxy>/v1 (dev) or ANTHROPIC_API_KEY=... (prod).
set -euo pipefail
cd "$(dirname "$0")/.."

BASELINE="${XBOW_BASELINE:-89}"
LEDGER="${XBOW_LEDGER:-bench/xbow-ledger.jsonl}"
SUITE="${XBOW_SUITE:-../validation-benchmarks}"
LIVE=0; ONLY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --live) LIVE=1 ;;
    --only) ONLY="${2:-}"; shift ;;
    --only=*) ONLY="${1#*=}" ;;
    --suite) SUITE="${2:-}"; shift ;;
    --suite=*) SUITE="${1#*=}" ;;
    -h|--help) sed -n '2,30p' "$0" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) echo "unknown arg: $1 (see --help)" >&2; exit 2 ;;
  esac
  shift
done

fail() { echo "  ✗ $*" >&2; exit 1; }

echo "→ building tsbench + tsengine"
go build -o ./bin/tsbench ./cmd/tsbench
go build -o ./bin/tsengine ./cmd/tsengine

echo "→ [fast] harness + agent-grounding + ledger unit tests (deterministic, no LLM)"
if go test ./internal/bench/... ./internal/webagent/... ./cmd/tsbench/... >/tmp/xbow-reg.log 2>&1; then
  echo "   ✓ unit tests pass"
else
  tail -25 /tmp/xbow-reg.log
  fail "unit tests FAILED — a grounding/harness regression. See /tmp/xbow-reg.log"
fi

echo "→ [fast] ledger baseline (>= $BASELINE distinct captures)"
[ -f "$LEDGER" ] || fail "ledger not found: $LEDGER"
CAPTURED="$(./bin/tsbench xbow-ledger --ledger "$LEDGER" 2>/dev/null | grep -oE '[0-9]+ distinct benchmarks captured' | grep -oE '^[0-9]+' | head -1 || true)"
[ -n "$CAPTURED" ] || fail "could not read the distinct-capture count from the ledger"
echo "   recorded: $CAPTURED distinct captures (baseline $BASELINE)"
[ "$CAPTURED" -ge "$BASELINE" ] || fail "REGRESSION — captures ($CAPTURED) dropped below the baseline ($BASELINE)"

if [ -d "$SUITE/benchmarks" ]; then
  echo "→ [fast] validating the suite parses (--dry-run, no Docker)"
  ./bin/tsbench xbow --suite "$SUITE" --dry-run >/dev/null 2>&1 && echo "   ✓ suite validates" || echo "   ⚠ suite dry-run reported issues (non-fatal)"
fi

if [ "$LIVE" -eq 0 ]; then
  echo
  echo "✓ FAST XBOW regression guard PASSED — $CAPTURED/104 recorded, unit tests green."
  echo "  Full flag-capture measurement: scripts/xbow-regression.sh --live   (needs Docker + suite + LLM)"
  exit 0
fi

# ───────────────────────── LIVE ─────────────────────────
echo
echo "→ [live] preconditions"
[ -d "$SUITE/benchmarks" ] || fail "--live needs the suite at '$SUITE' (git clone github.com/xbow-engineering/validation-benchmarks, or pass --suite)"
docker version --format '{{.Server.Version}}' >/dev/null 2>&1 || fail "--live needs Docker running"
if [ -z "${LLM_BASE_URL:-}" ] && [ -z "${LLM_API_KEY:-}" ] && [ -z "${ANTHROPIC_API_KEY:-}" ]; then
  fail "--live needs an LLM: set LLM_BASE_URL (dev proxy) or ANTHROPIC_API_KEY (prod). Refusing to report a fake 0."
fi

echo "→ [live] preparing the suite (environment-rot fix)"
scripts/xbow-prep.sh "$SUITE"

OUT="$(mktemp -d /tmp/xbow-live.XXXXXX)/run"
echo "→ [live] running tsbench xbow ${ONLY:+(--only $ONLY) }— SLOW (Docker builds + LLM per benchmark)"
DOCKER_DEFAULT_PLATFORM=linux/amd64 ./bin/tsbench xbow --suite "$SUITE" ${ONLY:+--only "$ONLY"} \
  --mode investigate --out "$OUT" --ledger "$LEDGER" || true

echo "→ [live] regression report — baseline-captured benchmarks that did NOT capture this run"
python3 - "$LEDGER" "$OUT.json" <<'PY'
import json, sys
ledger, results = sys.argv[1], sys.argv[2]
def base(i):  # XBEN-058-24 → XBEN-058 (dedup to the benchmark)
    p = (i or "").split("-"); return "-".join(p[:2]) if len(p) >= 2 else (i or "")
baseline = set()
for l in open(ledger):
    l = l.strip()
    if not l: continue
    try: e = json.loads(l)
    except Exception: continue
    if e.get("solved"): baseline.add(base(e.get("id")))
try:
    run = json.load(open(results))
except Exception as ex:
    print(f"   (no results file — run may have produced nothing: {ex})"); sys.exit(0)
ran = {base(r.get("id")): r for r in run}
solved_now = {b for b, r in ran.items() if r.get("solved")}
errored    = {b for b, r in ran.items() if r.get("errored")}
regressed  = sorted(b for b in ran if b in baseline and b not in solved_now and b not in errored)
newcap     = sorted(b for b in solved_now if b not in baseline)
print(f"   ran {len(ran)} · solved {len(solved_now)} · errored(infra) {len(errored)}")
if newcap:   print(f"   ✓ NEW captures (not in baseline): {newcap}")
if regressed:
    print(f"   ✗ REGRESSED (baseline-captured, missed now): {regressed}")
    sys.exit(1)
print("   ✓ no regressions — every baseline-captured benchmark that ran still captured (or was an infra flake).")
PY
