#!/usr/bin/env bash
# engineer_campaign.sh — the AI Security Engineer harness-improvement loop (MULTI-BENCHMARK).
#
# The defensive twin of the XBOW pentester campaign. The pentester has ONE neutral
# benchmark (flag capture); the Engineer has none, so this runs EVERY benchmark that
# scores it and feeds them all to engineer_autopsy.py, which reports the failure
# categories that SPAN benchmarks — those are the global harness levers. A category
# appearing in only one benchmark is as likely to be a property of that fixture.
#
# Benchmarks driven here:
#   NEUTRAL CEILING (corpora we did NOT author — the honest capability claim)
#     cloud-engine --cloudgoat   CloudGoat, scored vs Rhino's PUBLISHED solutions
#     IAM-Vulnerable (BishopFox) + Rhino GCP  — go-tests, need the corpora on disk
#     SCuBA (CISA)               — transcribed, always runs
#   AGENT CASES (harness lift — needs a brain)
#     cloud-engine --agent       per-seed agent-vs-substrate head-to-head
#     defense                    per-scenario remediation capture
#     defense-xbow               per-challenge patch-and-prove (needs Docker + suite)
#     cvepatch                   per-CVE real fix vs gold patch (needs a dataset)
#
# Three anti-overfit guards, matching the pentester loop:
#   1. Brain-health preflight — a dead/refusing proxy must NEVER be read as a
#      capability miss (the XBOW dead-model lesson). Aborts before attribution.
#   2. Neutral keys first — in-house synthetic accounts are REGRESSION signal, never
#      the efficacy claim (§14.2 rule 5).
#   3. Discrimination gate — only accounts where the substrate left the agent real
#      headroom are run; a saturated account measures the substrate, not L2.
#
# Proxy env (checked FIRST by cloudengine.LLMFromEnv):
#   TSENGINE_LLM_OPENCODE           opencode serve URL  (e.g. http://127.0.0.1:44551)
#   TSENGINE_LLM_OPENCODE_MODEL     provider/model
#   TSENGINE_LLM_OPENCODE_PASSWORD  basic-auth password (default "opencode")
# Optional external corpora:
#   IAM_VULNERABLE_DIR   RHINO_GCP_CATALOGUE   XBOW_SUITE   CVEPATCH_DATASET
#
# Usage: scripts/engineer_campaign.sh [num_seeds] [base_seed]
set -u

NSEEDS="${1:-6}"
BASE_SEED="${2:-1}"
# SCALE_BUDGET bounds the substrate worklist on the agent head-to-heads. The default
# per-run budget saturates the account (substrate finds every path → no headroom →
# NON-DISCRIMINATING). The discrimination sweep proves headroom at this tight budget,
# so the agent is measured against a substrate that genuinely misses paths.
SCALE_BUDGET="${TSENGINE_SCALE_BUDGET:-5}"
OUT="${TSENGINE_ENGINEER_OUT:-/tmp/e2e/engineer}"
LOG="$OUT/engineer-campaign.log"
BIN="./bin/tsbench"
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
mkdir -p "$OUT" "$OUT/work"   # work/ holds transient files the autopsy must ignore

say() { echo -e "$@" | tee -a "$LOG"; }
: > "$LOG"

say "== build tsbench =="
go build -o "$BIN" ./cmd/tsbench 2>>"$LOG" || { say "BUILD FAILED — see $LOG"; exit 1; }

# ---------------------------------------------------------------- 1. brain preflight
say "\n== preflight: brain health =="
HAVE_BRAIN=1
if [ -z "${TSENGINE_LLM_OPENCODE:-}${ANTHROPIC_API_KEY:-}${LLM_BASE_URL:-}${LLM_API_KEY:-}" ]; then
  say "  no LLM env set — the AGENT legs cannot run."
  say "  the neutral ceiling below is LLM-free and still meaningful; agent lift will be skipped."
  HAVE_BRAIN=0
else
  SMOKE="$OUT/work/preflight-ledger.jsonl"; : > "$SMOKE"
  say "  smoke run (one --agent head-to-head, seed 99999)…"
  timeout 300 "$BIN" cloud-engine --cloudquery --agent --seed 99999 --ledger "$SMOKE" >>"$LOG" 2>&1
  PRE="$(python3 scripts/engineer_autopsy.py "$SMOKE" 2>/dev/null | awk '$1=="cloud-engine"{print $4; exit}')"
  case "$PRE" in
    CONFIG|REFUSAL|HALLUCINATED)
      say "  BRAIN UNHEALTHY: preflight classified '$PRE' — an OPERATOR/model fix, not harness."
      say "  fix the model (switch/authorize) and re-run. Aborting before attribution."
      exit 1 ;;
    *) say "  brain OK (preflight: ${PRE:-ran}).";;
  esac
fi

# ---------------------------------------------------------------- 2. neutral ceiling
say "\n== neutral external keys (LLM-free — the honest capability claim) =="
"$BIN" cloud-engine --cloudgoat > "$OUT/cloudgoat.txt" 2>>"$LOG" && say "  cloudgoat  → $OUT/cloudgoat.txt"
go test ./internal/bench -run SCuBA -v > "$OUT/scuba.txt" 2>>"$LOG" && say "  scuba      → $OUT/scuba.txt"
if [ -n "${IAM_VULNERABLE_DIR:-}" ]; then
  go test ./internal/bench -run 'IAMVulnerable_Live|PolicyCases_Live' -v > "$OUT/iamvulnerable.txt" 2>>"$LOG" \
    && say "  iam-vuln   → $OUT/iamvulnerable.txt"
else
  say "  iam-vuln   SKIPPED (set IAM_VULNERABLE_DIR — BishopFox corpus; the FP half is the number that can go DOWN)"
fi
if [ -n "${RHINO_GCP_CATALOGUE:-}" ]; then
  go test ./internal/bench -run GCPPrivesc_Live -v > "$OUT/rhino-gcp.txt" 2>>"$LOG" && say "  rhino-gcp  → $OUT/rhino-gcp.txt"
else
  say "  rhino-gcp  SKIPPED (set RHINO_GCP_CATALOGUE — recall-only, no published FP set)"
fi

# ---------------------------------------------------------------- 3. agent legs
if [ "$HAVE_BRAIN" = 1 ]; then
  say "\n== discrimination sweep: selecting headroom accounts (LLM-free) =="
  SWEEP="$OUT/work/sweep.txt"
  "$BIN" cloud-engine --discrimination-sweep "$NSEEDS" --seed "$BASE_SEED" 2>>"$LOG" | tee "$SWEEP" | tail -5
  SEEDS="$(grep -Eo 'seed[[:space:]=:]+[0-9]+' "$SWEEP" | grep -Eo '[0-9]+' | sort -un)"
  [ -z "$SEEDS" ] && SEEDS="$(seq "$BASE_SEED" $((BASE_SEED + NSEEDS - 1)))"

  say "\n== cloud-engine: agent vs substrate (per seed) =="
  CE_LEDGER="$OUT/cloudengine-agent-ledger.jsonl"; : > "$CE_LEDGER"
  for s in $SEEDS; do
    say "  seed $s …"
    timeout 900 "$BIN" cloud-engine --cloudquery-large --agent --seed "$s" --max-hypotheses "$SCALE_BUDGET" --ledger "$CE_LEDGER" >>"$LOG" 2>&1 \
      || say "    (errored — the autopsy will classify it)"
  done

  say "\n== defense: remediation capture (per scenario) =="
  DEF_LEDGER="$OUT/defense-ledger.jsonl"; : > "$DEF_LEDGER"
  timeout 1800 "$BIN" defense --ledger "$DEF_LEDGER" >>"$LOG" 2>&1 || say "  (defense run errored)"

  if [ -n "${XBOW_SUITE:-}" ]; then
    say "\n== defense-xbow: patch-and-prove (per challenge) =="
    DX_LEDGER="$OUT/defensexbow-ledger.jsonl"; : > "$DX_LEDGER"
    timeout 3600 "$BIN" defense-xbow --suite "$XBOW_SUITE" --ledger "$DX_LEDGER" >>"$LOG" 2>&1 \
      || say "  (defense-xbow errored — needs Docker + the suite)"
  else
    say "\n  defense-xbow SKIPPED (set XBOW_SUITE to the validation-benchmarks dir; needs Docker)"
  fi

  if [ -n "${CVEPATCH_DATASET:-}" ]; then
    say "\n== cvepatch: real CVE vs gold patch (per instance) =="
    timeout 1800 "$BIN" cvepatch --dataset "$CVEPATCH_DATASET" --json > "$OUT/cvepatch.json" 2>>"$LOG" \
      || say "  (cvepatch errored)"
  else
    say "\n  cvepatch SKIPPED (set CVEPATCH_DATASET — operator-provided real CVEs, not committed)"
  fi
fi

# ---------------------------------------------------------------- 4. multi-benchmark autopsy
say "\n== autopsy: EVERY benchmark, span-first (a category crossing benchmarks is the global lever) =="
python3 scripts/engineer_autopsy.py --all "$OUT" | tee -a "$LOG"

say "\nartifacts: $OUT"
say "log:       $LOG"
