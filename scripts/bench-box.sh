#!/usr/bin/env bash
#
# bench-box.sh — run the per-asset benchmarks on one box.
#
# Every per-asset scorer already exists in tsbench and every ground truth is already
# committed. What never existed was something that deployed the targets and ran the set
# end to end. This is that. It brings up docker-compose.bench.yml on the isolated
# sandbox network, waits for each target to actually answer, scores each asset, and
# writes one report.
#
#   scripts/bench-box.sh              # everything that can run on this box
#   scripts/bench-box.sh web sast     # just those
#   scripts/bench-box.sh --keep-up    # leave targets running (see the warning below)
#   scripts/bench-box.sh --list       # what each asset needs, and run nothing
#
# THE ONE RULE THIS SCRIPT ENFORCES: it never reports a number it did not measure.
# An asset that cannot run on this box is printed as SKIPPED with the reason. A scorer
# that fails is printed as FAILED with its exit code. Neither is silently omitted and
# neither is estimated, because a benchmark report that quietly drops its failures is
# worse than no benchmark at all.

set -uo pipefail

cd "$(dirname "$0")/.."
ROOT="$(pwd)"

COMPOSE_FILE="docker-compose.bench.yml"
NETWORK="${TSENGINE_SANDBOX_NETWORK:-tsengine-sandbox}"
SANDBOX_IMAGE="${TSENGINE_SANDBOX_IMAGE:-tsengine/sandbox:0.1.0}"
TSBENCH="${TSBENCH:-./bin/tsbench}"
TSENGINE="${TSENGINE_BIN:-./bin/tsengine}"
OUTDIR="${BENCH_OUT:-bench/results/$(date -u +%Y-%m-%dT%H%M%SZ)}"
TARGETS_DIR="${BENCH_TARGETS_DIR:-bench/targets}"
KEEP_UP=0
LIST_ONLY=0

# Scanners run inside ephemeral sandboxes; they must land on the same bridge as the
# targets or every scan resolves nothing and every asset scores a spurious zero.
export TSENGINE_SANDBOX_NETWORK="$NETWORK"
export TSENGINE_SANDBOX_IMAGE="$SANDBOX_IMAGE"

ALL_ASSETS=(container repo-sca repo-clean web sast api ip cloud)
declare -a REQUESTED=()

for a in "$@"; do
  case "$a" in
    --keep-up) KEEP_UP=1 ;;
    --list)    LIST_ONLY=1 ;;
    all)       REQUESTED=("${ALL_ASSETS[@]}") ;;
    -h|--help) sed -n '2,22p' "$0"; exit 0 ;;
    -*)        echo "unknown flag: $a" >&2; exit 2 ;;
    *)         REQUESTED+=("$a") ;;
  esac
done
[ ${#REQUESTED[@]} -eq 0 ] && REQUESTED=("${ALL_ASSETS[@]}")

C_RED=$'\033[31m'; C_GRN=$'\033[32m'; C_YEL=$'\033[33m'; C_DIM=$'\033[2m'; C_OFF=$'\033[0m'
say()  { printf '%s\n' "$*"; }
head2() { printf '\n%s──  %s  ──%s\n' "$C_DIM" "$*" "$C_OFF"; }

# Results accumulate as flat "asset|STATUS|detail" strings rather than an associative
# array: `declare -A` is bash 4+, and macOS still ships bash 3.2, so an assoc array makes
# this script silently unrunnable on a dev laptop while working fine on the EC2 box.
RESULTS=()
record() { RESULTS+=("$1|$2|$3"); }

if [ "$LIST_ONLY" = 1 ]; then
  cat <<'EOF'
Asset          Target needed                        Neutral leaderboard?
-------------  -----------------------------------  ----------------------------------
container      none (pulls nginx:1.14 / alpine)     no  — vendors self-publish only
repo-sca       none (fixture tree in repo)          no  — vendors self-publish only
repo-clean     none (fixture tree in repo)          n/a — FP-control, floor is zero
web            WAVSEP container                     YES — Acunetix 87 / Burp 78 / ZAP 56
sast           BenchmarkJava source (git clone)     YES — Veracode 51 / Checkmarx 47
api            VAmPI container                      no  — none exists for API security
ip             unauthenticated Redis container      no  — Tenable/Qualys publish none
cloud          LocalStack (partial) or real creds   no  — CSPM vendors self-publish
domain         NOT RUNNABLE ON A BOX — see below    no

domain is the one asset that cannot be benchmarked in a box: subdomain enumeration
queries public sources (crt.sh, passive DNS) about a real registered domain. There is
nothing to host. Measure it against a domain you own and whose subdomain set you know.
EOF
  exit 0
fi

# ---------------------------------------------------------------- preflight
head2 "preflight"
fail_pre=0
if ! docker info >/dev/null 2>&1; then
  say "  ${C_RED}✗${C_OFF} docker daemon not reachable"; fail_pre=1
else
  say "  ${C_GRN}✓${C_OFF} docker $(docker version --format '{{.Server.Version}}' 2>/dev/null)"
fi
if ! docker image inspect "$SANDBOX_IMAGE" >/dev/null 2>&1; then
  say "  ${C_RED}✗${C_OFF} sandbox image $SANDBOX_IMAGE absent — run: make sandbox-image"; fail_pre=1
else
  say "  ${C_GRN}✓${C_OFF} sandbox image $SANDBOX_IMAGE"
fi
for b in "$TSBENCH" "$TSENGINE"; do
  if [ ! -x "$b" ]; then say "  ${C_RED}✗${C_OFF} $b missing — run: make cli tsbench"; fail_pre=1
  else say "  ${C_GRN}✓${C_OFF} $b"; fi
done
[ "$fail_pre" = 1 ] && { say "\npreflight failed — nothing was run."; exit 1; }

if ! docker network inspect "$NETWORK" >/dev/null 2>&1; then
  docker network create "$NETWORK" >/dev/null && say "  ${C_GRN}✓${C_OFF} created network $NETWORK"
else
  say "  ${C_GRN}✓${C_OFF} network $NETWORK"
fi
mkdir -p "$OUTDIR" "$TARGETS_DIR"

# ---------------------------------------------------------------- target lifecycle
needs_target() { case "$1" in web) echo wavsep ;; api) echo vampi ;; ip) echo ip-redis ;; cloud) echo localstack ;; *) echo "" ;; esac; }

compose() { docker compose -f "$COMPOSE_FILE" --profile bench "$@"; }

teardown() {
  [ "$KEEP_UP" = 1 ] && { say "\n${C_YEL}!${C_OFF} --keep-up: vulnerable targets LEFT RUNNING on $NETWORK. Stop them with:"; say "    docker compose -f $COMPOSE_FILE --profile bench down"; return; }
  head2 "teardown"
  compose down --remove-orphans >/dev/null 2>&1 && say "  ${C_GRN}✓${C_OFF} targets stopped"
}
trap teardown EXIT

# wait_http <container> <port> <path> <seconds>
# Probes from a throwaway container ON THE BENCH NETWORK rather than from the host —
# the host deliberately cannot reach these targets, and probing from inside also proves
# the exact reachability a scanner will have.
wait_http() {
  local host="$1" port="$2" path="$3" limit="$4" waited=0
  printf '  … waiting for %s:%s%s ' "$host" "$port" "$path"
  while [ "$waited" -lt "$limit" ]; do
    if docker run --rm --network "$NETWORK" curlimages/curl:latest \
         -s -o /dev/null --max-time 5 "http://${host}:${port}${path}" 2>/dev/null; then
      printf '%s✓%s (%ss)\n' "$C_GRN" "$C_OFF" "$waited"; return 0
    fi
    sleep 5; waited=$((waited+5)); printf '.'
  done
  printf '%s✗ timeout after %ss%s\n' "$C_RED" "$C_OFF" "$limit"; return 1
}

wait_tcp() {
  local host="$1" port="$2" limit="$3" waited=0
  printf '  … waiting for %s:%s ' "$host" "$port"
  while [ "$waited" -lt "$limit" ]; do
    if docker run --rm --network "$NETWORK" busybox:latest \
         sh -c "nc -z -w2 $host $port" >/dev/null 2>&1; then
      printf '%s✓%s (%ss)\n' "$C_GRN" "$C_OFF" "$waited"; return 0
    fi
    sleep 3; waited=$((waited+3)); printf '.'
  done
  printf '%s✗ timeout after %ss%s\n' "$C_RED" "$C_OFF" "$limit"; return 1
}

# ---------------------------------------------------------------- per-asset runs
# A fixture with runnable:false makes `tsbench run` print a stub and exit 0 — a SUCCESS
# exit code for a benchmark that never executed. Scoring on the exit code alone would
# record a pass for an unmeasured asset, which is the exact failure this whole harness
# exists to prevent. So every run is also checked for the stub marker.
STUB_MARKER='[STUB — not runnable]'

run_fixture() { # run_fixture <asset-key> <fixture-path>
  local key="$1" fx="$2" log="$OUTDIR/$1.log" rc
  head2 "$key  ·  $fx"
  "$TSBENCH" run --fixture "$fx" --image "$SANDBOX_IMAGE" >"$log" 2>&1; rc=$?
  if grep -qF "$STUB_MARKER" "$log" 2>/dev/null; then
    record "$key" SKIPPED "fixture is runnable:false — printed a stub, measured nothing"
    say "  ${C_YEL}!${C_OFF} stub, not a measurement — $log"
  elif [ "$rc" -eq 0 ]; then
    record "$key" OK "$(grep -ioE '(youden|recall|score)[^,;]*' "$log" | tail -1)"
    say "  ${C_GRN}✓${C_OFF} scored — $log"
  else
    record "$key" FAILED "exit $rc — see $log"
    say "  ${C_RED}✗${C_OFF} failed — $log"
  fi
}

run_web() {
  head2 "web_application  ·  WAVSEP (neutral leaderboard)"
  compose up -d wavsep >/dev/null 2>&1
  # Tomcat + MySQL seed: genuinely slow, and a premature scan scores a false zero.
  if ! wait_http bench-wavsep 8080 /wavsep/ 420; then
    record web SKIPPED "WAVSEP never became ready — logs: docker logs bench-wavsep"; return
  fi
  # Scan from the ROOT, not /wavsep. The ground-truth url_path column already carries the
  # full "/wavsep/active/..." prefix and scoring is substring containment, so the crawler
  # must start above that path to reach the cases at all.
  local log="$OUTDIR/web.log"
  if "$TSBENCH" wavsep --target http://bench-wavsep:8080 \
       --ground-truth fixtures/web/wavsep/expected-cases.csv \
       --image "$SANDBOX_IMAGE" >"$log" 2>&1; then
    record web OK "$(grep -ioE 'youden[^,;]*' "$log" | tail -1)"
    say "  ${C_GRN}✓${C_OFF} scored vs 1,133 cases — $log"
  else
    record web FAILED "see $log"; say "  ${C_RED}✗${C_OFF} failed — $log"
  fi
}

run_sast() {
  head2 "repository (SAST)  ·  OWASP Benchmark v1.2 (neutral leaderboard)"
  local src="$TARGETS_DIR/BenchmarkJava"
  # Pure source. Nothing is executed, so this is the safest benchmark of the set — it is
  # also the one whose fixture note wrongly claimed it was blocked on a semgrep wrapper.
  if [ ! -d "$src" ]; then
    say "  … cloning OWASP BenchmarkJava (~200MB, once)"
    if ! git clone --depth 1 https://github.com/OWASP-Benchmark/BenchmarkJava.git "$src" >/dev/null 2>&1; then
      record sast SKIPPED "clone failed — no network, or GitHub unreachable"; say "  ${C_RED}✗${C_OFF} clone failed"; return
    fi
  fi
  local gt="$src/expectedresults-1.2.csv"
  [ -f "$gt" ] || { record sast SKIPPED "ground truth $gt absent in the checkout"; say "  ${C_RED}✗${C_OFF} no expectedresults-1.2.csv"; return; }
  local log="$OUTDIR/sast.log"
  if "$TSBENCH" sast --target "$ROOT/$src" --ground-truth "$gt" --image "$SANDBOX_IMAGE" >"$log" 2>&1; then
    record sast OK "$(grep -ioE 'youden[^,;]*' "$log" | tail -1)"
    say "  ${C_GRN}✓${C_OFF} scored vs 2,740 cases — $log"
  else
    record sast FAILED "see $log"; say "  ${C_RED}✗${C_OFF} failed — $log"
  fi
}

# The committed api/ip fixtures are runnable:false because, absent this harness, their
# target did not exist. Now it does — so retarget at the container AND flip runnable, in
# a COPY under $OUTDIR. The committed fixtures stay untouched: their honest default is
# still "no target deployed", and the run that changes that is the run that says so.
retarget() { # retarget <src-fixture> <dst> <new-target>
  sed -e "s#\"target\": *\"[^\"]*\"#\"target\": \"$3\"#" \
      -e 's#"runnable": *false#"runnable": true#' "$1" > "$2"
}

run_api() {
  head2 "api  ·  VAmPI"
  compose up -d vampi >/dev/null 2>&1
  if ! wait_http bench-vampi 5000 /openapi.json 120; then
    record api SKIPPED "VAmPI never became ready"; return
  fi
  retarget fixtures/api/vampi/fixture.json "$OUTDIR/api-fixture.json" \
           "http://bench-vampi:5000/openapi.json"
  run_fixture api "$OUTDIR/api-fixture.json"
}

run_ip() {
  head2 "ip_address  ·  unauthenticated Redis"
  compose up -d ip-redis >/dev/null 2>&1
  if ! wait_tcp bench-ip-redis 6379 60; then
    record ip SKIPPED "redis never became reachable"; return
  fi
  retarget fixtures/ip/services/fixture.json "$OUTDIR/ip-fixture.json" "bench-ip-redis"
  run_fixture ip "$OUTDIR/ip-fixture.json"
}

run_cloud() {
  head2 "cloud_account  ·  LocalStack (PARTIAL — read the caveat)"
  compose up -d localstack >/dev/null 2>&1
  if ! wait_http bench-localstack 4566 /_localstack/health 180; then
    record cloud SKIPPED "LocalStack never became ready"; return
  fi
  local log="$OUTDIR/cloud.log"
  # LocalStack implements a SUBSET of the AWS APIs the 42 CIS controls need. Whatever
  # this prints is recall over the covered subset, NOT over the full control set. The
  # report says so; do not restate it as a CIS number.
  if AWS_ENDPOINT_URL="http://bench-localstack:4566" AWS_ACCESS_KEY_ID=test AWS_SECRET_ACCESS_KEY=test AWS_DEFAULT_REGION=us-east-1 \
     "$TSBENCH" cloud --target aws --ground-truth fixtures/cloud/baseline/expected-controls.csv \
       --image "$SANDBOX_IMAGE" >"$log" 2>&1; then
    record cloud PARTIAL "subset only (LocalStack) — $(grep -ioE 'recall[^,;]*' "$log" | tail -1)"
    say "  ${C_YEL}!${C_OFF} scored over the LocalStack-covered subset only — $log"
  else
    record cloud FAILED "see $log"; say "  ${C_RED}✗${C_OFF} failed — $log"
  fi
}

# ---------------------------------------------------------------- dispatch
for asset in "${REQUESTED[@]}"; do
  case "$asset" in
    container)  run_fixture container  fixtures/container/nginx-vuln
                run_fixture container-fp fixtures/container/alpine-clean ;;
    repo-sca)   run_fixture repo-sca   fixtures/repo/sca-vuln ;;
    repo-clean) run_fixture repo-clean fixtures/repo/clean ;;
    web)        run_web ;;
    sast)       run_sast ;;
    api)        run_api ;;
    ip)         run_ip ;;
    cloud)      run_cloud ;;
    domain)     record domain SKIPPED "not hostable — needs a real domain you own (see --list)" ;;
    *)          record "$asset" SKIPPED "unknown asset" ;;
  esac
done

# ---------------------------------------------------------------- report
REPORT="$OUTDIR/report.md"
{
  echo "# Per-asset benchmark run"
  echo
  echo "- UTC: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  echo "- Sandbox image: \`$SANDBOX_IMAGE\` (digest: $(docker image inspect --format '{{index .RepoDigests 0}}' "$SANDBOX_IMAGE" 2>/dev/null || echo 'local build, no digest'))"
  echo "- Network: \`$NETWORK\` (targets unpublished — reachable only from this bridge)"
  echo
  echo "| Asset | Status | Detail |"
  echo "|---|---|---|"
  for row in "${RESULTS[@]:-}"; do
    [ -z "$row" ] && continue
    IFS='|' read -r k st detail <<<"$row"
    echo "| $k | $st | ${detail:-—} |"
  done | sort
  echo
  echo "## How to read this"
  echo
  echo "- \`SKIPPED\` means the asset did not run and no number was produced. It is listed"
  echo "  rather than omitted so the report cannot be mistaken for full coverage."
  echo "- \`PARTIAL\` (cloud) is recall over the LocalStack-covered subset of the AWS APIs,"
  echo "  not over the full 42-control CIS set. The full number needs read-only credentials"
  echo "  on a real seeded account."
  echo "- Only **web** (WAVSEP) and **sast** (OWASP Benchmark) have neutral third-party"
  echo "  leaderboards to compare against. Every other asset here is our own must-find set:"
  echo "  useful as a regression gate, not as a competitive claim."
} > "$REPORT"

head2 "summary"
# Piped into `while read`, not `for row in $(...)`: the detail field contains spaces, and
# word-splitting a $(...) would shred every multi-word status into separate rows.
printf '%s\n' "${RESULTS[@]:-}" | sort | while IFS='|' read -r k st detail; do
  [ -z "$k" ] && continue
  case "$st" in
    OK)      printf '  %s✓%s  %-14s %s\n' "$C_GRN" "$C_OFF" "$k" "$detail" ;;
    PARTIAL) printf '  %s!%s  %-14s %s\n' "$C_YEL" "$C_OFF" "$k" "$detail" ;;
    *)       printf '  %s✗%s  %-14s %s %s\n' "$C_RED" "$C_OFF" "$k" "$st" "$detail" ;;
  esac
done
say ""
say "report: $REPORT"
