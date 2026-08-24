#!/bin/sh
# verify-tools.sh — assert the image actually CONTAINS the scanners it claims to.
#
# WHY THIS EXISTS. internal/toolsbundle's image-coverage test asks "does this tool's name appear in
# the Dockerfile?" — a textual check, and its own doc says so. That verifies INTENT. It passed for
# months while codeql and kics were ABSENT from every image, because both appear in the Dockerfile on
# the install lines that were 404-ing:
#
#   codeql: the release ships codeql-linux64.ZIP; we fetched .tar.gz
#   kics:   v2.1.3 publishes no platform binaries at all, and the arch string was wrong too
#
# Both failures were swallowed by `|| echo "non-fatal"`, so the build exited 0, and the repository
# asset shipped with no taint-analysis escalation and no deeper IaC pass. `tool-freshness` meanwhile
# reported both as "pinned" — asserting a version for a binary that was not there.
#
# So this checks the OUTCOME, inside the image, at build time. A missing scanner is a broken build,
# not a log line nobody reads.
#
# It runs only for TOOLSET=full, which is what production runs. A slim image is EXPECTED to stub the
# tools it excluded (toolset.sh writes a stub exiting 127, which tool.DidNotRun reports honestly), so
# asserting presence there would be asserting the opposite of the design.
set -eu

: "${TS_TOOLSET:=full}"
if [ "$TS_TOOLSET" != "full" ]; then
    echo "verify-tools: TOOLSET=$TS_TOOLSET (slim) — skipping the completeness check by design"
    exit 0
fi

# Kept in sync with the wrappers by TestVerifyToolsListMatchesTheWrappers; a binary added to a wrapper
# and not here fails that test rather than silently going unverified.
BINARIES="amass apkid bandit checkdmarc checkov cloudfox codeql cosign dalfox dnstwist dockle ffuf
gitleaks gosec govulncheck grype hadolint httpx hydra inql katana kics kr mobsfscan modelscan naabu
nikto nmap nuclei osv-scanner padbuster prowler schemathesis scout semgrep sqlmap subfinder syft
trivy trufflehog wpscan"

# codeql has no arm64 build upstream, so on an arm64 image it is deliberately a stub (see the
# Dockerfile). Asserting its presence there would demand something that does not exist.
ARCH_EXEMPT=""
if [ "$(uname -m)" != "x86_64" ]; then
    ARCH_EXEMPT="codeql"
    echo "verify-tools: $(uname -m) — codeql exempt (upstream ships no arm64 CLI)"
fi

missing=""
stubbed=""
for b in $BINARIES; do
    case " $ARCH_EXEMPT " in *" $b "*) continue ;; esac
    path=$(command -v "$b" 2>/dev/null) || { missing="$missing $b"; continue; }
    # toolset.sh writes stubs as shell scripts carrying this sentence. Detected by READING the file
    # rather than running it: running forty scanners at build time is slow, and some of them do real
    # work when invoked bare.
    if head -c 2 "$path" 2>/dev/null | grep -q '#!' && grep -q "is not installed in this image" "$path" 2>/dev/null; then
        stubbed="$stubbed $b"
    fi
done

if [ -n "$missing" ] || [ -n "$stubbed" ]; then
    echo "FATAL: a TOOLSET=full image is missing scanners it claims to ship." >&2
    [ -n "$missing" ] && echo "  ABSENT (install failed or was never wired):$missing" >&2
    [ -n "$stubbed" ] && echo "  STUBBED (gated out of a build that should include everything):$stubbed" >&2
    echo "  A scan dispatching these reports them in ToolsFailed — honest, but nobody learns until a" >&2
    echo "  customer's scan degrades. Fix the install; do not relax this check." >&2
    exit 1
fi

# ---------------------------------------------------------------------------
# CORPORA. A binary without its rules is not a working scanner.
#
# The binary checks above would have passed happily on an image where kics had no queries, ffuf had
# no wordlist and nuclei had no templates — every one of those RUNS and returns nothing, which reads
# as a clean scan and is worse than the tool being absent, because an absent tool lands in
# ToolsFailed and a ruleless one does not. kics shipped exactly that way.
#
# Each entry is "<description>|<test>". Kept small on purpose: only corpora a scanner DEFAULTS to,
# where its absence is silent.
# ---------------------------------------------------------------------------
corpus_missing=""
check_corpus() {
    # $1 description, $2 a path that must exist and be non-empty (file) or contain a match (glob)
    if [ ! -s "$2" ]; then
        corpus_missing="$corpus_missing
    $1 ($2)"
    fi
}
check_corpus "nuclei templates"  "$(find /home/tsengine/nuclei-templates -name '*.yaml' 2>/dev/null | head -1)"
check_corpus "kics queries"      "$(find /opt/kics/assets/queries -name '*.rego' 2>/dev/null | head -1)"
check_corpus "ffuf wordlist"     "/usr/share/seclists/Discovery/Web-Content/common.txt"
check_corpus "kiterunner routes" "$(find /usr/share/kiterunner -name '*.kite' 2>/dev/null | head -1)"

if [ -n "$corpus_missing" ]; then
    echo "FATAL: a TOOLSET=full image is missing detection corpora:$corpus_missing" >&2
    echo "  A scanner without its rules RUNS and returns nothing, which reads as a clean scan." >&2
    exit 1
fi

echo "verify-tools: all $(echo $BINARIES | wc -w) scanner binaries present and non-stubbed, and every corpus loaded"
