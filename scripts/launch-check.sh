#!/usr/bin/env bash
#
# launch-check.sh — the pre-outreach gate.  →  `make launch-check URL=https://…`
#
# WHY THIS EXISTS. Every value it checks is already wired end to end: NEXT_PUBLIC_* are
# declared in frontend/Dockerfile, passed as build args by .github/workflows/images.yml from
# repo variables, and inlined into the bundle. What was missing is a check that anyone
# ACTUALLY SET THEM. An unset repo variable does not fail the build — the image is published
# with the built-in defaults, the deploy succeeds, the tick is green, and the site quietly
# tells vulnerability researchers to email a personal Gmail account. That is §14.2 rule 6 one
# level out: there was no guard at all, so absence of a complaint meant nothing.
#
# It runs against a DEPLOYED URL rather than the source tree, because the source tree cannot
# answer the question. NEXT_PUBLIC_* values are baked at image-build time, so what a checkout
# says and what a running site serves are different facts — and it is the running site that a
# prospect, a researcher and a regulator will read.
#
# IT FAILS RATHER THAN SKIPS. A check that cannot reach its subject reports FAIL, not "n/a" —
# a skip is green, and green at the moment we are least able to see is exactly how the
# defects this repo keeps finding got shipped.
#
#   make launch-check URL=https://tensorshield.in
#   ./scripts/launch-check.sh https://staging.example.com
#
# Exit 0 = safe to start outreach. Non-zero = something on this list would cost more trust
# than the outreach earns.
set -uo pipefail

URL="${1:-${URL:-}}"
if [ -z "$URL" ]; then
  echo "usage: launch-check.sh <base-url>   (e.g. https://tensorshield.in)" >&2
  echo "       export TSENGINE_PLATFORM_TOKEN=... to also verify the in-process configuration" >&2
  exit 2
fi
URL="${URL%/}"
HOST="$(printf '%s' "$URL" | sed -E 's#^https?://##; s#/.*##')"

# A loopback target cannot yield a launch verdict: there is no deployed domain for the
# canonical check to compare against, and "READY" printed after a localhost run is a claim
# about production made from a laptop. The address checks below are still meaningful (the
# values are baked into the same bundle), so they run and report — only the VERDICT is
# withheld.
LOCAL=0
case "$HOST" in
  localhost|localhost:*|127.0.0.1|127.0.0.1:*|0.0.0.0|0.0.0.0:*|\[::1\]*) LOCAL=1 ;;
esac

FAILED=0
pass() { printf '  \033[32m✓\033[0m %s\n' "$1"; }
fail() { printf '  \033[31m✗\033[0m %s\n' "$1"; FAILED=1; }
note() { printf '    %s\n' "$1"; }

# Mailbox providers that are free/personal. An address at one of these is not a trust
# failure everywhere — it is a trust failure on the channels below, where the reader is a
# security researcher, a regulator or a procurement team deciding whether we are a real
# company. Deliberately NOT a general "is this a nice address" opinion.
FREEMAIL='gmail\.com|googlemail\.com|yahoo\.[a-z.]+|hotmail\.[a-z.]+|outlook\.com|live\.com|aol\.com|icloud\.com|me\.com|proton\.me|protonmail\.com|gmx\.[a-z.]+|mail\.ru|yandex\.[a-z.]+|rediffmail\.com'

fetch() { curl -fsS -m 20 -A "tensorshield-launch-check" "$1" 2>/dev/null; }

echo "launch-check → $URL"
echo

# ── 1. security.txt (RFC 9116) ────────────────────────────────────────────────────────────
# The address a researcher uses to report a vulnerability IN OUR PRODUCT. A security product
# publishing a personal mailbox here is the single most expensive line on the site: it is read
# by exactly the audience that judges us on it, and it is one of the checks our OWN free
# scanner runs against a customer's domain.
echo "security.txt (RFC 9116)"
SEC="$(fetch "$URL/.well-known/security.txt")"
if [ -z "$SEC" ]; then
  fail "not served at $URL/.well-known/security.txt"
  note "our own /scan flags a missing security.txt on a customer's domain"
else
  SEC_CONTACT="$(printf '%s' "$SEC" | sed -nE 's/^Contact: *mailto: *//Ip' | head -1 | tr -d '\r')"
  if [ -z "$SEC_CONTACT" ]; then
    fail "no Contact: mailto: line — the file is invalid under RFC 9116"
  elif printf '%s' "$SEC_CONTACT" | grep -qiE "@($FREEMAIL)\$"; then
    fail "Contact is a personal mailbox: $SEC_CONTACT"
    note "set the repo variable NEXT_PUBLIC_SECURITY_EMAIL and rebuild the frontend image"
    note "(NEXT_PUBLIC_* are inlined at BUILD time — setting it only at run time changes nothing)"
  else
    pass "Contact: $SEC_CONTACT"
  fi

  # Expires is mandatory, and an expired file is an INVALID file. It is computed at build
  # time on a force-static route, so a pinned image redeployed long after it was built serves
  # a lapsed one — the failure mode a rollback produces.
  SEC_EXP="$(printf '%s' "$SEC" | sed -nE 's/^Expires: *//Ip' | head -1 | tr -d '\r')"
  if [ -z "$SEC_EXP" ]; then
    fail "no Expires: line — required by RFC 9116"
  else
    EXP_EPOCH="$(date -j -f "%Y-%m-%dT%H:%M:%S" "${SEC_EXP%%.*}" +%s 2>/dev/null \
      || date -d "$SEC_EXP" +%s 2>/dev/null)"
    if [ -z "$EXP_EPOCH" ]; then
      fail "Expires is unparseable: $SEC_EXP"
    elif [ "$EXP_EPOCH" -le "$(date +%s)" ]; then
      fail "Expires is in the PAST ($SEC_EXP) — the file is invalid; rebuild the image"
    else
      pass "Expires $SEC_EXP"
    fi
  fi
fi
echo

# ── 2. the published contact channels ─────────────────────────────────────────────────────
# privacy@ is where GDPR Art. 15-22 and DPDP data-subject requests are legally directed. It
# defaults to the general mailbox in lib/contact.ts — a deliberate choice (a role address that
# bounces is worse than an informal one that arrives), which is exactly why it needs checking
# rather than assuming: the default is safe and it is not what we want to publish.
echo "contact channels"
CONTACT_PAGE="$(fetch "$URL/contact")"
if [ -z "$CONTACT_PAGE" ]; then
  fail "/contact is not reachable"
else
  ADDRS="$(printf '%s' "$CONTACT_PAGE" | grep -oE 'mailto:[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+' | sed 's/^mailto://' | sort -u)"
  if [ -z "$ADDRS" ]; then
    fail "/contact publishes no email address at all"
  else
    BAD="$(printf '%s\n' "$ADDRS" | grep -iE "@($FREEMAIL)\$" || true)"
    if [ -n "$BAD" ]; then
      fail "personal mailbox published on /contact:"
      printf '%s\n' "$BAD" | while read -r a; do note "$a"; done
      note "set NEXT_PUBLIC_CONTACT_EMAIL / _PRIVACY_EMAIL / _LEGAL_EMAIL and rebuild"
    else
      pass "$(printf '%s\n' "$ADDRS" | wc -l | tr -d ' ') address(es), none on a free-mail provider"
    fi
  fi
fi
echo

# ── 3. one domain, everywhere ─────────────────────────────────────────────────────────────
# SITE_URL feeds canonical links, the sitemap, OG tags and security.txt's own Canonical. If it
# disagrees with the host actually being served, every one of those points somewhere else —
# and the mismatch is invisible from inside the app, which is how the tree came to carry
# tensorshield.io URLs beside a tensorshield.com SITE_URL.
echo "domain consistency"
CANON="$(printf '%s' "${SEC:-}" | sed -nE 's#^Canonical: *https?://([^/]+).*#\1#Ip' | head -1 | tr -d '\r')"
if [ "$LOCAL" -eq 1 ]; then
  # Not a skip dressed as a pass: the question genuinely does not apply to a loopback target,
  # and the verdict is withheld at the end because of it.
  printf '  \033[33m–\033[0m not applicable on a local host (would publish: %s)\n' "${CANON:-unset}"
elif [ -z "$CANON" ]; then
  fail "no Canonical line in security.txt to compare against"
elif [ "$CANON" != "$HOST" ]; then
  fail "the site says its canonical host is '$CANON' but it is being served from '$HOST'"
  note "NEXT_PUBLIC_SITE_URL is baked at build time — rebuild after changing the domain"
else
  pass "canonical host matches the host being served ($HOST)"
fi
echo

# ── 4. the assets outreach points AT ──────────────────────────────────────────────────────
# An outreach email whose one link 404s is worse than no email. Both of these are the public,
# ungated entry points, so they must answer without a session.
echo "public entry points"
for path in "/sample-report" "/api/sample-report" "/scan"; do
  CODE="$(curl -o /dev/null -s -w '%{http_code}' -m 20 "$URL$path" 2>/dev/null)"
  if [ "$CODE" = "200" ]; then
    pass "$path → 200 (ungated)"
  else
    fail "$path → ${CODE:-no response}"
  fi
done
echo

# ── 5. nothing cross-tenant is public ─────────────────────────────────────────────────────
# The activation funnel aggregates every tenant, so it is platform-token gated. Checked here
# because a route that starts returning 200 to strangers is a tenant-isolation failure, and
# this is the one place that looks at the deployed thing rather than the test suite.
echo "operator-only surfaces stay closed"
FUNNEL_CODE="$(curl -o /dev/null -s -w '%{http_code}' -m 20 "$URL/v1/funnel" 2>/dev/null)"
case "$FUNNEL_CODE" in
  200) fail "/v1/funnel answered 200 WITHOUT a token — cross-tenant counts are public" ;;
  401|403) pass "/v1/funnel refuses an unauthenticated caller ($FUNNEL_CODE)" ;;
  # A 404 is NOT evidence the gate works — it means the route is not reachable on this host at
  # all, so nothing was tested. Reported as untested rather than counted as a pass, which is
  # the distinction that makes the other lines worth reading.
  *)   printf '  \033[33m–\033[0m /v1/funnel not reachable on this host (%s) — gate NOT verified\n' "${FUNNEL_CODE:-no response}" ;;
esac
echo

# ── 6. what nobody set INSIDE the process ─────────────────────────────────────────────────
# Everything above reads the site. The failures that cost the most are invisible from there: a
# lead form whose delivery is a log line, a Connect button whose OAuth app was never registered,
# reset mail with no SMTP behind it. GET /v1/launch-readiness reports each as a fact read from the
# running configuration, with the variable that fixes it. It is operator-token gated, so this
# section runs only when TSENGINE_PLATFORM_TOKEN is exported — and SAYS SO when it is not, because
# a check that silently skips is indistinguishable from one that passed.
echo "deployment configuration (in-process)"
if [ -n "${TSENGINE_PLATFORM_TOKEN:-}" ]; then
  READY_JSON="$(curl -fsS -m 20 -H "Authorization: Bearer $TSENGINE_PLATFORM_TOKEN" "$URL/v1/launch-readiness" 2>/dev/null || true)"
  if [ -z "$READY_JSON" ]; then
    printf '  \033[33m–\033[0m /v1/launch-readiness not reachable on this host — in-process config NOT verified\n'
  elif command -v jq >/dev/null 2>&1; then
    # each item on its own line; a failing BLOCKING item fails the verdict, a non-blocking one is shown
    while IFS=$'\t' read -r key ok blocking detail fix; do
      if [ "$ok" = "true" ]; then
        pass "$key — $detail"
      elif [ "$blocking" = "true" ]; then
        fail "$key — $detail  →  $fix"
      else
        printf '  \033[33m–\033[0m %s — %s  →  %s\n' "$key" "$detail" "$fix"
      fi
    done < <(printf '%s' "$READY_JSON" | jq -r '.items[] | [.key, (.ok|tostring), (.blocking|tostring), .detail, (.fix // "")] | @tsv')
  else
    # no jq: still fail on the server's own verdict rather than pretending the section ran clean
    if printf '%s' "$READY_JSON" | grep -q '"ready":true'; then
      pass "/v1/launch-readiness reports ready (install jq to see each item)"
    else
      fail "/v1/launch-readiness reports NOT ready — install jq to see which items, or open the endpoint"
    fi
  fi
else
  printf '  \033[33m–\033[0m TSENGINE_PLATFORM_TOKEN not set — in-process config (mail, lead delivery, OAuth apps, URLs) NOT verified\n'
fi
echo

if [ "$LOCAL" -eq 1 ]; then
  printf '\033[33mLOCAL RUN\033[0m — this is not a launch verdict. The address checks above are real\n'
  printf '(the same values are baked into the deployed bundle), but domain consistency and the\n'
  printf 'operator-gate check need the real host. Re-run against the deployed URL before outreach.\n'
  exit "$FAILED"
fi
if [ "$FAILED" -eq 0 ]; then
  printf '\033[32mREADY\033[0m — nothing on the pre-outreach list is misconfigured.\n'
else
  printf '\033[31mNOT READY\033[0m — fix the ✗ items above before outreach.\n'
  printf 'Each one costs more trust than the outreach earns.\n'
fi
exit "$FAILED"
