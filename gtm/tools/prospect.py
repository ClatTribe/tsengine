#!/usr/bin/env python3
"""
prospect.py — turn a list of domains into evidence-led outbound.

The outbound motion in ../outbound-sourcing.md has one step that does not scale by hand:
run every sourced domain through the public assessment, then open each email with a true
fact about that company's own domain. Doing that for two hundred domains by hand is why
people give up and send a template instead.

    python3 gtm/tools/prospect.py domains.txt --api https://app.tensorshield.io > out.csv

Input:  one domain per line ('#' comments and blank lines ignored). '-' reads stdin.
Output: CSV on stdout — domain, grade, score, failed, total, hook_check, opening_line,
        fix_summary, status.

Two rules it enforces, because they are the whole reason this motion works:

  1. NEVER INVENT A FINDING. If the scan errors, the row is written with status=error and
     an EMPTY opening line. It is not skipped silently — a missing row is easy to miss and
     easy to backfill with a guess. A row that says "error" cannot be mailed by accident.
  2. A CLEAN DOMAIN GETS THE CLEAN-SCAN LINE, never a manufactured problem. A domain that
     passes everything is a real opening, not a failure — 1 of the first 8 scanned did.

Stdlib only — no pip install, so it runs on any machine that has Python.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

# Priority order for choosing the ONE check to open on, from ../signals.md.
#
# Email auth leads NOT because it is common — the first real run found zero DMARC/SPF/DKIM gaps
# across eight live B2B SaaS domains — but because when it does fire it is the strongest opener
# available: verifiable by the reader in ten seconds, no security background needed to feel it,
# and a one-record fix. It is ordered first so it wins when present, not because it usually is.
# Re-measure on your own list; the distribution is in ../signals.md.
#
# Names must match the API's `checks[].name` exactly.
HOOKS: list[tuple[str, str]] = [
    ("DMARC enforcement", "Anyone can send email as @{domain} right now — your DMARC isn't set to reject or quarantine, so a forged invoice from your domain lands in your customer's inbox looking legitimate."),
    ("SPF", "{domain} doesn't publish a sender policy, so mail forged from your domain isn't rejected."),
    ("DKIM", "Mail from {domain} isn't cryptographically signed, so a receiving server can't tell a forgery from the real thing."),
    # The header hooks below fire FAR more often than the email-auth ones in practice (see the
    # measured distribution in ../signals.md), and they are the weaker openers: a founder feels
    # "anyone can email your customers as you" and feels nothing about "no content-security-policy".
    # So each lands on the SECURITY REVIEW — the thing the reader already cares about — instead of
    # on the vulnerability class, which they don't.
    ("HTTPS enforced", "{domain} still answers on plain HTTP — that's a first-page question on most vendor security reviews."),
    ("HSTS", "{domain} is missing HSTS, so a first visit can be silently downgraded to HTTP. It's one of the handful of headers an enterprise reviewer checks from the outside, usually before they even send the questionnaire."),
    ("Content-Security-Policy", "{domain} has no content-security-policy header. It's one of the first things a security reviewer checks from outside, it's a one-line change, and it's an easy thing to have already fixed by the time they ask."),
    ("Clickjacking & MIME protections", "{domain} can be loaded inside an attacker's iframe — the two headers that prevent that aren't set. Reviewers check them from outside, and it's a one-line fix."),
    ("Security contact (security.txt)", "There's no documented way for a researcher to report a vulnerability to you — reviewers check for this."),
]

CLEAN_LINE = (
    "Ran the public checks on {domain} — all {total} pass, which is rarer than it should be. "
    "That's the outside view; the questions that actually stall enterprise deals are the ones "
    "nobody can check from outside."
)


def assess(api: str, domain: str, timeout: float) -> dict:
    url = f"{api.rstrip('/')}/v1/assess?" + urllib.parse.urlencode({"domain": domain})
    req = urllib.request.Request(url, headers={"User-Agent": "tensorshield-prospect/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return json.loads(r.read().decode("utf-8"))


def row_for(domain: str, data: dict) -> dict:
    checks = data.get("checks") or []
    # `ok` is the source of truth for pass/fail, NOT score: a check can be ok-but-imperfect
    # (DMARC p=quarantine rather than p=reject), which lowers the score while still passing.
    failing = {c.get("name"): c for c in checks if not c.get("ok")}
    q = data.get("questionnaire") or {}
    total = q.get("total") or len(checks)

    hook_name, opening, fix_summary = "", "", ""
    for name, line in HOOKS:
        if name in failing:
            hook_name = name
            opening = line.format(domain=domain)
            fix = failing[name].get("fix") or {}
            fix_summary = (fix.get("summary") or "").strip()
            break
    if not hook_name:
        # Clean scan (or every failure is a check this script has no hook for — same handling,
        # because opening on a check we have not written a human line for produces jargon).
        opening = CLEAN_LINE.format(domain=domain, total=total)
        hook_name = "clean"

    return {
        "domain": domain,
        "grade": data.get("grade", ""),
        "score": data.get("score", ""),
        "failed": q.get("failed", len(failing)),
        "total": total,
        "hook_check": hook_name,
        "opening_line": opening,
        "fix_summary": fix_summary,
        "status": "ok",
    }


def read_domains(path: str) -> list[str]:
    fh = sys.stdin if path == "-" else open(path, encoding="utf-8")
    try:
        out, seen = [], set()
        for raw in fh:
            d = raw.strip().lower()
            if not d or d.startswith("#"):
                continue
            # Tolerate pasted URLs and stray paths — sourcing lists are rarely clean.
            d = d.replace("https://", "").replace("http://", "").split("/")[0].strip()
            if d and d not in seen:
                seen.add(d)
                out.append(d)
        return out
    finally:
        if fh is not sys.stdin:
            fh.close()


def main() -> int:
    p = argparse.ArgumentParser(description="Domains -> evidence-led opening lines (see gtm/outbound-sourcing.md)")
    p.add_argument("domains", help="file with one domain per line, or '-' for stdin")
    p.add_argument("--api", default="http://localhost:8090", help="platform base URL")
    p.add_argument("--delay", type=float, default=2.0,
                   help="seconds between requests (default 2). /v1/assess is rate-limited per IP "
                        "on purpose; do not spread requests across IPs to evade it")
    p.add_argument("--timeout", type=float, default=30.0)
    args = p.parse_args()

    domains = read_domains(args.domains)
    if not domains:
        print("no domains given", file=sys.stderr)
        return 2

    cols = ["domain", "grade", "score", "failed", "total", "hook_check", "opening_line", "fix_summary", "status"]
    w = csv.DictWriter(sys.stdout, fieldnames=cols)
    w.writeheader()

    ok = errors = clean = 0
    for i, d in enumerate(domains):
        try:
            row = row_for(d, assess(args.api, d, args.timeout))
            ok += 1
            if row["hook_check"] == "clean":
                clean += 1
        except (urllib.error.URLError, urllib.error.HTTPError, json.JSONDecodeError, TimeoutError, OSError) as e:
            # Rule 1: the row still gets written, with an empty opening line, so it is visible
            # and un-mailable rather than quietly missing.
            errors += 1
            row = {c: "" for c in cols}
            row.update(domain=d, hook_check="", opening_line="", status=f"error: {type(e).__name__}")
        w.writerow(row)
        sys.stdout.flush()
        if i < len(domains) - 1:
            time.sleep(args.delay)

    print(f"\n{len(domains)} domains — {ok} scanned ({clean} clean), {errors} errors",
          file=sys.stderr)
    if errors:
        print("rows with status=error have an empty opening line on purpose: never mail a "
              "finding that did not actually run.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
