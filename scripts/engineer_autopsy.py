#!/usr/bin/env python3
"""engineer_autopsy.py — MULTI-BENCHMARK failure classifier for the AI Security Engineer.

The defensive twin of xbow_autopsy.py. XBOW autopsies the AI PENTESTER over ONE
benchmark (flag capture); the Engineer has no single equivalent, so this reads
EVERY benchmark that scores it, normalises them to one case-level record, and
reports the failure categories that SPAN benchmarks — those are the global
harness levers, the same "fix the category, never the case" discipline.

Testing against several benchmarks is not thoroughness for its own sake: one
benchmark can only tell you about itself, and a category that appears in only one
is as likely to be a property of that fixture as of the engineer (§14.2).

SOURCES (auto-detected per file — pass any mix; ledgers are JSONL, results JSON):

  cloud-engine   internal/bench/cloudengine_ledger.go   per SEED   (agent vs substrate
                 `tsbench cloud-engine --agent --ledger P`         head-to-head on a
                                                                   synthetic account)
  defense        internal/bench/defense_ledger.go       per SCENARIO (remediation
                 `tsbench defense --ledger P`                        capture; mode =
                                                                     substrate | agent)
  defense-xbow   internal/bench/defensexbow.go          per CHALLENGE (patch the vuln →
                 `tsbench defense-xbow --ledger P`                    the recorded exploit
                                                                      must stop capturing)
  cvepatch       internal/bench/cvepatch.go             per CVE INSTANCE (real CVE +
                 `tsbench cvepatch --dataset D --json > P`           gold-patch oracle)

  external keys  rendered text from the neutral corpora we did NOT author —
                 IAM-Vulnerable (BishopFox), Rhino GCP, SCuBA (CISA), CloudGoat.
                 Parsed from their own stable summary lines; an unparseable file is
                 reported UNPARSED, never as a zero (§10: "we could not look" and
                 "we looked and it was clean" are different claims).

TAXONOMY — the load-bearing split. A run can score badly for reasons that are NOT
the engineer's capability, and merging them means tuning against a benchmark that
is not measuring what you think it is:

  operator/eval (NEVER a capability miss)
    CONFIG              no model reached the agent / provider error → switch the model
    REFUSAL             the brain declined an AUTHORIZED task → model choice, not harness
    NON-DISCRIMINATING  the substrate already solved it at this budget → no headroom to
                        evaluate the agent; pick a headroom seed (--discrimination-sweep)
    EXCLUDED            the benchmark itself could not set up the test (not_vulnerable /
                        errored build) → the engineer was never fairly tested
    HALLUCINATED        invented > 0 → DISQUALIFIED. Grounding is structural (§10), so
                        this is a BUG to fix, never a tuning target.

  HARNESS TARGET (the real levers)
    NO-LIFT             agent added nothing over the substrate → prompt / estate traversal
    PARTIAL-RECALL      beat the substrate but still missed real paths → search control
    UNVERIFIED-FIX      found it, but the fix did not verify → the remediation loop
    NO-PATCH            produced no applicable patch at all → the patch generator
    INEFFECTIVE-PATCH   patched, app works, exploit STILL captures → the fix was cosmetic
    BROKE-APP           the "fix" broke the app → anti-sabotage regression guard
    MISLOCALIZED        patch produced but touched none of the gold files → localization
    UNJUDGED            a patch exists but no oracle ran → an EVAL gap, reported as itself
                        rather than counted as either success or failure

Usage:
  engineer_autopsy.py <file> [<file> …]
  engineer_autopsy.py --all [dir]     # every known ledger/result under dir (default /tmp/e2e/engineer)
"""
import json
import os
import re
import sys
from collections import defaultdict

# --- category sets -----------------------------------------------------------
# Only a CAPABILITY outcome may enter the engineer's score. An operator/eval state
# has no gradeable agent behaviour in it, and counting its zeros would misattribute
# a dead proxy (or a saturated fixture) to the engineer.
OPERATOR = {"CONFIG", "REFUSAL", "NON-DISCRIMINATING", "EXCLUDED", "HALLUCINATED", "UNJUDGED", "UNPARSED"}
CAPABILITY = {
    "SOLVED", "NO-LIFT", "PARTIAL-RECALL", "UNVERIFIED-FIX",
    "NO-PATCH", "INEFFECTIVE-PATCH", "BROKE-APP", "MISLOCALIZED",
}

UNVERIFIED_FLOOR = 0.5  # verified/remediation rate below this on an otherwise-solved run → the fix loop

REFUSAL_MARKERS = (
    "cannot assist", "can't assist", "unable to engage", "against my",
    "safety guidelines", "as an ai", "cannot help with", "not able to help",
)
CONFIG_MARKERS = (
    "not supported", "provider error", "invalid model", "needs an llm",
    "no llm", "unauthorized", "api key",
)


class Case:
    """One normalised benchmark case — the common shape every adapter produces."""

    def __init__(self, bench, case_id, category, solved, detail="", model="", cls=""):
        self.bench = bench
        self.case_id = case_id
        self.category = category
        self.solved = solved
        self.detail = detail
        self.model = model
        self.cls = cls  # vuln class, where the benchmark carries one — cross-bench signal


def _note_category(note, model=""):
    """Operator states readable from a free-text note/model field, or None."""
    hay = (note or "").lower()
    if any(m in hay for m in REFUSAL_MARKERS):
        return "REFUSAL"
    if any(m in hay for m in CONFIG_MARKERS):
        return "CONFIG"
    # A missing `model` field is PROVENANCE absent, not a dead brain — the campaign's
    # preflight smoke run is the health guard. Inferring CONFIG from it false-flags a
    # working run whose ledger simply didn't stamp the model (cloud-engine does not).
    return None


# --- adapters ----------------------------------------------------------------
def adapt_cloudengine(e):
    """cloudengine_ledger.go — per-seed agent-vs-substrate head-to-head."""
    cid = f"seed-{e.get('seed', '?')}"
    model = (e.get("model") or "").strip()
    grade = (e.get("grade") or "").upper()
    real = e.get("real_total", 0)
    agent = e.get("agent_found", 0)
    invented = e.get("invented", 0)
    lift = e.get("lift_paths", agent - e.get("engine_found", 0))
    vrate = e.get("verified_rate", 0.0)
    detail = f"lift {lift:+d} · recall {agent}/{real} · vfix {vrate*100:.0f}%"

    if grade == "DISQUALIFIED" or invented > 0:
        return Case("cloud-engine", cid, "HALLUCINATED", False, detail + f" · invented {invented}", model)
    cat = _note_category(e.get("note", ""), model)
    if cat:
        return Case("cloud-engine", cid, cat, False, detail, model)
    if not e.get("discriminating"):
        return Case("cloud-engine", cid, "NON-DISCRIMINATING", False, detail, model)
    solved = real > 0 and agent >= real
    if solved and vrate < UNVERIFIED_FLOOR:
        return Case("cloud-engine", cid, "UNVERIFIED-FIX", False, detail, model)
    if solved:
        return Case("cloud-engine", cid, "SOLVED", True, detail, model)
    if lift <= 0:
        return Case("cloud-engine", cid, "NO-LIFT", False, detail, model)
    return Case("cloud-engine", cid, "PARTIAL-RECALL", False, detail, model)


def adapt_defense(e):
    """defense_ledger.go — per-scenario remediation capture (mode substrate|agent)."""
    mode = e.get("mode", "")
    cid = f"{e.get('scenario_id', '?')}[{mode}]"
    closeable = e.get("closeable", 0)
    captured = e.get("captured", 0)
    rate = e.get("remediation_rate", 0.0)
    exp, found = e.get("expected_paths", 0), e.get("found_paths", 0)
    invented = e.get("invented", 0)
    detail = f"capture {captured}/{closeable} ({rate*100:.0f}%) · paths {found}/{exp} · decoys {e.get('decoy_actions', 0)}"

    if invented > 0:
        return Case("defense", cid, "HALLUCINATED", False, detail + f" · invented {invented}")
    cat = _note_category(e.get("note", ""), model="present")  # defense entries carry no model field
    if cat:
        return Case("defense", cid, cat, False, detail)
    if e.get("pass"):
        return Case("defense", cid, "SOLVED", True, detail)
    # Not a pass: separate "never found it" from "found it, fix didn't close it".
    if exp > 0 and found < exp:
        return Case("defense", cid, "PARTIAL-RECALL", False, detail)
    if closeable > 0 and captured < closeable:
        return Case("defense", cid, "UNVERIFIED-FIX", False, detail)
    return Case("defense", cid, "NO-LIFT", False, detail)


# defensexbow verdict → category (constants from internal/bench/defensexbow.go)
XBOW_DEF_VERDICT = {
    "remediated": ("SOLVED", True),
    "ineffective": ("INEFFECTIVE-PATCH", False),
    "broke_app": ("BROKE-APP", False),
    "no_patch": ("NO-PATCH", False),
    # The benchmark could not set the test up — the engineer was never fairly tested.
    "not_vulnerable": ("EXCLUDED", False),
    "errored": ("EXCLUDED", False),
}


def adapt_defensexbow(e):
    """defensexbow.go — per-challenge: patch it, the recorded exploit must stop capturing."""
    cid = e.get("benchmark_id", "?")
    model = (e.get("model") or "").strip()
    verdict = (e.get("verdict") or "").lower()
    cls = e.get("class", "")
    detail = f"verdict {verdict or '?'}"
    cat, solved = XBOW_DEF_VERDICT.get(verdict, (None, False))
    if cat is None:
        oc = _note_category(e.get("note", ""), model)
        cat = oc or "UNCLASSIFIED"
    # An operator state in the note outranks a bare no_patch: a refusing/dead brain
    # produces no patch for a reason that is not the patch generator's fault.
    elif cat == "NO-PATCH":
        oc = _note_category(e.get("note", ""), model)
        if oc:
            cat, solved = oc, False
    return Case("defense-xbow", cid, cat, solved, detail, model, cls)


def adapt_cvepatch(r):
    """cvepatch.go — per-instance real-CVE fix against a gold-patch oracle."""
    cid = r.get("id") or r.get("cve", "?")
    cls = r.get("class", "")
    fixed = (r.get("fixed") or "unknown").lower()
    produced, localized = r.get("produced", False), r.get("localized", False)
    err = r.get("err", "")
    detail = f"produced={produced} localized={localized} fixed={fixed}"
    if err:
        oc = _note_category(err, model="present")
        return Case("cvepatch", cid, oc or "EXCLUDED", False, detail + f" · {err[:40]}", cls=cls)
    if not produced:
        return Case("cvepatch", cid, "NO-PATCH", False, detail, cls=cls)
    if fixed == "fixed":
        return Case("cvepatch", cid, "SOLVED", True, detail, cls=cls)
    if fixed == "not_fixed":
        # It produced a patch that did not close the vuln. If it never touched a gold
        # file the failure is LOCALIZATION; otherwise the fix itself was wrong.
        return Case("cvepatch", cid, "MISLOCALIZED" if not localized else "INEFFECTIVE-PATCH", False, detail, cls=cls)
    # fixed == unknown: a patch exists but no oracle judged it. Reporting this as a
    # pass would invent a result; as a failure would blame the engineer for our own
    # missing oracle. It is an EVAL gap and says so.
    return Case("cvepatch", cid, "UNJUDGED", False, detail, cls=cls)


# --- external neutral keys (rendered text) -----------------------------------
# Each parser targets ONE stable summary line printed by our own renderer. A file
# we cannot parse yields UNPARSED — never a zero, and never silence.
EXTERNAL_PATTERNS = [
    ("IAM-Vulnerable (BishopFox)", re.compile(r"paths scored:\s*(\d+)\s+detected:\s*(\d+)")),
    ("Rhino GCP privesc", re.compile(r"methods scored:\s*(\d+)\s+detected:\s*(\d+)")),
    ("CloudGoat (Rhino)", re.compile(r"calibration:\s*(\d+)\s*/\s*(\d+)\s*scenarios")),
]
SCUBA_TOTAL = re.compile(r"scanner-detectable:\s*\*\*(\d+)\*\*")
SCUBA_FULL = re.compile(r"detected in full:\s*\*\*(\d+)\*\*")


def parse_external(text, path):
    """Return (name, hits, total) or (None, ...) — the neutral-corpus ceiling."""
    for name, pat in EXTERNAL_PATTERNS:
        m = pat.search(text)
        if m:
            a, b = int(m.group(1)), int(m.group(2))
            # "paths scored: T detected: H" vs "calibration: H/T scenarios"
            return (name, a, b) if "calibration" in pat.pattern else (name, b, a)
    ft, ff = SCUBA_TOTAL.search(text), SCUBA_FULL.search(text)
    if ft and ff:
        return ("SCuBA (CISA)", int(ff.group(1)), int(ft.group(1)))
    return (None, 0, 0)


# --- ingestion ---------------------------------------------------------------
def detect_and_adapt(path):
    """Return (cases, external_row_or_None). Schema is detected from the record's
    own discriminating fields, so any mix of files can be passed in any order."""
    try:
        raw = open(path, encoding="utf-8", errors="ignore").read()
    except OSError as exc:
        print(f"  ! {path}: {exc}", file=sys.stderr)
        return [], None
    if not raw.strip():
        return [], None

    text = raw.lstrip()
    cases = []

    # JSON array → cvepatch results (the only array-shaped source).
    if text.startswith("["):
        try:
            for r in json.loads(text):
                if isinstance(r, dict) and ("cve" in r or "produced" in r):
                    cases.append(adapt_cvepatch(r))
            return cases, None
        except json.JSONDecodeError:
            pass

    # JSONL → one of the three ledgers, detected per line.
    if text.startswith("{"):
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                e = json.loads(line)
            except json.JSONDecodeError:
                continue
            if not isinstance(e, dict):
                continue
            if "seed" in e and ("discriminating" in e or "lift_paths" in e):
                cases.append(adapt_cloudengine(e))
            elif "scenario_id" in e:
                cases.append(adapt_defense(e))
            elif "benchmark_id" in e and "verdict" in e:
                cases.append(adapt_defensexbow(e))
            elif "cve" in e or "produced" in e:
                cases.append(adapt_cvepatch(e))
        if cases:
            return cases, None

    # Otherwise: a rendered external-key report.
    name, hits, total = parse_external(raw, path)
    if name:
        return [], (name, hits, total, path)
    return [], ("UNPARSED", 0, 0, path)


def main():
    argv = sys.argv[1:]
    if not argv:
        print(__doc__)
        sys.exit(2)
    if argv[0] == "--all":
        root = argv[1] if len(argv) > 1 else "/tmp/e2e/engineer"
        argv = []
        for dirpath, dirnames, names in os.walk(root):
            # `work/` holds the campaign's TRANSIENT files — the brain-health smoke run
            # and the discrimination sweep. Neither is a benchmark result: the smoke run
            # would pollute the case table with a throwaway seed, and the sweep is not a
            # score at all and would read as UNPARSED. Skipped by construction.
            dirnames[:] = [d for d in dirnames if d != "work"]
            for n in names:
                if n.endswith((".jsonl", ".json", ".txt", ".md")):
                    argv.append(os.path.join(dirpath, n))
        if not argv:
            print(f"no ledger/result files under {root}")
            sys.exit(1)

    all_cases, externals = [], []
    for p in sorted(argv):
        cases, ext = detect_and_adapt(p)
        all_cases.extend(cases)
        if ext:
            externals.append(ext)

    # EVER-BEST per (bench, case): a later capability win supersedes an earlier
    # operator/eval miss, so a dead-proxy run never masks a real result.
    tier = {"SOLVED": 6, "UNVERIFIED-FIX": 5, "PARTIAL-RECALL": 4, "INEFFECTIVE-PATCH": 4,
            "MISLOCALIZED": 4, "BROKE-APP": 3, "NO-PATCH": 3, "NO-LIFT": 2,
            "UNJUDGED": 1, "NON-DISCRIMINATING": 1, "EXCLUDED": 1,
            "REFUSAL": 0, "CONFIG": 0, "UNCLASSIFIED": 0, "HALLUCINATED": -1}
    best, attempts = {}, defaultdict(int)
    for c in all_cases:
        k = (c.bench, c.case_id)
        attempts[k] += 1
        if k not in best or tier.get(c.category, 0) > tier.get(best[k].category, 0):
            best[k] = c

    # ---- neutral external ceiling (the number that is not ours to author) ----
    print("== neutral external keys (corpora we did NOT author — the honest ceiling) ==")
    if externals:
        for name, hits, total, path in externals:
            if name == "UNPARSED":
                print(f"  {'UNPARSED':<28} {os.path.basename(path)} — could not read a score "
                      f"(reported as unknown, NOT as zero)")
            else:
                pct = (hits / total * 100) if total else 0.0
                print(f"  {name:<28} {hits}/{total}  ({pct:.1f}%)")
    else:
        print("  none supplied — pass the rendered reports (cloud-engine --cloudgoat, the")
        print("  IAM-Vulnerable / Rhino / SCuBA go-test output) to anchor the capability claim.")

    # ---- per-case table -----------------------------------------------------
    print(f"\n== cases ==\n{'benchmark':13} {'case':26} {'result':7} {'att':>3}  {'failure-mode':18} detail")
    cats = defaultdict(list)          # category → [(bench, case)]
    per_bench = defaultdict(lambda: defaultdict(int))
    for (bench, cid), c in sorted(best.items()):
        res = "SOLVED" if c.solved else "miss"
        per_bench[bench]["total"] += 1
        per_bench[bench]["solved" if c.solved else "miss"] += 1
        if c.category in CAPABILITY:
            per_bench[bench]["evald"] += 1
        if not c.solved:
            cats[c.category].append((bench, cid))
        print(f"{bench:13} {cid[:26]:26} {res:7} {attempts[(bench, cid)]:>3}  {c.category:18} {c.detail[:44]}")

    # ---- per-benchmark roll-up ---------------------------------------------
    print(f"\n== per benchmark ==\n{'benchmark':13} {'solved':>7} {'evald':>7} {'cases':>6}  capture")
    for bench in sorted(per_bench):
        d = per_bench[bench]
        ev = d["evald"]
        cap = f"{d['solved']}/{ev}" if ev else "— (no run evaluated the engineer)"
        print(f"{bench:13} {d['solved']:>7} {ev:>7} {d['total']:>6}  {cap}")

    # ---- cross-benchmark categories: the global levers ----------------------
    print("\n== failure categories — SPAN-FIRST (a category crossing benchmarks is the global lever) ==")

    def span(ids):
        return len({b for b, _ in ids})

    ordered = sorted(cats.items(), key=lambda kv: (-span(kv[1]), -len(kv[1])))
    for cat, ids in ordered:
        benches = sorted({b for b, _ in ids})
        if cat in OPERATOR:
            tag = "operator/eval — NOT a capability miss"
        elif span(ids) >= 2:
            tag = "*** GLOBAL LEVER (spans benchmarks) ***"
        else:
            tag = "harness target (single benchmark — may be a fixture property)"
        print(f"{cat:18} {len(ids):>3} case(s) across {span(ids)} benchmark(s) [{', '.join(benches)}]  {tag}")

    # ---- honest totals ------------------------------------------------------
    solved = sum(1 for c in best.values() if c.solved)
    evald = sum(1 for c in best.values() if c.category in CAPABILITY)
    print(f"\ncases: {len(best)}   solved: {solved}   runs that actually evaluated the engineer: {evald}")
    if evald:
        print(f"capability capture over the eval'd set: {solved}/{evald} ({solved/evald*100:.1f}%)")
        print("  (operator/eval cases are EXCLUDED — a dead proxy or a saturated fixture is not")
        print("   the engineer's failure, and counting it would misattribute the score.)")
    elif best:
        print("NO case actually evaluated the engineer — every case was an operator/eval state.")
        print("  fix the model/proxy, or pick headroom seeds (cloud-engine --discrimination-sweep N).")
    else:
        print("no benchmark CASES supplied — the ceiling above says what the substrate can reach,")
        print("  but nothing here measured the engineer. Run the agent benchmarks and pass their ledgers.")
    if not externals:
        print("\nNOTE: no neutral external key supplied, so the numbers above are OUR OWN fixtures")
        print("  (regression signal, not an efficacy claim — §14.2 rule 5).")


if __name__ == "__main__":
    main()
