#!/usr/bin/env python3
"""bountybench_to_cvepatch.py — turn BountyBench PATCH tasks into an agentic `tsbench cvepatch` set.

WHY THIS EXISTS. `tsbench bountybench` inventories the corpus and reports the honest denominator
("22 of 46 in a class we cover"). That is a real number, but it measures the SUBSTRATE — which
vulnerability classes our detectors handle. It never runs the agent, so it says nothing about the AI
Security Engineer's harness, which is the thing under test. A benchmark that does not exercise the
LLM cannot answer "is the engineer any good".

BountyBench already carries what an agentic run needs, so no new scoring machinery is required:

    patch_files/<file>     the FIXED file — the gold patch, as whole-file content
    codebase/<file>        the same file BEFORE the fix — the vulnerable source
    bounty_metadata.json   CWE + vulnerable_commit

That is exactly `cvepatch`'s shape (vuln_files + gold_files + gold_anchors), and cvepatch already
drives codeagent.ProposePatch. So the same corpus that gave us a denominator can grade the engineer.

SAFETY / DISK — read-only and offline by construction:
  * Nothing from the corpus is EXECUTED. Each bounty ships exploit_files/, verify_files/ and
    run_bounty_invariants.sh; running any of them would execute a real exploit to produce a number.
    We read text only.
  * NO network. Unlike the CVE-Bench converter (which fetched sources from raw.githubusercontent),
    every byte here is already on disk in the clone — vulnerable source and gold patch both.
  * The EXECUTION ORACLE IS NOT WIRED. `verify` is left unset, so `fixed` stays unjudged and the run
    reports produced + localized + anchors. Their verify.sh remains the only thing that may claim a
    fix works, and we do not run it.

GROUNDING (§10): a task is emitted ONLY when the same relative path exists in both patch_files/ and
codebase/ — that pairing is what makes the gold patch a real before/after rather than an assumption.
Anything unpaired is REPORTED as skipped, never silently dropped, so the denominator stays honest.

Usage: bountybench_to_cvepatch.py <bountytasks-dir> <out.json> [--limit N]
"""
import json
import os
import re
import subprocess
import sys

_ANCHOR_MIN_LEN = 12

LANG = {".py": "python", ".js": "js", ".ts": "ts", ".go": "go", ".java": "java",
        ".php": "php", ".rb": "ruby"}

# CWE → the class vocabulary codeagent uses. Unmapped CWEs keep the bare id: a wrong class steers the
# patch prompt at the wrong defence, which is worse than a generic one.
CWE_CLASS = {
    "CWE-22": "lfi", "CWE-23": "lfi", "CWE-35": "lfi", "CWE-36": "lfi", "CWE-73": "lfi",
    "CWE-89": "sqli", "CWE-79": "xss", "CWE-1336": "ssti",
    "CWE-94": "rce", "CWE-95": "rce", "CWE-78": "rce", "CWE-77": "rce", "CWE-502": "rce",
    "CWE-306": "idor", "CWE-639": "idor", "CWE-863": "idor", "CWE-862": "idor", "CWE-284": "idor",
    "CWE-918": "ssrf", "CWE-611": "xxe", "CWE-352": "csrf", "CWE-601": "open-redirect",
    "CWE-400": "dos", "CWE-770": "dos", "CWE-1333": "dos", "CWE-287": "auth",
}


def deep_get(o, key):
    """Find `key` anywhere in a nested dict — the metadata nests inconsistently across projects."""
    if isinstance(o, dict):
        for k, v in o.items():
            if k == key:
                return v
            r = deep_get(v, key)
            if r is not None:
                return r
    elif isinstance(o, list):
        for v in o:
            r = deep_get(v, key)
            if r is not None:
                return r
    return None


def read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


TEST_MARKERS = ("test_", "_test.", "/tests/", "tests/", "/test/", ".spec.", "__tests__",
                "/fixtures/", "conftest.py", "/testing/")


def _is_test_path(p):
    """True for test/fixture scaffolding.

    The CVE-Bench converter has excluded these from gold_files since it was written; this one did
    not, and six BountyBench instances were being scored against a TEST file rather than the code
    that contains the vulnerability. `localized` then rewards editing a test — which is the exact
    defect the CVE-Bench exclusion exists to prevent, reproduced in the sibling converter because
    the rule lived in one file instead of both.
    """
    pl = p.lower()
    return any(m in pl for m in TEST_MARKERS)


NON_SOURCE_EXT = (".rst", ".md", ".txt", ".lock", ".cfg", ".ini", ".toml", ".yaml", ".yml")
NON_SOURCE_NAMES = ("changelog", "changes", "release", "security", "news", "history", "authors")


def _is_non_source(p):
    """True for docs / changelog / lockfile paths — commit noise, not the fix.

    Ported from cvebench_to_cvepatch.py, where it has always existed. Measured here:
    fastapi-bounty_0 paired ONLY `requirements-tests.txt` and `pyproject.toml`, so an
    engineer that appended a pin scored `localized` while the vulnerability was untouched.
    Third instance of the same shape as the TEST_MARKERS gap — a rule that lives in one
    converter and not its sibling.
    """
    pl = p.lower()
    if pl.endswith(NON_SOURCE_EXT):
        return True
    return os.path.basename(pl).rsplit(".", 1)[0] in NON_SOURCE_NAMES


def _commit_state(codebase, declared):
    """Is the checked-out source actually AT the commit this bounty calls vulnerable?

    THE DEFECT. This converter reads whatever commit `codebase/` happens to be checked out
    at; it never checks out `bounty_metadata.json`'s `vulnerable_commit`. That is not a
    theoretical concern — measured on the corpus:

      * Of the 16 bounties declaring a raw SHA, 12 are at a DIFFERENT commit.
      * mlflow settles it: four bounties declare four different vulnerable commits and the
        single checkout sits at exactly one of them (bounty_2's). The other three are being
        served source from another point in that project's history.
      * The same holds for LibreChat (5 bounties, 2 declared commits, 1 checkout), gradio
        (3/3/1), langchain, lunary, bentoml, InvokeAI, pytorch-lightning.

    The consequence is NOT a mis-paired file — the pairing can be perfect — but source in
    which the vulnerability has already been fixed. Verified by hand on two of them:
    scikit-learn-bounty_0 (CVE-2024-5206) contains no `stop_words_` at all and
    `_limit_features` already returns the fixed shape, and django-bounty_0's html.py carries
    every CVE-2024-38875 bound (MAX_URL_LENGTH gating both regexes, trim_url's max(0, ...),
    the 63-char email-domain guard, MAX_STRIP_TAGS_DEPTH). An engineer graded on those is
    being asked to fix code that is not broken, and scores zero however good it is.

    THREE STATES, and the third is the point. Tags cannot be resolved in these shallow
    clones (measured: 0 tags fetched for LibreChat/yaml/node, 1 for zipp), so a
    tag-declared bounty is UNVERIFIABLE here — reported as itself rather than folded into
    either "verified" or "mismatch", because a check that could not run is not a check that
    passed. Nothing is dropped on this signal: it is disclosed so a reader can score the
    verified subset separately, and fixing it properly means checking out each bounty's own
    commit, which is a corpus-build decision with real network and disk cost.
    """
    if not declared:
        return "unverifiable"
    try:
        head = subprocess.run(["git", "-C", codebase, "rev-parse", "HEAD"],
                              capture_output=True, text=True, timeout=30).stdout.strip()
    except (OSError, subprocess.SubprocessError):
        return "unverifiable"
    if not head:
        return "unverifiable"
    if re.fullmatch(r"[0-9a-f]{7,40}", declared):
        return "verified" if (head.startswith(declared) or declared.startswith(head)) else "mismatch"
    try:
        res = subprocess.run(["git", "-C", codebase, "rev-parse", "--verify", "-q",
                              declared + "^{commit}"], capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError):
        return "unverifiable"
    resolved = res.stdout.strip()
    if not resolved:
        return "unverifiable"   # shallow clone: the tag was never fetched
    return "verified" if resolved == head else "mismatch"


def _line_overlap(a, b):
    """Jaccard over non-blank stripped lines — how recognisably a and b are the same file.

    A gold patch is a MODIFIED COPY of its twin, so the two share most of their lines. Two
    unrelated files that merely share a basename share almost none. This is the signal that
    tells those apart; it is computed converter-side over the answer key and never reaches
    the engineer.
    """
    A = set(l.strip() for l in a.splitlines() if l.strip())
    B = set(l.strip() for l in b.splitlines() if l.strip())
    return len(A & B) / max(1, len(A | B))


def _best_twin(codebase, name, gold):
    """The codebase file that IS this gold file's pre-fix version — not merely the first
    thing with the same basename.

    THE DEFECT THIS REPLACES. `patch_files/` is FLAT (bare filenames, no directories), so
    pairing had to search the tree — and it took the first os.walk hit. Measured across the
    corpus, that was the WRONG FILE for 24 of the paired files, silently:

        pytorch-lightning app.py      41 candidates, first 0.002 -> best 0.998
        mlflow file_store.py           3 candidates, first 0.000 -> best 0.973
        LibreChat files.js             2 candidates, first 0.010 -> best 0.850
        django html.py                 2 candidates, first 0.021 -> best 0.962
        zipp __init__.py               4 candidates, first 0.000 -> best 0.749

    The engineer was handed a file that does not contain the vulnerability and graded on
    whether it fixed it. That is not a hard benchmark, it is a broken one: every such
    instance scores as a capability miss no matter how good the engineer is, and the
    resulting number is unfalsifiable in the pessimistic direction.

    Selection is by overlap with the gold, NOT by a threshold — nothing is dropped for
    scoring low, because the corpus must not shrink in the flattering direction (Sec 14.2
    rule 5's corollary). A weak best match is REPORTED as pair_confidence and left in.
    Ties break on the shortest relative path so the choice is deterministic across runs.
    """
    best = None
    for cdir, _, cfiles in os.walk(codebase):
        if name not in cfiles:
            continue
        t = os.path.join(cdir, name)
        body = read(t)
        if body is None:
            continue
        score = _line_overlap(gold, body)
        key = (score, -len(os.path.relpath(t, codebase)))
        if best is None or key > best[0]:
            best = (key, t, body, score)
    return (best[1], best[2], best[3]) if best else (None, None, 0.0)


_SHIM_LANGS = (".py", ".js", ".jsx", ".mjs", ".cjs", ".ts", ".tsx")


def _is_reexport_shim(src, ext=".py"):
    """True for a deprecation/re-export stub: forwards names elsewhere, defines no logic.

    langchain ships many of these (create_importer + DEPRECATED_LOOKUP + __getattr__). The real
    vulnerability lives in the package they forward to, which is not in this checkout.
    """
    # The heuristic reasons about Python and JS/TS declaration syntax. For any OTHER
    # language it has no logic markers at all, so EVERY file reads as a shim — which is
    # how curl's fopen.c (a real C fix, unambiguously paired at 0.62 overlap) was being
    # dropped. Same defect as the JS one below, recurring one language over: rather than
    # bolt on C markers and wait for the next language, the check now DECLINES outside the
    # syntax it actually models. Not guessing is the correct answer here; guessing "shim"
    # silently deletes a real instance.
    if ext.lower() not in _SHIM_LANGS:
        return False
    if "create_importer" in src and "DEPRECATED_LOOKUP" in src:
        return True
    skip_prefixes = (chr(35), 'import ', 'from ')
    meaningful = []
    for line in src.splitlines():
        t = line.strip()
        if not t or t.startswith(skip_prefixes) or t[:3] in ('"""', "'''"):
            continue
        meaningful.append(t)
    if not meaningful:
        return True
    # Logic markers must cover EVERY language in the corpus. The first version tested only for
    # Python's `def `/`class `, so every JavaScript file was misread as a shim — including
    # parse-url's dist/index.js, a real bundle with a real SSRF that had already been patched by
    # hand. An over-aggressive filter silently shrinks the corpus and flatters the result, which is
    # the same defect as an over-generous one pointed the other way.
    py_logic = ('def ', 'class ')
    js_logic = ('function ', 'const ', 'let ', 'var ', 'module.exports', 'exports.', 'async ')
    for t in meaningful:
        if t.startswith(py_logic) and '__getattr__' not in t:
            return False
        if t.startswith(js_logic) or '=>' in t or 'function(' in t:
            return False
    return True

def anchors_between(vuln, gold):
    """Distinctive lines the real fix REMOVED — present in the vulnerable file, gone from the fixed one.

    This is the same stricter-than-file-level signal the CVE-Bench converter builds, derived here by
    differencing the two whole files rather than parsing a diff. SCORER-ONLY: these are the answer,
    so a guard test asserts they never reach the engineer's prompt.
    """
    gold_lines = set(l.strip() for l in gold.splitlines())
    out = []
    for line in vuln.splitlines():
        s = line.strip()
        if len(s) >= _ANCHOR_MIN_LEN and s not in gold_lines and s not in out:
            out.append(s)
    return out[:40]  # bounded: a rewritten file would otherwise contribute hundreds


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    limit = 0
    for a in sys.argv[1:]:
        if a.startswith("--limit"):
            limit = int(a.split("=", 1)[1]) if "=" in a else 0
    if len(args) < 2:
        print(__doc__)
        sys.exit(2)
    root, out_path = args[0], args[1]

    instances, skipped = [], []
    for dirpath, _, files in os.walk(root):
        if "bounty_metadata.json" not in files:
            continue
        meta_raw = read(os.path.join(dirpath, "bounty_metadata.json"))
        if not meta_raw:
            continue
        try:
            meta = json.loads(meta_raw)
        except json.JSONDecodeError as exc:
            skipped.append((dirpath, f"bad metadata: {exc}"))
            continue

        # bountytasks layout: <project>/bounties/<bounty_N>/ , project source at <project>/codebase/
        bounty_dir = dirpath
        project_dir = os.path.dirname(os.path.dirname(bounty_dir))
        project = os.path.basename(project_dir)
        bounty = os.path.basename(bounty_dir)
        codebase = os.path.join(project_dir, "codebase")
        patch_dir = os.path.join(bounty_dir, "patch_files")
        if not os.path.isdir(patch_dir):
            skipped.append((f"{project}/{bounty}", "no patch_files — not a patch task"))
            continue

        cwe_raw = str(deep_get(meta, "CWE") or "")
        cwe = (re.search(r"CWE-\d+", cwe_raw) or [None])[0] if re.search(r"CWE-\d+", cwe_raw) else ""
        cwe = re.search(r"CWE-\d+", cwe_raw).group(0) if re.search(r"CWE-\d+", cwe_raw) else ""

        vuln_files, gold_files, anchors, pair_conf = [], [], {}, {}
        for pf in sorted(os.listdir(patch_dir)):
            gold_path = os.path.join(patch_dir, pf)
            if not os.path.isfile(gold_path):
                continue
            gold = read(gold_path)
            if gold is None:
                skipped.append((f"{project}/{bounty}", f"unreadable gold {pf}"))
                continue
            if _is_non_source(pf):
                skipped.append((f"{project}/{bounty}", f"{pf}: doc/changelog/lockfile, not the fix"))
                continue
            # The gold name mirrors a path in the codebase; find its pre-fix twin — the
            # file it is a modified copy OF, not merely the first basename match.
            twin, vuln, confidence = _best_twin(codebase, pf, gold)
            if not twin:
                skipped.append((f"{project}/{bounty}", f"no codebase twin for {pf}"))
                continue
            if vuln is None or vuln == gold:
                skipped.append((f"{project}/{bounty}", f"{pf}: unreadable or identical to gold"))
                continue
            # An instance is only a fair test if the VULNERABLE CODE IS ACTUALLY PRESENT in the file
            # handed to the engineer. Two shapes fail that and were emitted by the first version of
            # this converter, which paired purely on filename:
            #   * an EMPTY file (zipp-bounty_0 came through at 0 bytes),
            #   * a pure RE-EXPORT SHIM (langchain-bounty_0 paired five deprecation stubs whose real
            #     pickle vulnerability lives in langchain_community, absent from the clone).
            # Scoring the engineer on those measures nothing - it cannot fix what it was never shown
            # - so they are skipped and REPORTED, exactly like the unpaired bounties.
            if len(vuln.strip()) < 200:
                skipped.append((f"{project}/{bounty}", f"{pf}: source empty/too small to hold the vuln"))
                continue
            if _is_test_path(rel_check := os.path.relpath(twin, codebase)):
                skipped.append((f"{project}/{bounty}", f"{rel_check}: test/fixture file, not the vulnerable code"))
                continue
            if _is_reexport_shim(vuln, os.path.splitext(pf)[1]):
                skipped.append((f"{project}/{bounty}", f"{pf}: re-export shim - vuln code not in this file"))
                continue
            rel = os.path.relpath(twin, codebase)
            pair_conf[rel] = round(confidence, 3)
            vuln_files.append({"path": rel, "content": vuln})
            gold_files.append(rel)
            a = anchors_between(vuln, gold)
            if a:
                anchors[rel] = a

        if not vuln_files:
            skipped.append((f"{project}/{bounty}", "no paired vulnerable/gold file"))
            continue

        instances.append({
            "id": f"{project}-{bounty}",
            "cve": str(deep_get(meta, "CVE") or cwe or f"{project}-{bounty}"),
            "fix_commit": str(deep_get(meta, "vulnerable_commit") or ""),
            "lang": LANG.get(os.path.splitext(gold_files[0])[1].lower(), ""),
            "class": CWE_CLASS.get(cwe, cwe),
            "endpoint": gold_files[0],
            "detail": cwe_raw or "a real, paid bug-bounty vulnerability in this file",
            "vuln_files": vuln_files,
            "gold_files": gold_files,
            "gold_anchors": anchors,
            # Converter-side pairing confidence, per file. Reported so a weak pairing is
            # visible to whoever reads the score rather than being indistinguishable from
            # an engineer that failed. Never reaches the engineer's prompt.
            "pair_confidence": pair_conf,
            # Whether the checked-out source is really AT the declared vulnerable commit.
            # "mismatch" means the engineer may be shown ALREADY-FIXED code (see
            # _commit_state). Reported, never used to silently drop an instance.
            "commit_state": _commit_state(codebase, str(deep_get(meta, "vulnerable_commit") or "")),
            # `verify` intentionally omitted — their verify.sh is the oracle and we do not run it.
        })
        if limit and len(instances) >= limit:
            break

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(instances, fh, indent=2)
    print(f"wrote {len(instances)} agentic patch instance(s) → {out_path}")
    print("  source: BountyBench (Stanford) — real paid bounties, externally authored")
    print("  execution oracle NOT wired: scores produced + localized + anchors; `fixed` stays unjudged")
    by_state = {}
    for i in instances:
        by_state.setdefault(i["commit_state"], []).append(i["id"])
    print("  commit pin: " + ", ".join(f"{k} {len(v)}" for k, v in sorted(by_state.items())))
    if by_state.get("mismatch"):
        print("    MISMATCH — source is NOT at the declared vulnerable commit; the "
              "vulnerability may already be fixed in what the engineer is shown:")
        for iid in sorted(by_state["mismatch"]):
            print(f"      {iid}")
    weak = [(i["id"], p, c) for i in instances for p, c in i["pair_confidence"].items() if c < 0.35]
    if weak:
        print(f"  {len(weak)} weakly-paired file(s) KEPT and reported (not dropped — the corpus must not shrink):")
        for iid, p, c in sorted(weak, key=lambda r: r[2])[:12]:
            print(f"    {iid}: {p} overlap={c}")
    if skipped:
        print(f"  skipped {len(skipped)} (reported, never silently dropped):")
        for w, why in skipped[:12]:
            print(f"    {w}: {why}")


if __name__ == "__main__":
    main()
