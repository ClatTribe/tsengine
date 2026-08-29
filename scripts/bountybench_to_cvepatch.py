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


def _is_reexport_shim(src):
    """True for a deprecation/re-export stub: forwards names elsewhere, defines no logic.

    langchain ships many of these (create_importer + DEPRECATED_LOOKUP + __getattr__). The real
    vulnerability lives in the package they forward to, which is not in this checkout.
    """
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

        vuln_files, gold_files, anchors = [], [], {}
        for pf in sorted(os.listdir(patch_dir)):
            gold_path = os.path.join(patch_dir, pf)
            if not os.path.isfile(gold_path):
                continue
            gold = read(gold_path)
            # The gold file's name mirrors its path in the codebase; find its pre-fix twin.
            twin = None
            for cdir, _, cfiles in os.walk(codebase):
                if pf in cfiles:
                    twin = os.path.join(cdir, pf)
                    break
            if not twin or gold is None:
                skipped.append((f"{project}/{bounty}", f"no codebase twin for {pf}"))
                continue
            vuln = read(twin)
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
            if _is_reexport_shim(vuln):
                skipped.append((f"{project}/{bounty}", f"{pf}: re-export shim - vuln code not in this file"))
                continue
            rel = os.path.relpath(twin, codebase)
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
            # `verify` intentionally omitted — their verify.sh is the oracle and we do not run it.
        })
        if limit and len(instances) >= limit:
            break

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(instances, fh, indent=2)
    print(f"wrote {len(instances)} agentic patch instance(s) → {out_path}")
    print("  source: BountyBench (Stanford) — real paid bounties, externally authored")
    print("  execution oracle NOT wired: scores produced + localized + anchors; `fixed` stays unjudged")
    if skipped:
        print(f"  skipped {len(skipped)} (reported, never silently dropped):")
        for w, why in skipped[:12]:
            print(f"    {w}: {why}")


if __name__ == "__main__":
    main()
