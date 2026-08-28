#!/usr/bin/env python3
"""cvebench_to_cvepatch.py — convert GiovanniGatti/cve-bench tasks into a `tsbench cvepatch` dataset.

WHY. `tsbench cvepatch` scores the AI AppSec engineer on REAL CVEs against the real fixing commit
(the gold patch) — but it needs an operator-supplied `--dataset`, and we had none, so the code
surface went unmeasured while six harness fixes landed on the cloud surface. CVE-Bench is the
neutral external key for that gap: 20 real CVEs across real Python projects, each with the
upstream advisory, the true vulnerable commit, and the actual fixing patch.

SAFETY — this converter is READ-ONLY BY CONSTRUCTION, and that is the whole point:

  * It NEVER runs anything from the benchmark. Each task ships `setup.sh` (which does
    `git clone` + `pip install -e ./repo` on third-party code) and `run_tests.sh`/`test_security.py`
    (which execute a real exploit). Running any of those would execute untrusted code from the
    internet to produce a benchmark number — a trade this campaign is not willing to make.
  * Vulnerable sources are fetched as TEXT over HTTPS from raw.githubusercontent at the task's own
    pinned `vulnerable_sha`. Fetching a blob is not executing it; nothing is imported, installed,
    or run, and the bytes are stored as JSON data the engineer reads as a string.
  * The EXECUTION ORACLE IS DELIBERATELY NOT WIRED. `verify` is left unset, so `fixed` stays
    JudgeUnknown and the run reports `produced` + `localized` only. That is an HONEST partial
    measurement — engineer_autopsy.py classifies an unjudged instance as UNJUDGED (an eval gap),
    never as a pass or a failure. Wiring execution is a separate, sandboxed decision.

TWO SCORING DECISIONS worth stating, because both change the number:

  1. TEST FILES ARE EXCLUDED FROM `gold_files`. A real fixing commit usually touches the fix AND
     its regression test. `localized` asks "did the engineer edit a file the real fix edited" — if
     a test path counted, an engineer that only edited the test would score as localized while
     leaving the vulnerability in place.
  2. The advisory's own text becomes `detail` (the grounding for the fix) and `locate.md` becomes
     `endpoint`. Both come from the benchmark, not from us — we are not authoring the answer.

UNTRUSTED CONTENT NOTE: advisory text and vulnerable source end up in the engineer's prompt. They
are third-party bytes, so treat them as data, not instructions — the same discipline the product
applies to scanner output. The patch the model returns is scored against the gold files; it is
never executed here.

Usage:
  cvebench_to_cvepatch.py <cve-bench-dir> <out.json> [--offline]
    --offline  skip the source fetch and emit instances with no vuln_files (metadata only)
"""
import json
import os
import re
import sys
import urllib.request

RAW = "https://raw.githubusercontent.com/{owner_repo}/{sha}/{path}"

# CWE → the class vocabulary codeagent uses (patch.go: sqli | xss | ssti | lfi | idor | rce | …).
# Unmapped CWEs keep the bare CWE id rather than being forced into a bucket they do not belong in:
# a wrong class steers the patch prompt at the wrong defence, which is worse than a generic one.
CWE_CLASS = {
    "CWE-22": "lfi", "CWE-23": "lfi", "CWE-35": "lfi", "CWE-36": "lfi",
    "CWE-89": "sqli",
    "CWE-79": "xss",
    "CWE-1336": "ssti", "CWE-94": "rce", "CWE-95": "rce", "CWE-78": "rce", "CWE-77": "rce",
    "CWE-502": "rce", "CWE-306": "idor", "CWE-639": "idor", "CWE-863": "idor", "CWE-862": "idor",
    "CWE-918": "ssrf", "CWE-611": "xxe", "CWE-352": "csrf",
    "CWE-400": "dos", "CWE-770": "dos", "CWE-1333": "dos",
}

# Path fragments that mark a file as test/fixture scaffolding rather than the fix itself.
TEST_MARKERS = ("test_", "_test.", "/tests/", "tests/", "/test/", "conftest.py", "/fixtures/")

# NON-SOURCE artefacts a real fixing commit routinely carries alongside the fix: the changelog
# entry, the advisory note, the release doc, the re-locked dependency file. They are part of the
# commit and NOT part of the fix, and `localized` asks whether the engineer edited a file the real
# fix edited. Counting them means an engineer that appended a CHANGELOG line scores as localized
# while the vulnerability is untouched — the same defect as counting a test edit, one step over.
# Measured on this corpus: 12 of 46 gold files were docs/changelogs/lockfiles.
NON_SOURCE_EXT = (".rst", ".md", ".txt", ".lock", ".cfg", ".ini", ".toml", ".yaml", ".yml")
NON_SOURCE_NAMES = ("changelog", "changes", "release", "security", "news", "history", "authors")


def is_test_path(p):
    pl = p.lower()
    return any(m in pl for m in TEST_MARKERS)


def is_non_source(p):
    """True for documentation / changelog / lockfile paths — commit noise, not the fix."""
    pl = p.lower()
    if pl.endswith(NON_SOURCE_EXT):
        return True
    base = os.path.basename(pl).rsplit(".", 1)[0]
    return base in NON_SOURCE_NAMES


def gold_files_from_patch(patch_text):
    """Files the REAL fixing commit modified, excluding test scaffolding (see decision 1)."""
    files, dropped = [], []
    for m in re.finditer(r"^diff --git a/(\S+) b/(\S+)", patch_text, re.M):
        path = m.group(2)
        (dropped if (is_test_path(path) or is_non_source(path)) else files).append(path)
    # de-dupe, preserve order
    seen, out = set(), []
    for p in files:
        if p not in seen:
            seen.add(p)
            out.append(p)
    return out, dropped


# Minimum length for a removed line to serve as an anchor. Short lines ("}", ")", "else:") recur
# all over a file, so their disappearance proves nothing about WHERE the engineer edited.
_ANCHOR_MIN_LEN = 12


def gold_anchors_from_patch(patch_text, keep_paths):
    """The distinctive lines the REAL fix DELETED, per source file — the vulnerable code itself.

    File-level localization is coarse: on a 74KB file, "touched the right file" is nearly free.
    These anchors make it specific — did the engineer actually change the lines the real fix
    changed? A patch that still contains them left the vulnerable code exactly where it was.

    SCORER-ONLY. These are the answer, so they must never reach the engineer's prompt; a guard
    test in internal/bench asserts that.
    """
    anchors, current = {}, None
    for line in patch_text.splitlines():
        m = re.match(r"^diff --git a/(\S+) b/(\S+)", line)
        if m:
            current = m.group(2) if m.group(2) in keep_paths else None
            continue
        if current is None or not line.startswith("-") or line.startswith("---"):
            continue
        body = line[1:].strip()
        if len(body) >= _ANCHOR_MIN_LEN:
            anchors.setdefault(current, [])
            if body not in anchors[current]:
                anchors[current].append(body)
    return anchors


def lang_of(path):
    ext = os.path.splitext(path)[1].lower()
    return {".py": "python", ".js": "js", ".ts": "ts", ".go": "go",
            ".java": "java", ".php": "php", ".rb": "ruby"}.get(ext, "")


def owner_repo(url):
    m = re.search(r"github\.com/([^/]+/[^/.\s]+)", url or "")
    return m.group(1) if m else ""


def fetch_text(owner_repo_s, sha, path, timeout=30):
    """Fetch ONE file as text at a PINNED sha. Read-only: nothing is executed or installed."""
    url = RAW.format(owner_repo=owner_repo_s, sha=sha, path=path)
    req = urllib.request.Request(url, headers={"User-Agent": "tsengine-cvepatch-converter"})
    with urllib.request.urlopen(req, timeout=timeout) as r:  # noqa: S310 — pinned raw.githubusercontent
        return r.read().decode("utf-8", errors="replace")


def read(p):
    try:
        with open(p, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return ""


def endpoint_from_locate(text):
    """locate.md names the File and Method the real fix touched — the benchmark's own pointer."""
    f = re.search(r"File:\s*(\S+)", text or "")
    m = re.search(r"Method:\s*(\S+)", text or "")
    if f and m:
        return f"{f.group(1)}:{m.group(1)}"
    return f.group(1) if f else ""


def impact_of(advisory):
    """The advisory's Impact section — the grounding for the fix, in the upstream's own words."""
    m = re.search(r"##\s*Impact\s*\n(.+?)(?:\n##|\Z)", advisory or "", re.S)
    body = (m.group(1) if m else advisory or "").strip()
    body = re.sub(r"\s+", " ", body)
    return body[:600]


def main():
    args = [a for a in sys.argv[1:] if not a.startswith("--")]
    offline = "--offline" in sys.argv
    if len(args) < 2:
        print(__doc__)
        sys.exit(2)
    root, out_path = args[0], args[1]
    tasks_dir = os.path.join(root, "tasks")
    if not os.path.isdir(tasks_dir):
        print(f"no tasks/ under {root}", file=sys.stderr)
        sys.exit(1)

    instances, skipped = [], []
    for tid in sorted(os.listdir(tasks_dir)):
        d = os.path.join(tasks_dir, tid)
        if not os.path.isdir(d):
            continue
        meta_raw = read(os.path.join(d, "meta.json"))
        if not meta_raw:
            skipped.append((tid, "no meta.json"))
            continue
        try:
            meta = json.loads(meta_raw)
        except json.JSONDecodeError as exc:
            skipped.append((tid, f"bad meta.json: {exc}"))
            continue

        repo = meta.get("repo") or {}
        orep = owner_repo(repo.get("url"))
        vsha, fsha = repo.get("vulnerable_sha", ""), repo.get("fixed_sha", "")
        gold, dropped = gold_files_from_patch(read(os.path.join(d, "fix.patch")))
        if not gold:
            # No non-test file in the gold patch → nothing to localize against. Skipping is
            # honest; scoring it would grade the engineer on an oracle that cannot discriminate.
            skipped.append((tid, f"gold patch touches no source file ({len(dropped)} test/doc file(s) only)"))
            continue

        cwes = meta.get("cwe") or []
        cls = next((CWE_CLASS[c] for c in cwes if c in CWE_CLASS), cwes[0] if cwes else "")

        vuln_files = []
        if not offline and orep and vsha:
            for path in gold:
                try:
                    vuln_files.append({"path": path, "content": fetch_text(orep, vsha, path)})
                except Exception as exc:  # noqa: BLE001 — a fetch failure must not abort the set
                    skipped.append((tid, f"fetch {path}: {exc}"))
        if not offline and not vuln_files:
            # An instance with no source is not a patching task — the engineer would be asked to
            # fix code it was never shown. Dropped rather than emitted as an impossible case.
            skipped.append((tid, "no vulnerable source retrieved"))
            continue

        instances.append({
            "id": tid,
            "cve": tid if tid.startswith("CVE-") else meta.get("ghsa_id", tid),
            "fix_commit": f"{repo.get('url','')}/commit/{fsha}" if fsha else "",
            "lang": lang_of(gold[0]),
            "class": cls,
            "endpoint": endpoint_from_locate(read(os.path.join(d, "locate.md"))),
            "detail": impact_of(read(os.path.join(d, "advisory.md"))),
            "vuln_files": vuln_files,
            "gold_files": gold,
            "gold_anchors": gold_anchors_from_patch(read(os.path.join(d, "fix.patch")), set(gold)),
            # `verify` intentionally omitted — no execution oracle (see the module docstring).
        })

    with open(out_path, "w", encoding="utf-8") as fh:
        json.dump(instances, fh, indent=2)

    print(f"wrote {len(instances)} instance(s) → {out_path}")
    print(f"  source: CVE-Bench (GiovanniGatti/cve-bench) — external, not authored here")
    print(f"  execution oracle: NOT wired — `fixed` stays unjudged; scores `produced` + `localized` only")
    if skipped:
        print(f"  skipped {len(skipped)} task(s) — reported, never silently dropped:")
        for tid, why in skipped[:25]:
            print(f"    {tid}: {why}")


if __name__ == "__main__":
    main()
