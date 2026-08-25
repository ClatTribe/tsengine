#!/usr/bin/env python3
"""xbow_autopsy.py — post-batch failure classifier (harness-improvement-program).

Reads an XBOW ledger (jsonl) and, when TSENGINE_XBOW_KEEP artifacts exist,
their transcripts. Emits a failure-mode table for every unsolved benchmark so
harness work targets CATEGORIES spanning challenges — never single cases.

Failure taxonomy:
  CONFIG          environment mis-set (no LLM visible to the agent)
  INFRA           spawn/teardown failures (sandbox leaks, daemon)
  BRAIN-STALL     0-turn runs: provider throttle window or context ceiling
  BUDGET-EXHAUST  ran out of wall-clock mid-chain while progressing (>=8 turns)
  CHAIN-INCOMPLETE proved the vuln class but never reached flag exfil
  WANDER          budget spent, few/no findings, no coherent chain (scope drift)
  AUTH-WALL       transcript dominated by login walls / 401-302-to-login

Usage: xbow_autopsy.py <ledger.jsonl> [artifacts_dir]
"""
import json
import os
import re
import sys
from collections import defaultdict


def classify(entry, transcript_text=""):
    note = entry.get("note", "")
    turns_m = re.search(r"(\d+) turn", note)
    turns = int(turns_m.group(1)) if turns_m else 0
    if "needs an LLM" in note:
        return "CONFIG"
    if "spawning OSS sandbox" in note and "failed" in note.split("spawning")[0]:
        return "INFRA"
    if entry.get("errored"):
        return "INFRA"
    if turns == 0 and ("flag not captured" in note or "stopped" in note):
        return "BRAIN-STALL"
    if turns >= 12 and "didn't reach the flag" in note and entry.get("findings", 0) == 0:
        return "WANDER"
    if turns >= 8 and ("timeout" in note or "stopped" in note):
        # transcript evidence beats the one-line note when present
        if transcript_text:
            tl = transcript_text.lower()
            walls = sum(tl.count(p) for p in ("302 found", "login", "401 unauthorized"))
            if walls >= 5:
                return "AUTH-WALL"
        return "BUDGET-EXHAUST"
    if entry.get("findings", 0) > 0 and not entry.get("solved"):
        if transcript_text:
            return "CHAIN-INCOMPLETE"
        return "CHAIN-INCOMPLETE?"  # unconfirmed without transcript
    if turns <= 6 and entry.get("findings", 0) == 0:
        return "WANDER"
    return "UNCLASSIFIED"


def main():
    ledger = sys.argv[1] if len(sys.argv) > 1 else "/tmp/e2e/xbow-v3-ledger.jsonl"
    art = sys.argv[2] if len(sys.argv) > 2 else None
    best = {}
    attempts = defaultdict(int)
    for line in open(ledger):
        e = json.loads(line)
        attempts[e["id"]] += 1
        b = best.setdefault(e["id"], e)
        if e["solved"] and not b["solved"]:
            best[e["id"]] = e

    print(f"{'challenge':14} {'result':7} {'att':>3}  {'failure-mode':16} evidence")
    cats = defaultdict(list)
    for cid in sorted(best):
        e = best[cid]
        ttext = ""
        if art:
            tp = os.path.join(art, cid, "transcript.json")
            if os.path.exists(tp):
                try:
                    ttext = open(tp, encoding="utf-8", errors="ignore").read().lower()
                except OSError:
                    pass
        if e["solved"]:
            res = "SOLVED"
            mode = "-"
        else:
            mode = classify(e, ttext)
            res = "miss"
            cats[mode].append(cid)
        ev = e.get("note", "")[:60]
        print(f"{cid:14} {res:7} {attempts[cid]:>3}  {mode:16} {ev}")

    print("\n== failure categories (target the biggest span-first) ==")
    for c, ids in sorted(cats.items(), key=lambda kv: -len(kv[1])):
        print(f"{c:16} {len(ids)}  {', '.join(i.replace('XBEN-','').replace('-24','') for i in sorted(ids))}")
    solved = sum(v["solved"] for v in best.values())
    print(f"\ncapture: {solved}/{len(best)}")


if __name__ == "__main__":
    main()
