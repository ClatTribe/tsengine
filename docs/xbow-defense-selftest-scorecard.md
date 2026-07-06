# AI Security Engineer — live per-category scorecard (self-test fixtures)

This is the honest, reproducible evidence that the **defense benchmark scores a real LLM engineer
end-to-end, per vuln category**. It complements — it does NOT replace — the real XBOW-suite numbers.

## What was run

For each vuln class we built a minimal, controlled vulnerable app (`fixtures/defense-xbow/selftest-<class>`)
with a seeded winning exploit, and ran the full pipeline **with a live LLM** (Claude, via the file-relay
proxy — the no-key dev workaround; a customer key replaces it in production):

```
tsbench defense-xbow --suite fixtures/defense-xbow --only selftest-<class> \
    --exploits-dir fixtures/defense-xbow/exploits
# LLM_BASE_URL=<proxy>/v1  LLM_MODEL=claude-proxy  (no --patch-file → the engineer proposes the fix)
```

The harness built the vuln app → reconfirmed the exploit → **asked the engineer to patch it** → applied the
patch → rebuilt → re-fired the recorded exploit (must be gone) + a regression check (app must still serve).

## Results (2026-07-06, `model=claude-proxy`)

| Category | Verdict | The engineer's root-cause fix |
|---|---|---|
| `lfi` | ✅ remediated | confine reads to a public dir; reject absolute/traversal paths |
| `sqli` | ✅ remediated | parameterise the query (bind the input as a value) |
| `cmdi` | ✅ remediated | drop the shell; pass an argument vector so input can't execute |
| `ssti` | ✅ remediated | never eval user input as a template; insert it as escaped data |

Ledger: `bench/defense-xbow-selftest-ledger.jsonl` (one grounded line per run).

## What this proves — and what it does not (intellectual honesty)

**Proves:** the whole loop works with a live model — the engineer is scored on *real* remediation (the
recorded exploit is re-fired and must fail, and the app must still work), across four distinct vuln
classes, each fixed at the root cause rather than by breaking the app (the anti-sabotage guard from ADR
0014's calibration would have caught that).

**Does NOT prove:** that these numbers transfer to the *hardened* XBOW challenges. These fixtures are clean,
textbook instances — a **capability floor** ("can the engineer patch this class at all"), not the real
difficulty. The real 71-challenge XBOW suite has filters, obfuscation, and multi-step exploits; running the
engineer against it at scale needs an **autonomous LLM key** (for the offensive exploit-capture step on
every challenge). That is the honest gate — the number over the real suite is not fabricated here.

The benchmark's *correctness* (that a wrong or app-breaking patch scores `ineffective`/`broke_app`, not a
false pass) is proven separately by the calibration self-test (ADR 0014, `TestDefenseXBOWSelftest_Calibration`).
