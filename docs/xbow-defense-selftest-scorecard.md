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

## The other half of the job: impact accuracy

Remediation is only half of a security engineer's job. The other half — the differentiated AI value — is
figuring out **what a finding means for the organisation**: what it reaches, what data it exposes, how to
prioritise. Detection is deterministic; *impact-to-this-org* is judgment. `tsbench impact`
(`internal/bench/impact.go`) measures it: the engineer is given the estate + the substrate's grounded facts
(severity, data-tier, crown-jewel reach) and must **prioritise by real impact, not raw severity**, identify
crown-jewel reach, and invent nothing (§10).

**Live run (2026-07-06, `model=claude-proxy`)** on a mixed estate:

| Finding | Severity | Tier | Reaches crown | |
|---|---|---|---|---|
| leaked AWS key → PII bucket | medium | 1 | ✅ | ← the engineer ranked this **#1** |
| stored XSS in admin panel | high | 2 | ✗ | |
| RCE on a throwaway CI box | critical | 3 | ✗ | scarier severity, contained blast radius |
| SQLi on marketing microsite | high | 3 | ✗ | |

Result: `crown 1/1 correct · priority 1/1 lead (100%) [PASS]` — the engineer led with the *medium* that
reaches customer data over the *critical* on a throwaway box. **Discrimination proven**: a severity-first
answer (`--answer-file`) scores `priority 0/1 lead (0%)` — no pass. So the benchmark rewards real-impact
reasoning and penalises the "AI = re-rank by CVSS" failure.

**Two axes, both live-proven** — mirroring the two halves of the engineer's job:
- **remediation-capture** (`defense-xbow`): did the estate get verifiably safer? (execution-verified)
- **impact-accuracy** (`impact`): did the engineer correctly tell the org what matters + why? (grounded rubric)

Honest next step (documented, not built): the impact dimension currently scores *consistency with the
tagged facts*. The deeper AI value-add — catching impact the tags **mis-classify** (a "tier-3 internal"
repo that actually holds prod admin keys) — needs scenarios whose correct impact *overrides* the naive
substrate ranking; that is the follow-on dimension.
