# Defensive remediation-capture ledger (durable, append-only)

_Generated from `bench/defense-ledger.jsonl` — one appended line per scenario run of `tsbench defense`. The DEFENSIVE twin of the XBOW ledger: XBOW scores exploitation (flags captured); this scores remediation (seeded vulns verifiably closed on re-scan, via the SAME `retest.Verify` the product uses). Substrate (deterministic) and agent (LLM engineer) are kept separate — the delta is the agent's measured lift._

- **substrate** (deterministic remediation): 0 scenario(s) fully remediated, 1 run(s).

## substrate — best remediation rate per scenario

| Scenario | Best remediation | Best path recall |
|---|---|---|
| leaked-key-to-cloud | 100% | 100% |
