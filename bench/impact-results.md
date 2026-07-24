# Impact-accuracy results — AI security engineer vs the substrate-only baseline

`tsbench impact` measures the OTHER half of the AI security engineer's job (beyond *finding* the vuln):
**prioritise a mixed estate by REAL organisational impact, not raw severity/tags, and don't fabricate a
crown-jewel reach.** The built-in competitor is `--naive-baseline` — the deterministic substrate ranking
by its own tags with no LLM. That baseline is what every tag/severity-sorting scanner effectively does, so
beating it is the AI engineer's measurable value.

The engineer's brain was driven by a **frontier LLM through the OpenAI-compat proxy** (`LLM_BASE_URL` →
file-relay; ledger `model=claude-proxy` — a real LLM-call path, not `--answer-file`). The bench scorer is
deterministic (`bench.ScoreImpact`), so the LLM supplies judgment but **cannot game the score**.

## Measured (this run, `bench/impact-ledger.jsonl`)

| Scenario | Substrate-only baseline | AI engineer (frontier via proxy) | Delta |
|---|---|---|---|
| `estate-mistagged` | **0% lead — FAIL** (tags say the throwaway dev-box RCE is #1) | **100% lead — PASS**, 0 invented | **+100 pts** |
| `estate-priority` | 100% lead — PASS (tags are correct here) | 100% lead — PASS, crown 1/1, 0 invented | matched (no regression) |

**Why the lift is real, not a fixture artifact.** `estate-mistagged` seeds an AWS *AdministratorAccess*
key tagged `medium / data_tier=3 / reaches_crown=false` and a "critical" RCE that is an isolated
nightly-torn-down build agent with no credentials. Ranking by tags (the substrate) leads with the useless
critical → 0%. The engineer reads the *detail*, re-judges the admin key as the real #1 → 100%. On
`estate-priority` the tags already encode impact correctly (a tier-1 crown-reaching secret), so the
engineer must MATCH the baseline, not regress — it did.

## The §10 anti-hallucination bar, observed firing

The first `estate-mistagged` attempt (ledger row 1: `invented:1, pass:false`) is retained evidence: the
frontier brain claimed the admin key *reaches a crown jewel* (reasoning "admin = prod takeover"). But
`reaches_crown` is a **grounded substrate attack-path fact** (the fixture models no such edge), so the
scorer counted the crown claim as **invented** and failed the run. The corrected run re-judged only
PRIORITY (a reasoning conclusion the engineer is allowed to draw) and left CROWN empty (an attack-path is a
graph fact you don't fabricate) → PASS. This is the exact discipline the product depends on: **judgment
re-ranks impact; it never invents a reachability the graph didn't establish.**

## How to reproduce

```
# baseline (no LLM):
tsbench impact --scenario fixtures/impact/estate-mistagged.json --naive-baseline
# AI engineer (frontier via proxy): start the file-relay proxy, then
LLM_BASE_URL=http://127.0.0.1:8898/v1 LLM_MODEL=claude-proxy LLM_API_KEY=proxy LLM_PROVIDER=openai \
  tsbench impact --scenario fixtures/impact/estate-mistagged.json --ledger bench/impact-ledger.jsonl
```
