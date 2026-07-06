# The AI Security Engineer benchmark — better than XBOW by measuring the whole job

XBOW proves a vuln is **exploitable**. A scanner proves it **exists**. Neither tells the organisation what
it **means for them**, nor proves it can be **fixed**. This benchmark measures the two things a real
security engineer does that neither does — and it is the "better than XBOW" claim, made testable.

It is the defensive twin of `tsbench xbow` (the offensive flag-capture suite), and it is derived from the
**same XBOW challenge corpus** so the two are directly comparable: exploit it (`xbow`), then prove you can
fix it and explain what it means (`defense-xbow` + `impact`).

## The two halves of the job → three measured axes

| Axis | Question | How it's scored | CLI |
|---|---|---|---|
| **Remediation-capture** | did the estate get *verifiably* safer? | patch the real vuln → re-fire the recorded exploit (must fail) + regression (app must still work) — execution-verified | `tsbench defense-xbow` |
| **Impact-accuracy** | did the engineer prioritise by *real org impact*, not raw severity? | grounded rubric vs the substrate's facts (RiskWeight + crown-jewel reach) | `tsbench impact` |
| **Value-add over the substrate** | did the engineer catch impact the tags *mis-classify*? | the gap between the substrate-only ranking and the engineer's, on mis-tagged findings | `tsbench impact --naive-baseline` vs live |

## The deterministic / AI line (why this is honest, not hype)

The benchmark keeps the product's core boundary crisp (`CLAUDE.md` §2.7 / §13): **the deterministic
substrate computes the facts; the AI engineer is scored on judgment over them, and must invent nothing
(§10).**

- Deterministic (and NOT what we benchmark the LLM on): does the vuln exist, is it on a reachable path
  (`cloudgraph`), does it bridge surfaces (`crossdetect`), what's the tag-based RiskWeight, is the finding
  gone after the fix (`retest.Verify`).
- AI engineer (what we DO benchmark): produce a fix that survives re-attack without breaking the app;
  prioritise by real impact; **catch when the tags are wrong** — the one place a lookup cannot help.

## Results (live, `model=claude-proxy` — Claude via the no-key dev proxy; a customer key replaces it in prod)

**Remediation** — the engineer proposed a root-cause fix, re-attack confirmed it dead, app still served:

| class | fix | verdict |
|---|---|---|
| lfi | confine reads to a public dir | ✅ remediated |
| sqli | parameterise the query | ✅ remediated |
| cmdi | drop the shell, argument vector | ✅ remediated |
| ssti | never eval user input as a template | ✅ remediated |
| idor | enforce object-level authorization | ✅ remediated |
| xxe | disable external entities + DTD | ✅ remediated |

**Impact** — the engineer led with a *medium* leaked key that reaches customer PII over a *critical* on a
throwaway box: `priority 1/1 lead, PASS`. A severity-first answer scores `0/1 lead` (fails).

**Value-add** — on a finding tagged *medium/tier-3* whose detail is an *AdministratorAccess key*: the
substrate-only ranking scored `0/1 lead` (buried it); the engineer read the detail and scored `1/1 lead,
PASS`. **The 0→100 gap is the measured AI value-add.**

Evidence ledgers: `bench/defense-xbow-selftest-ledger.jsonl`, `bench/impact-live-ledger.jsonl`.

## Correctness of the benchmark itself (positive + negative controls)

A grader is only trustworthy if it correctly *fails* bad inputs. Proven in CI:
- `TestDefenseXBOWSelftest_Calibration` (`-tags=integration`): a correct patch → `remediated`, a no-op →
  `ineffective`, an **app-breaking patch → `broke_app`** (the anti-sabotage guard — you cannot "fix" by
  killing the app).
- `TestScoreImpact_PenalisesSeverityFirst` / `_MisTagged_AIValueAdd`: severity-first and substrate-only
  rankings must fail; a real-impact / detail-reading assessment must pass.
- `TestScorer_NoSUTIdentifiers`: the scoring code contains no challenge-specific identifiers (anti-overfit,
  §14.2).

## How to run

```sh
# The deterministic gate (unit scorers + calibration on a real container + impact discrimination):
make bench-engineer

# Remediation, per category (real XBOW suite; needs a live LLM for the attack + patch steps):
LLM_BASE_URL=… LLM_MODEL=… LLM_API_KEY=… tsbench defense-xbow --category sqli
# Deterministic pipeline validation (no LLM):
tsbench defense-xbow --only <id> --patch-file <fix>
# Impact:
LLM_BASE_URL=… tsbench impact --scenario fixtures/impact/estate-mistagged.json
tsbench impact --scenario … --naive-baseline    # the substrate-only number to beat
```

## Honest gates (not fabricated)

- **The full 71-challenge remediation sweep needs an autonomous LLM key.** Every real challenge needs its
  recorded exploit (the offensive capture step); the self-test fixtures above are a per-class **capability
  floor** on clean vulns, not the hardened-challenge number. The live results here used Claude via a
  file-relay proxy (the no-key workaround) on the self-test fixtures; the real-suite number is a key away,
  and is *not* printed until measured.
- **Impact ground truth for mis-tagged findings is authored** (it must be — measuring judgment needs a
  ground-truth judgment), but every override is justified by the finding *detail* shown to the engineer, so
  it's a fair test, and the scoring code stays SUT-agnostic.

Design: [`docs/adr/0014-xbow-defense-benchmark.md`](../docs/adr/0014-xbow-defense-benchmark.md),
[`docs/adr/0013-code-depth-specialist.md`](../docs/adr/0013-code-depth-specialist.md),
[`docs/xbow-defense-selftest-scorecard.md`](../docs/xbow-defense-selftest-scorecard.md).
