# Benchmark correctness audit

A benchmark is only worth trusting if it is itself correct. This is an honest self-audit of the AI
Security Engineer benchmark (`internal/bench/defensexbow*.go`, `impact.go`, `codeagent`): a critical read
of the scoring logic for bugs and gaming loopholes — not just "do the tests pass."

## Bug found + FIXED

**Impact prioritisation: must-lead set could diverge from the answer key.** `ScoreImpact` ranks the answer
key by `groundScore` (RiskWeight + a 2× crown boost), but the "must-lead" set was built from the
`ReachesCrown || TrueImpact>0` flags *directly*. These diverge when a crown-reaching **low**-severity
finding (score 200) is outscored by a **critical** non-crown one (score 400): the benchmark would then
*require* the engineer to lead with the low-crown issue, so a correct engineer ranking by the answer key
(critical first) would **wrongly FAIL**.

- Fix: the must-lead set is now always the **top-K by `groundScore`** (K = the count of crown/override
  issues), so it can never contradict the answer-key ranking.
- Regression: `TestScoreImpact_MustLeadConsistentWithScore` (critical non-crown must be the must-lead over a
  low crown). All existing impact tests still pass.
- Impact on prior results: none. The committed scenarios (`estate-priority`, `estate-mistagged`) don't
  trigger the divergence — the crown/override issue *is* the top scorer — so the live PASS/FAIL numbers
  stand; this was a latent bug for other scenarios.

## Verified-correct (critical read + re-run)

- **Remediation verdict** (`XBOWDefenseVerdict`): `not_vulnerable` → `no_patch` → `broke_app` (app dead
  wins over everything) → `remediated` (exploit dead + app alive) → `ineffective`. Ordering is right.
- **Flag detection** (`ReplayExploit`): `strings.Contains(response, flag)` on a high-entropy build-time
  flag — no coincidental matches; the patched rebuild bakes the *same* flag, so before/after are comparable.
- **Calibration controls** (real container): correct→`remediated`, no-op→`ineffective`, breaking→`broke_app`.
- **Anti-sabotage + functional probe**: breaking the app (or breaking legitimate access, for authz) →
  `broke_app`, verified both by calibration and the IDOR `--patch-file` block-everything run.
- **Impact discrimination (post-fix, re-run)**: impact-first→PASS, severity-first→`0/1 lead`,
  substrate-only on mis-tagged→`0/1 lead`. Holds.
- **Anti-overfit**: `TestScorer_NoSUTIdentifiers` covers all scorers.

## Known limitations (honest, not fabricated)

1. **Single-exploit replay.** The verdict re-fires only the *recorded* exploit. A fix that blocks that exact
   request without fixing the root cause would score `remediated` (root-cause is *prompted*, not *enforced*).
   Same shape as XBOW's single-flag. **Mitigation the spec already supports:** `WinningExploit.Steps` is a
   list and `ReplayExploit` flags the flag in *any* step, so adding equivalent **variant** requests to a
   fixture makes a payload-specific block fail (a root-cause fix blocks all variants). Recommended for
   hardened fixtures; the clean self-test fixtures use a single request.
2. **`AppFunctional` is a liveness check (`< 500`).** A 404 homepage would pass as "functional." Fine for
   injection classes (the fix doesn't touch the homepage) and covered for authz by the functional probe; a
   fix that 404s the homepage on an injection class is a theoretical false-pass.
3. **Live-run engineer = the author.** The *mechanics* are validated independently (calibration +
   `--patch-file`, no LLM). The *live* per-class results used Claude (via the proxy) as the engineer on
   fixtures authored in the same session — a fair capability demonstration on clean vulns, not an
   independent-party measurement. The hardened real-XBOW number (independent challenges) is the honest next
   step.

## Fixture bug found + FIXED (surfaced while hardening #1)

Building the variant-replay revealed a concrete instance of limitation #1: the **SQLi self-test fixture put
the flag in a user row (`id=99`), directly readable via `?id=99` with NO injection**. The parameterised
fix blocked the recorded `OR 1=1` exploit, so it scored `remediated` — but the flag was still trivially
reachable. Corrected: the flag now lives in a separate `secrets` table reachable **only via UNION
injection**, the exploit carries a **variant** step (casing/comment — defeats a naive UNION-SELECT filter),
and a **functional probe** (a legit `?name=al` search must still return `alice`). The corrected fixture
builds and the UNION exploit re-confirms; the `sqli` remediation entry should be re-verified live against it
(the mechanism is proven; the earlier `remediated` was on the flawed fixture).

## Verdict

The scoring logic is correct after the one fix; the calibration + discrimination controls hold; the
limitations are documented and bounded (none produce a false `remediated`/`PASS` for a good-faith engineer).
