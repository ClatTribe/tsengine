# ADR 0014 — The XBOW-derived defense benchmark (re-attack verification)

**Status:** Accepted (design) / building. Extends ADR 0013 (code-depth specialist) and the `tsbench defense`
scorer (`internal/bench/defense.go`). This is the STRONGEST version of the AI Security Engineer benchmark
for the code/web surface: instead of authored synthetic scenarios, it derives the corpus from the real
XBOW challenges we already exploit offensively.

## The idea — invert the capture

XBOW = 104 Dockerized vulnerable apps, each graded on FLAG CAPTURE (deterministic, ungameable). Our
offensive agent (`web-investigate`) has captured ~79. Each capture *proves* the vuln is real. So the
defensive question is the exact inverse:

> Given this vulnerable app + its source, can the AI Security Engineer produce a patch such that the
> **same exploit that captured the flag no longer works — and the app still functions**?

"Remediation-capture" becomes literally **"the flag is now uncapturable by the recorded exploit."** Both
halves are ground-truthed by real execution: the vuln is real (offensively captured) and the fix works
(the live exploit now fails). This is the attack↔defense symmetry on the same 104-suite XBOW itself uses —
the most defensible number possible, and a lane XBOW (offense-only) does not have.

## The oracle — deterministic replay + a regression guard

The offensive agent is LLM-driven (non-deterministic). So the defense VERDICT must not be "re-run the agent
and see if it fails" (a flaky miss would read as a fix). Instead:

1. **Confirm-attack (setup):** build the vuln app, run the offensive agent, capture the flag, and record the
   **winning exploit** — the concrete request(s) whose response carried the flag — into `bench/exploits/<ID>.json`.
   The agent's non-determinism only affects whether we can SET UP the test, never the verdict.
2. **Engineer patch:** hand the AI Security Engineer the finding + the build-context source; it returns a
   patch (LLM via the customer's key / the local proxy). Apply it to the build context.
3. **Rebuild** the container.
4. **Replay** the recorded winning exploit deterministically against the patched build:
   - flag ABSENT in the replay response → the vuln is closed.
   - flag PRESENT → the fix is ineffective.
5. **Regression guard (the honesty gate):** replay a benign baseline (the app's normal homepage / a known-good
   request) against the patched build. If the app no longer serves it (5xx / dead), the "fix" just BROKE the
   app — it does NOT count as a remediation. This is what stops the trivial "break everything to kill the
   exploit" cheat and is what makes the number mean *real* remediation, not sabotage.

**Defense-capture = (exploit now fails) AND (app still functions).** Both required.

## Categories

Run and report BY VULN CLASS (sqli, xss, ssti, idor, lfi, rce, ssrf, xxe, deserialization, …) — the user's
"do it in categories" directive. Per-class remediation rate is the headline; a class where the engineer
patches 4/5 is a legible, improvable signal (which classes it defends well vs poorly).

## Anti-overfit (mandatory, CLAUDE.md §14.2)

- The scorer has ZERO challenge-specific logic — no XBEN ids, no per-app payloads in scoring code (a
  source-grep test forbids SUT identifiers, like the offensive bench).
- The exploit is RECORDED from the real attack (per-instance grounding), not hardcoded.
- The patch comes from the LLM; the replay + regression are generic.
- The regression guard prevents gaming by app-breakage.

## Disk discipline (rule)

One challenge at a time: build → test → `compose down -v --rmi local` (removes the image) before the next.
Never touch the other session's images/containers. `bench/exploits/<ID>.json` are tiny text artifacts.

## Honesty / LLM (rule)

The patch proposer needs an LLM brain (the customer's key in production; the local proxy as the dev
workaround). No LLM → the run degrades honestly ("can't test the engineer without its brain", §10) — it
never fabricates a patch or a verdict.

## What it reuses

The whole `cmd/tsbench` xbow pipeline (`runOneXBOW`: compose build/up, target-port, teardown) and the
`internal/bench/defense.go` scoring skeleton (remediation-capture, the durable ledger, the substrate-vs-agent
framing). Only the ORACLE changes: authored after-state → replay-the-real-exploit + regression.

## Correctness — how we know the benchmark itself is right (calibration)

A benchmark is a grader; you test it with positive AND negative controls. `fixtures/defense-xbow/selftest-lfi`
is a tiny LFI app we fully control (known exploit, known fix), with three ground-truth patches; the
calibration test (`cmd/tsbench` `TestDefenseXBOWSelftest_Calibration`, `-tags=integration`) runs the real
pipeline and asserts each verdict:

| Control patch | Must score | Proves |
|---|---|---|
| correct (confine the read) | `remediated` | soundness — a real fix is rewarded |
| no-op (comment only) | `ineffective` | a non-fix is NOT rewarded (exploit still fires) |
| breaking (500 everything) | `broke_app` | the anti-sabotage guard works — a broken app is never a win |

**Measured (2026-07-06): all three correct on a real container in ~28s** — no LLM, no XBOW suite, own
compose/image/port (collision-safe, CI-able via a seeded exploit + `--patch-file`). This is the benchmark's
own regression test: it proves the number means real remediation and can't be gamed by the two cheats that
matter, *before* trusting any live per-category run.

## Consequence

Two symmetric, ungameable, climbing scoreboards on the same suite: **attack** = flags captured
(`tsbench xbow`), **defense** = vulns verifiably patched (`tsbench defense-xbow`). Being best-in-class at
BOTH — exploit it, then prove you can fix it — is the "better than XBOW" claim, grounded.
