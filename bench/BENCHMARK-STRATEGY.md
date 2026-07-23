# Benchmark strategy — how we measure the two L2 agents against competitors

The question this answers: **for the AI offensive agent and the AI security engineer, what is the RIGHT
benchmark, why, how do we score today, and where do we improve to reach parity?** Numbers below are
tagged by provenance: `[det]` = deterministic, reproducible in CI with no LLM (run here); `[proxy]` =
requires a frontier LLM driving the agent (the dev-proxy), so it's gated on an API key + live targets.

## 1. AI offensive agent → XBOW's 104-challenge flag-capture suite (`tsbench xbow`)

**Why this is the right benchmark — the three properties a good agent benchmark needs:**
- **Ungameable.** The success signal is a *captured flag*, not a self-graded "I think I exploited it." You
  either extract the secret or you don't — no false positive is possible, so the score can't be inflated.
- **Competitor-comparable.** XBOW (the company) publishes its own solve-rate on *these same 104
  challenges*. Same suite, same yardstick → a directly comparable number, not a bespoke internal metric.
- **Exploitation-verified, not detection.** A scanner proves a vuln *exists*; this proves it's *exploitable
  end-to-end*. That's the offensive agent's actual job.

**Current: 89/104 captured** `[proxy]` (`bench/XBOW-SCOREBOARD.md`, every capture grounded by an evidence
SHA-256, §10). By class: xss 21 · idor 12 · ssti 11 · cmd-injection 6 · privesc 6 · lfi 5 · sqli 4 ·
deserialization 4 · ssrf 3 · xxe 3 · blind-sqli 3 · … By difficulty: easy 41 · medium 44 · hard 4.

**The 15 misses = the improvement backlog** (categorised so each is actionable, not a vague "get better"):
1. *Needs sandbox tooling* — a challenge whose exploit is a specific OSS tool's job (wpscan, phpggc PHP
   gadget-chains, a padding-oracle). Fix: wrap the tool into the `dispatch_oss` gateway + sandbox image.
2. *EOL / unbuildable* — the challenge container no longer builds (dead base image). Not our gap.
3. *Infeasible black-box* — requires source the black-box agent can't have. Documented as out-of-scope.

**Anti-overfit guards** `[det]` (§14.2, `internal/bench/xbow_test.go` + `guard_test.go`, passing): a
source-grep forbids SUT-specific identifiers in scoring code; every run appends to an evidence-hashed
ledger; the score is real captures, never a heuristic.

## 2. AI security engineer → impact-discovery + remediation-capture (`tsbench discover-suite` / `defense-xbow` / `impact`)

XBOW measures "can you exploit it." The security engineer's job is the *other* two things — **find the vuln
that creates real impact**, and **prove it can be fixed** — so its benchmark measures those. It's derived
from the *same XBOW corpus* (`bench/AI-SECURITY-ENGINEER-BENCHMARK.md`), so offensive and defensive are
directly comparable: exploit it (`xbow`) → prove you can fix it (`defense-xbow`) + explain what it means
(`impact`).

- **Impact discovery** — 8 estate scenarios, `[proxy]` **100% recall / 100% precision** each; and `[det]`
  every scenario is self-validated: the oracle answer PASSES and flag-everything raises false alarms, so
  each genuinely tests precision, not just recall (ran here: *8/8 well-formed + discriminating*). The
  precision floor is `estate-clean` — a hardened all-noise estate where the correct answer is to flag
  **nothing** (the §10 "don't manufacture impact" test); an always-flag-nothing engineer passes it but
  fails the other 7, and an over-flagger fails it.
- **Remediation-capture** (`defense-xbow`) — the seeded vuln is verifiably CLOSED on re-scan via the SAME
  `retest.Verify` the product uses (broke_app ≠ win). The defensive hero metric no competitor publishes.

**No neutral AI-SOC leaderboard exists** (honest gap, §14) — so the honest comparison is per-substrate
(below) plus the self-validated scenario design.

## 3. Substrate benchmarks — the deterministic floor both agents stand on `[det]`

The agents reason over L1/L1.5 output; if that's weak, no agent can be strong. These run in CI with no LLM:

| Benchmark | Metric | Result (ran here) | Competitor |
|---|---|---|---|
| `cloud-baseline` | CIS-control recall over a fixture account | **tsengine 1.00 (6/6)** vs prowler/scout **0.83 (5/6)** — engine lift **+0.17** (ran here) | Prowler/Scout self-publish; no neutral cloud bench |
| `containment` | safety invariants held | **12/12 held** (ran here) | internal (no leaderboard) |
| `discover-suite` | scenario well-formed + discriminating | **8/8** (ran here) | internal |
| `sast` (OWASP Benchmark) | per-CWE Youden | 0.387 last measured (CLAUDE.md §16); **needs the OWASP corpus + sandbox** (`--target`/`--ground-truth`) — not runnable bare | Veracode 51% · Checkmarx 47% · Fortify 35% · SonarQube 6% |
| `wavsep` | per-class Youden | needs a deployed WAVSEP target | Acunetix/Netsparker 87% · Burp 78% · ZAP 56% |

## 4. The honest constraint + how we improve

The headline agent numbers (XBOW 89/104, impact 8/8) are `[proxy]` — they need a **frontier LLM** driving
the agent. The tested local-8B config scores 0/104, so a meaningful agent number needs an API key + the
live XBOW targets; that is the gate on a bigger number, not a missing capability. The deterministic floor
(§3) and the scenario self-validation (§2) *are* reproducible in CI today and are green.

**Improvement loop to reach parity:** (1) wrap the missing sandbox tools for the XBOW "needs-tooling"
misses → each unlocks a capture; (2) drive the suite with a frontier LLM to convert the backlog; (3) keep
the deterministic floor at/above the OSS baselines (cloud 1.00 > prowler 0.83 today). Every run appends to
its evidence-hashed ledger, so progress is durable and auditable, never a one-off claim.
