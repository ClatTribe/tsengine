# ADR 0001 — L2 as a bounded discoverer (not a translator only)

- **Status:** Proposed
- **Date:** 2026-05-30
- **Affects:** CLAUDE.md §2.2, §2.6, §2.7, §5.1, §9; the L2 layer

## Context

A reference product (Cipher) runs a continuous, fully-agentic loop:
**build context → reason → plan → validate → remediate → learn**, where the
agent itself decides what to scan, triggers scans, reviews output, and
re-plans — with a persistent "living security graph" and compounding
cross-engagement memory.

tsengine today draws a hard line: **L1 detects deterministically; L2
translates.** CLAUDE.md §2.2 states *"L2 cannot translate findings L1 didn't
surface"* and frames L2 as a pure translator for non-security audiences. Two
consequences fall out of that framing:

1. **Strength — a recall floor no model can undercut.** The L1 recon→fan-out
   runs regardless of the LLM. This exists *because* the strix lineage shipped
   the bug where "the model ignored the recon directive" (§5.1): when an LLM
   decides what to scan, recall becomes model-dependent and non-reproducible.
   For the security-engineer and **compliance** audiences (who need "same scan
   = same result", §10), a model-driven floor is disqualifying.

2. **Limitation — a discovery ceiling at L1's tool coverage.** If L2 is *only*
   a translator, tsengine can never surface what L1's deterministic OSS tools
   miss: BOLA/BFLA authorization logic, business-flow abuse, and multi-step
   chains — exactly the classes an agentic discoverer finds by reasoning, and
   exactly where no OSS oracle exists (§5.2.6 already flags this as a gap).

The question raised: should L2 do its own scanning/analysis of the environment
and drive scans bidirectionally, rather than the current one-way L1→L2 flow?

## Decision

**Keep the deterministic L1 floor. Promote L2 from "translator only" to
"translator + *bounded* discoverer." The separation is a floor, not a wall.**

Concretely:

1. **The L1 deterministic prepass stays the non-negotiable recall floor.** It
   is the source of the §2.4 recall guarantee and §10 reproducibility — the
   two things a pure-agentic loop structurally cannot offer. L2 never *replaces*
   it.

2. **L2 may discover *additively* above the floor.** The agent analyzes
   context → forms hypotheses → triggers targeted probes → reviews → re-plans
   (the Cipher loop), but for the classes deterministic tools can't reach, and
   layered on top of — never instead of — the deterministic pass.

3. **The bidirectional channel already exists: `dispatch_l2_probe` (§9).** This
   ADR does not add a new escape hatch; it makes the existing one richer and
   blesses the loop. Probe results re-enter L2's OODA reasoning (already the
   ReAct loop), and — once L3 lands — write back to a persistent graph so the
   review compounds.

4. **Bounds and audit are mandatory.** L2-driven probes are capped (an
   escalation-style budget, cf. `TSENGINE_ESCALATION_MAX`) and every probe is
   audited (`discovery_method.replay_of`, §9). The agent's discovery is
   visible, replayable, and cost-bounded — it does not become an unbounded
   model-driven scan.

5. **Two prerequisites, tracked separately:**
   - **A "living security graph" (L3).** L2 cannot intelligently decide what to
     probe without a model of the system (architecture, trust boundaries,
     prior findings). This is the biggest delta vs the reference loop and is
     currently deferred (§5 L3 = future).
   - **Relax the §2.2 stance** from "L2 = translator only" to "L1 floor is
     deterministic; L2 may discover additively above it, bounded + audited."

## Consequences

**Positive**
- tsengine keeps the recall floor + reproducibility (its compliance moat) while
  gaining the agentic discovery ceiling (the reference product's advantage).
- BOLA/BFLA and multi-step chains become reachable via L2 reasoning without
  weakening L1.
- No new bypass of the host/sandbox boundary or the ≤12-tool cap — probes route
  through the existing replay path (§9) and `dispatch_l2_probe` slot.

**Negative / risks**
- L2-discovered findings are, by nature, less reproducible than L1's. Mitigation:
  they are tagged (`verification_status`, `discovery_method.replay_of`) and the
  **L1 dashboard the security engineer reads stays the deterministic floor**;
  L2 discoveries surface in the L2/developer view, never silently in
  `findings_raw`.
- Cost. Mitigation: known signal→tool mappings stay in *deterministic* L1
  escalation (§5.3, zero-token); only open-ended discovery is L2, and it is
  budget-capped.

## Alternatives considered

- **Go fully agentic (drop the L1/L2 split), like the reference product.**
  Rejected: forfeits the recall floor and reproducibility — the exact
  properties the security + compliance audiences buy tsengine for, and the
  exact strix bug class (§5.1) this architecture was built to make impossible.
- **Keep translator-only.** Rejected: permanently caps discovery at L1's OSS
  tool coverage; cedes the authz-logic / chain classes entirely.

## Validation hook

The companion to this ADR is the **differential-recall (tool-parity) harness**
(`internal/bench/parity.go`, `tsbench parity`): it proves the L1 floor holds —
the orchestration drops nothing the standalone tool finds (§2.4) — so additive
L2 discovery is always measured *on top of* a verified floor, never as a
substitute for one.
