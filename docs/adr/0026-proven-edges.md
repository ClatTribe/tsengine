# ADR 0026 — Proven edges: exploitation state on the estate graph

**Status:** **Phase 1 SHIPPED** (types + refusals + merge rules + weakest-hop path aggregation, pure
and leaf-only, no caller changed). Phases 2–4 proposed. Adds a PROOF STATE to `estategraph.Edge` and,
later, the one converter that returns a pentest demonstration to the graph — so a hop an attacker
actually traversed and a hop a policy merely permits stop being the same row.

**Until phase 2 lands, every edge in the running product is `config_possible`.** Phase 1 makes the
distinction REPRESENTABLE; it does not make it true of any estate. Nothing renders a proof state yet
(phase 3), so a half-landed change cannot show a reader a claim the graph cannot support.

**Date:** 2026-08-23
**Depends on / reconciles:** CLAUDE.md §10 (evidence grounding — the model proposes, the framework
disposes), §2.2.1 rule 2 (split by domain, not by task), §18.2 inv. 5 (grounding holds end to end);
`cloudgraph.PruneUnreachable` (theoretical vs real network reach) and the provider dry-run
(config-possible → provider-confirmed), which draw this same line one layer down.
**Neighbour, not overlap:** ADR 0025 (field evidence) aggregates verification outcomes ACROSS tenants
to calibrate what evidence is sufficient. This ADR records proof state WITHIN one tenant's graph.
0025 asks *"how often does a clean re-scan lie?"*; this asks *"was this specific hop ever crossed?"*.
**Supersedes:** nothing.

## Context

`internal/estategraph` is the ground truth BOTH L2 agents read, and both directions are wired today:
the AI Security Engineer reaches it through `cloudagent`'s `estate_context` tool, and the AI Pentester
through `webagent.Context.Leads` ← `estateingest.LeadsForRoutes` ← `platformapi.leadsFor`.

`Edge` carries `Evidence []string`, and `AddEdge` refuses without it (`ErrNoEvidence`). That answers
**"who asserted this hop exists"**. It does not answer **"did anyone ever traverse it"** — and nothing
in the type distinguishes the two. So:

> A hop a trust policy PERMITS and a hop the pentester ACTUALLY CROSSED render identically, to both
> agents and to the human reading the attack-path page.

That is the "rendered identically, X and Y are the same row" defect this codebase keeps naming
(`Incident.AbsentPasses`, `Incident.Onset`, `DeclaredGaps` vs `UntestedClasses`) — sitting inside the
one capability where we actually lead the AEV lane.

**Four consequences, in order of severity.**

1. **It is the category's own definition.** Gartner's AEV is *evidence of the FEASIBILITY of an
   attack*. We already draw exactly this line one layer down — `cloudgraph.PruneUnreachable`
   separates theoretical from real network reach, and the provider dry-run work drew the same line
   for authorization (**config-possible → provider-confirmed**). The graph the agents traverse is the
   one place the distinction was never made.
2. **The strongest evidence this product generates is discarded.** An authorized exploit that
   succeeded is a harder fact than any policy inference in the graph, and it never returns to it.
3. **Both agents prioritise blind.** The pentester's `Leads` rank by stakes but not by what is already
   proven, so budget can be spent re-proving a crossed hop while the one unproven load-bearing hop is
   ignored. The engineer's `propose_fix` cannot prefer cutting a DEMONSTRATED edge over a theoretical
   one — which is the whole point of ranking remediation by exploitability.
4. **Closure is keyed on findings, not paths.** `retest`/`ApplyReattack` resolve `rule_id|endpoint`
   keys. A fix that closes hop 3 of a 5-hop path clears a finding; the PATH's status is never
   recomputed, so the cross-surface claim outlives the thing that made it true.

This is not a defect in `estategraph` — it shipped strangler-style and deliberately leaf-only, and
`AddEdge`'s refusal is the right one. This ADR adds the missing RETURN edge.

## Decision

Add a proof state to `Edge`, one converter that derives it from a demonstration, and weakest-hop
aggregation on paths.

### The states

| State | Claim | Explicitly NOT a claim |
|---|---|---|
| `config_possible` **(default)** | the configuration permits this hop | that anyone ever did it |
| `demonstrated` | an AUTHORIZED attempt crossed this boundary, citing its demonstration id | that it is still possible today (see `ProofAt`) |
| `exploit_failed` | a previously demonstrated edge whose recorded exploit no longer succeeds | **that the hop is closed** |

**There is deliberately no `closed` state.** One exploit failing is not proof a hop is gone — the
signature moved, the route moved, the payload stopped matching. Those are the same cases
`scanner_sees_variant` exists to name, and `retest`'s rule is already that absence is the weaker
evidence. `exploit_failed` downgrades an edge to config-possible-with-history; the edge itself
disappears only when its CONFIG evidence does, which is a different detector's job.

Defaulting to `config_possible` means **every existing producer keeps working unchanged** and none of
them accidentally claims more than it did.

### The refusals (each gets a mutation-verified test)

1. **Only a boundary CROSSING may mark an edge.** Most exploits prove a NODE fact ("this endpoint is
   injectable"), not a traversal. A reflected-XSS finding marks nothing. Qualifying shapes are the
   ones that actually moved between surfaces: `ssh_exec` with discovered credentials (code → host), a
   leaked key used against a live cloud API (code → cloud), `bola_confirmed` reading another
   principal's object (identity → data), `privesc_confirmed` (principal → admin). Without this
   refusal every finding becomes a proven edge and the state means nothing — strictly worse than not
   having it, because it would launder inference as proof.
2. **Proof RISES on evidence and never falls silently.** Mirrors `MergeSensitivity`. A downgrade needs
   its own evidence (a recorded failed re-attack); a re-run that did not happen leaves the state
   untouched. This is the degraded-pass rule — three consumers already reason from absence and all
   three had to be gated — applied to the graph before it acquires a fourth.
3. **`demonstrated` requires a resolvable demonstration id.** No id → refuse, the same shape as
   `ErrNoEvidence`. A proof nobody can replay is not a proof.
4. **A path's proof is its WEAKEST hop.** `demonstrated` only if every hop is. Calling a path proven
   because one hop was is the exact overclaim this ADR exists to remove.
5. **Proof is time-stamped and never auto-expires.** `ProofAt` records when; a renderer states the
   age. Nothing silently flips an old proof to unproven, because "we have not re-checked" and "it no
   longer works" are different claims — the distinction the coverage layer is built on.

### Wiring — the return edge

- `internal/estateingest/exploit.go` — `EdgesFromDemonstration(...)`: a verified pentest finding plus
  its demonstration → zero or more edge proofs. **Zero is the common and correct answer.** The
  converter lives in `estateingest`, not `estategraph`, so the graph stays a leaf that knows about no
  detector (the existing strangler seam).
- Called where pentest findings are persisted, so the graph learns from every engagement rather than
  from a separate opt-in step nobody runs.
- `PathsFrom` returns per-path proof; `ChokePoints` may weight demonstrated edges above possible ones.
- Re-attack targets the demonstrated HOP, so closure recomputes the PATH instead of only the finding
  key — the thing Horizon3's finding-level 1-Click Verify does not do.
- `estatedetect`'s `estate::cross-surface-path-to-crown` states its proof state in the finding, and a
  demonstrated path may carry a different severity from a permitted one, because they are different
  claims.

## What this ADR does NOT do

No internal AD/lateral surface. No new asset type. No change to L1 detection or the L1.5 chain. No new
agent, and no new tool in either agent's catalog (§2.6 cap untouched). `crossdetect` is not retired.

## Alternatives considered

- **Keep proof on findings and join at render.** Rejected: the AGENTS traverse the graph. A render-time
  join leaves both agents unable to prioritise by proof, which is most of the value.
- **A separate "proven paths" store.** Rejected: two ground truths drift. That is the lesson behind
  strangling `crossdetect` rather than extending it, and behind the §11 two-doors bug.
- **A boolean `Proven bool`.** Rejected: it forces `exploit_failed` to be represented as "not proven",
  collapsing *never tried* with *tried and it failed* — the single-bool mistake `gcpiam` already had
  to undo when a conditional allow turned out to be three distinct states.

## Consequences

- The attack-path surface can finally say THEORETICAL vs PROVEN — the AEV category's own definition —
  on the lane where we lead.
- Capability 2 (closure) stops being "parity with Horizon3 minus the UX": path-level closure is a
  claim their finding-level verify cannot make.
- Cost: every edge producer now makes a decision it did not make before. The default keeps that
  honest, and refusal 1 keeps the new state narrow.
- **Risk — sparse proof.** Most estates will carry zero demonstrated edges until an engagement runs.
  That is correct, and it must render as *"not yet tested"*, never as *"not exploitable"*. A UI that
  gets this backwards would turn the honest state into the false-clean it was built to prevent.

## Guards

- Table test: every declared state is emitted by some real path (a state declared and never produced
  is the silent-signal bug one level up).
- Mutation: deleting the boundary-crossing check must FAIL — an XSS finding must yield zero edges.
- Mutation: deleting weakest-hop aggregation must FAIL.
- A proof carrying an unresolvable demonstration id is refused.
- The arch.md §14 "the exploit's proof never returns to the graph" bullet is deleted only when this
  lands — not when the types land.

## Rollout

1. **DONE** — types + refusals (pure, leaf, no caller changed): `EdgeProof`, `Edge.Proof` /
   `.ProofRefs` / `.ProofAt`, `ErrProofUngrounded` / `ErrProofUnstamped` / `ErrUnknownProof`,
   `MergeProof`, `Path.Proof()`. Every refusal is mutation-verified (`internal/estategraph/proof.go`,
   `proof_test.go`).
2. `EdgesFromDemonstration` in `estateingest` + persist wiring. **Nothing populates proof until this
   lands** — the arch.md §14 bullet stays until it does.
3. Path aggregation consumed by `estatedetect` severity + UI proof state.
4. Re-attack targets hops; closure recomputes paths.

Each phase is independently useful; nothing renders a proof state before phase 3, so a half-landed
change cannot show a reader a claim the graph cannot yet support.
