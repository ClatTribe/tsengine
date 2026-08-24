# ADR 0030 — Agent fleet over an engagement worldview: two graphs, one identity space, every generative step paired with its counter

**Status:** Proposed.

**Date:** 2026-08-24

**Depends on / reconciles:** CLAUDE.md §2.2.1 (specialist taxonomy — this changes no specialist
boundary), §5.1 (recon→fan-out and its caps — the bounds below are deliberately the agent-layer
twins), §5.3 (signal-gated escalation), §7.1 (threat-informed discovery), §10 (evidence grounding),
§11 (hook chain untouched), §12.6 (agents execute host-side), §14 (bench + anti-overfit rules),
ADR 0006 (RoE guard — unchanged), ADR 0008 (XBOW exploitation parity — this is its scale-out),
ADR 0019 (offensive exploit intel — becomes worker fuel), ADR 0021 (offensive agent consolidation —
workers are its output), ADR 0024 (best-in-breed gaps — closes the fleet/worldview rows),
ADR 0029 (exploitation-proven end-to-end — the per-hop verification ladder this completes).
**Supersedes:** nothing. Retires nothing immediately; `crossdetect`'s eventual retirement into
`estategraph` projections remains the strangler plan it already documents.

---

## Context

Three measured facts motivate this ADR; none is speculative.

1. **Variance, not capability, is the gap.** On XBOW's own public suite the pentester solves
   **78/104 first-attempt (pass@1 0.75)** and **89/104 allowing retries (0.86)** — an eleven-point
   spread attributable to context exhaustion and luck of draw, not missing capability
   (`internal/bench/scorecard.go`). Every offensive agent in the tree (`l2.Agent`,
   `webagent.Investigate`, `cloudagent.Investigate`, the pentest runner) is a single serial loop;
   `web.go:219` is representative. One context, one draw, one chance.
2. **Discovery breadth is the bottleneck.** AgentCyberRange's published result — endpoint discovery
   is the #1 predictor of success, hinted jumps take success from ~16% to ~33% — matches our own
   ledger. A serial agent that spends half its turns finding the surface has lost before it probed.
3. **Agent runs disclose coverage only at run granularity, not per class×route.** PR #1444 added
   `webagent.Report.Coverage` (stop reason, probed-vs-known routes, the now-consumed
   `Requester.Denied()` count, budget exhaustion, WAF signatures) — the run-level coverage-honesty
   gap is CLOSED, and this ADR builds ON that foundation rather than re-litigating it. What is still
   missing is the per-target ledger the fleet needs to schedule against and the report needs to be
   trustworthy at finding granularity: which CLASS was proven / clean / denied / contested / never
   tried on which ROUTE. A flat "probed 40/50 routes" cannot say a route was checked for XSS but
   never for authz — §5.2 rule 5 at the granularity a fleet coordinator can act on.

Industry convergence (XBOW fleet posts, Rapid7's red-team multi-agent writeup, Anthropic
orchestrator-worker guidance) agrees on the shape: short-lived workers over clean contexts plus a
persistent, adjudicated view of what has been covered. The failure mode that shape invites — and
the reason this ADR exists rather than a bare "add parallelism" note — is **unbounded exploration**:
discovery generates routes, routes generate workers, conflicts generate re-probes, retries multiply,
and the spend curve never bends. strix died of exactly this class of bug at L1 (Q5.34l); §5.1's caps
are its grave marker. The fleet reproduces every one of those risks multiplied by worker count,
unless bounding is structural.

---

## Decision overview

Five decisions, each with its refusal stated:

| | Decision | The refusal that makes it ours |
|---|---|---|
| D1 | Two graphs: persistent estate graph + per-engagement worldview | Never merged; never a second identity space |
| D2 | Existing agents become workers, unchanged | The coordinator gains zero action authority |
| D3 | Deterministic kernel forever; LLM planner proposes inside validated bounds | The model widens what is tried, never what counts as true |
| D4 | The frontier is intelligence-led (scanner + threat intel), not crawl-led | Discovery beyond the evidence-led frontier is capped and disclosed |
| D5 | Bounded by construction: every generative step pairs a closing counter | Termination asserted by test, not observed in practice |

---

## D1 — Two graphs, one identity space

The repo already owns half of the "common view": `internal/estategraph` holds what **is true**
across code, cloud, identity, api, domain, container, saas — nodes, evidence-cited edges
(`AddEdge → ErrNoEvidence`), exact-only identity resolution (`Canonical`), additive-only merge
(sensitivity/exposure rise, never clear), bounded `PathsFrom`, real-betweenness `ChokePoints`.
It answers *what exists and what reaches what*.

The engagement worldview answers a different question: *what did we try, prove, deny, fail to finish
during this run*. Its verdicts get overturned by re-probe; the estate graph's facts must never
silently downgrade. Different mutability semantics ⇒ different types. **Merging them is refused**:
a worldview entry is provisional by design, and provisional state inside the persistent substrate
would let a re-probe launder an estate fact.

But they share **one identity space**: worldview entries store projections of `estategraph.Canonical`
identities (routes, principals, secrets, buckets), never a second universe of stringly-typed
endpoints. This is cheap now and expensive to retrofit, so Phase A adopts it from day one.

The relationship, drawn:

```
        estategraph (persistent)            worldview (per-engagement)
        what IS true                        what we ESTABLISHED this run
             ▲  │ typed projections            ▲  │ claims (evidence-cited)
             │  ▼ (SurfaceSlice)               │  ▼ (debriefs)
             │        COORDINATOR              │
             │   kernel: merge · evidence ·    │
             │   budgets · waves · scope       │
             │   planner (LLM): chunks ·       │
             │   priorities · resolutions      │
             │   → kernel validates, disposes  │
          [worker] [worker] [worker]
```

Runtime discoveries flow BACK: a worker proving `code:repo/app.py --leaked--> cloud:role/deploy`
writes that edge into the estate graph carrying turn-ID evidence (D6). Today estategraph is
ingest-fed only, so an exploitation-proven hop evaporates at engagement end. Closing that loop is
what upgrades attack paths from *grounded* to **verified per hop** — the third rung of the ladder
ADR 0029 builds toward, and the claim no competitor ships.

## D2 — Workers are the existing agents, unchanged

A worker is one existing engagement function over one scoped slice: `webagent.Investigate`
(primary), later pentest ModeDeep drivers and Lead verify-tasks. It keeps its own loop, its own
≤12-tool catalog (§2.6 untouched — the worldview reaches workers as **prompt content via a compact,
paged digest**, not as catalog slots), its own Requester/session (cookie jars are never shared —
a shared jar poisons `bola_diff` controls; what is shared is the validated login *recipe*, stored
in the worldview), and its own RoE gating per action.

Strangler rule, pinned before anything parallel ships:

> **TestFleet_SingleWorkerMatchesDirectInvestigate** — a 1-chunk, 1-worker fleet produces a report
> byte-identical to calling `Investigate` directly today.

## D3 — Propose/dispose, one level up

The split follows §5.3's own line (known signal→action mappings are deterministic; open-ended
reasoning is the LLM's job) applied to orchestration:

| Decision | Owner | Why permanent vs proposable |
|---|---|---|
| Merge precedence, contested detection, evidence validation | Kernel, **forever** | Correctness contract. An LLM adjudicating claims is a hallucination surface over ground truth — the lesson every fleet operator has published |
| Budgets, rate governance, wave partitioning, scope containment | Kernel, **forever** | Safety contracts must be auditable and race-testable |
| Decomposition strategy for novel app shapes | **LLM proposes**, kernel disposes | Judgment ("SPA behind an API gateway → split by API surface") |
| Priority over untested regions | Hybrid: deterministic base score, model reranks inside validated bounds | Base score keeps identical inputs → identical plan; rerank spends judgment where it pays. Honest limit: disposal protects GROUNDING, not EFFICIENCY — a bad rerank wastes budget on the wrong region without being disposably-wrong, so the deterministic base score (threatintel × Reaches × data-tier) is the floor that keeps a bad rerank bounded |
| Contested-resolution strategy (re-probe / panel / human) | **LLM proposes**, policy table disposes | Cost/value judgment; execution mechanical |

An LLM-proposed decomposition exceeding chunk-count or violating minimum chunk size is **refused by
the kernel** and falls back to deterministic partitioning — the model widens what is tried, never
what counts as true. This is the same invariant as `DemoFromSpec`, at coordination altitude.

## D4 — The frontier is intelligence-led, not crawl-led

Unbounded exploration is prevented twice: by the counters in D5, and by making the *default*
frontier small because it is evidence-ranked. The exploration queue is a priority stack consumed
against finite budget — **ordering IS the bound**, because the highest-evidence work completes
before any cap cuts the tail:

| Tier | Source | Ranking signal (all existing machinery) |
|---|---|---|
| 0 | Auth establishment | wave 0; validated recipe stored for reuse |
| 1 | L1 scanner seeds | `SeedFinding.Enrichment`: KEV > EPSS > public exploit > weaponized rank (the `L15Summary` order), exploit-context skeletons attached (ADR 0019) |
| 2 | Corpus-driven CVE probes | `threatinformed.Plan` over observed technology — the same corpus, same env var (`TSENGINE_THREAT_INTEL_CORPUS`), so annotation and targeting agree on world-state (§7.1's own rule) |
| 3 | Crown-jewel routes | `EstateLead.Reaches` × data-tier weighting (platform layer) × `estategraph.ChokePoints` |
| 4 | Residual discovered surface | capped, shape-deduped (`/items/N ≡ /items/M`), param-bearing first, static assets dropped |

Tiers 1–3 exist today as wiring at L1 or in the worker input surface; the fleet's contribution is
consuming them as ONE ordered frontier instead of letting a crawl lead. Tier 4 is what remains when
the evidence runs out — and it is the tier the counters in D5 govern.

## D5 — Bounded by construction

Every generative mechanism pairs with a closing counter. Termination is structural: all counters
monotonically consume finite envelopes, and the scheduler may only act when doing so provably
reduces a measured deficit.

| # | Runaway vector | Closing counter | Pinned by |
|---|---|---|---|
| 1 | Discovery loop (probe → new routes → new workers) | Routes enter the worldview **only through Tier-4 filtration**, under hard `TSENGINE_FLEET_MAX_ROUTES` + `MAX_CHUNKS`; overflow counted + disclosed ("N discovered, unexplored"), never silently dropped, never explored | `TestFleet_DiscoveryOverflowDisclosedNotExplored` |
| 2 | Marginal-value stop defeated by #1 | Absolute envelope: engagement request reservation + `$` cap + wall-clock ctx, drawn down atomically by all workers; at zero — no worker, no probe, full disclosure | `TestGovernor_EnvelopeIsAbsolute` |
| 3 | Adjudication loop (Clean vs Vulnerable forever) | Max 1 re-probe per contested pair → `consensus` panel (fails-open keeps the candidate, rationales ride) → final state renders **Contested**, honestly unresolved. The panel MAY raise coverage confidence; it MUST NOT set a finding's `verification_status = verified` (see the invariant below) | `TestAdjudication_ContestedTerminates`, `TestAdjudication_NeverUpgradesToVerified` |
| 4 | Multiplier stacks (K looks × retries × trials) | `CoverK ≤ 3`, crown-jewel-adjacent routes only; inconclusive retries draw from a finite pool spent by lead-weight; variance trials are bench-only cost | `TestCoverK_AppliesOnlyWhereDeclared` |
| 5 | Planner-generated decomposition | Chunk-count cap + minimum chunk size enforced at validation; violating plans fall back to deterministic partitioning | `TestCoordinator_RefusesPlanViolatingCaps` |
| 6 | Frontier stalls (spends without progress) | Stalled-coordinator watchdog: no deficit reduction (untested/contested/denied-unknown counts) in N minutes → terminate with full what-was-covered disclosure — the l2 `budget.stalled()` pattern ported | `TestCoordinator_StallWatchdogFires` |
| 7 | Persistent growth (D6 estate writes across runs) | Per-run observation cap `TSENGINE_FLEET_MAX_OBSERVATIONS`; `Canonical` dedup means repeats merge, never grow | `TestEstateWrite_CappedPerRun` |
| 8 | Digest bloat re-creating context exhaustion | Worker-facing worldview digest is paged top-N by priority score **with a query operation for the rest** — truncate-without-access (the l2 `prompt.go` "+N more" defect) is refused by design | `TestDigest_PagesWithQueryNotBlindCap` |

Frontier monotonicity is the formal core: a chunk is schedulable iff executing it reduces a counted
deficit by ≥ 1. With caps upstream the deficit is finite; therefore the schedule terminates.
`TestFleet_TerminatesOnCappedSurface` asserts the scheduler reaches "no schedulable chunk" in
bounded steps on a synthetic infinite-discovery fixture (a server that mints fresh links forever —
the exact hostile case).

Wave partitioning ports §5.1 rule 4: chunks sharing an auth context or reset endpoints
(`race_probe` state) are state-coupled and never share a wave — concurrent workers running
differentials against each other's controls corrupt both results.

**Invariant — adjudication annotates coverage, it never upgrades a finding's tier.** A finding's
`verification_status = verified` is predicate-owned (PR #1444 / §5 L2.5): it is set ONLY when a real
`send_request`/`dispatch_l2_probe` executed and its deterministic predicate held. The class-level
`Contested` verdict and a finding-level `verified` are DIFFERENT granularities and compose freely —
two workers may honestly disagree on "is `/x` vulnerable to sqli" while one of them holds a
genuinely predicate-proven finding. But the `consensus` panel resolving a `Contested` verdict may
only raise the worldview's coverage confidence; it may NEVER set a finding to `verified`. Without
this line the fail-open "keep the candidate" is a back door around the exact gate #1444 closed — a
panel of LLMs promoting an unproven finding, which §2.5/§13 forbid everywhere except the codesweep
disposer. `TestAdjudication_NeverUpgradesToVerified` pins it.

## D6 — Runtime evidence writes back, capped, without breaking the leaf

`estategraph` stays a LEAF (its own header rule). The write path lives on the fleet side: debriefs
call `estategraph.AddEdge` with turn-ID evidence through the same public API the ingest converters
use — estategraph learns nothing about workers. Per-run cap from D5-7 applies. An edge whose
evidence is a worker turn is marked with its provenance so an auditor can distinguish
inventory-derived edges from engagement-proved ones; the additive-only merge semantics are
unchanged (an engagement may strengthen, never weaken, an estate fact).

**Deferred — cross-run retention.** The per-run cap (D5-7) bounds one engagement's writes;
`Canonical` dedup merges repeats. But the persistent graph is rise-only, so across many runs
distinct real edges still accumulate without bound — intended (it IS the accumulating estate), but
it eventually needs a retention/confidence-decay story (a stale edge whose backing finding was
later re-scanned clean should weaken). Out of scope for this ADR; logged here so it is a known
deferral, not a surprise discovered in production.

## Phases

Each phase ships standalone value and is gated before the next.

**A — Worldview as passive artifact (~days).** Run today's serial engagement; build the worldview
from Turns post-hoc; attach the per-class×route ledger to `Report` alongside the run-level
`Coverage` block #1444 already ships. This DEEPENS that block (Context #3) — from "probed 40/50
routes" to "route `/x`: sqli proven, authz never tried, xss clean" — it does not re-close a closed
gap. Zero new risk (no parallelism, no new authority). Canonical IDs and typed projections from day
one. Tests: golden merge determinism; `Update` refuses evidence-less claims (`ErrNoEvidence`);
conflict → `Contested` never overwritten; single-worker identity vs today's `Investigate`.

**B — Intelligence-led decomposition, sequential (~1 wk).** Tier stack from D4 becomes the
frontier; chunks run one at a time. Validates merge/adjudication on real runs with zero rate/state
risk. Tests: overflow disclosure; contested termination; plan-validation refusals.

**C — Bounded parallelism (~1 wk + live validation).** `TSENGINE_FLEET_WORKERS` (default unset =
serial path), shared governor, shared latching breaker extended with health kinds
(`session_invalid`, `waf_block`, `target_unhealthy` — the deterministic auto-pause the evaluation
flagged as missing, arriving as a side effect). Tests: envelope absolute under concurrency; shared
breaker trip halts all workers; rate ≤ limit with N workers.

**D — Policy layer (ongoing).** `TSENGINE_FLEET_COVER_K`; consensus adjudication of Contested;
best-of-N as the intra-chunk depth mechanism (independent full attempts at one chunk, the variance
lever XBOW measures — distinct from decomposition's breadth lever); assurance tiers (fast = pass@1,
verified = best-of-N, priced through the existing budget clamp); `$`/finding recorded beside rates —
**prerequisite**: usage accounting is a change to the SHARED `cloudengine.LLM.Generate` seam
(returns `(string, error)` today, no usage) and its three clients (Anthropic/Gemini/OpenAICompat),
touching both the webagent and cloudagent lanes — NOT a `generateWithRetry`-local add. Note the
asymmetry: `l2.Agent` already accounts usage on its own seam (`resp.Usage`), so this migration
brings the offensive lanes up to the Lead's level. Without it the ablation cannot judge cost and
Phase D is blocked on it honestly.

## Measurement — the number that decides whether C survives

**Match the yardstick to the mechanism, or the gate lies.** Phase C is DECOMPOSITION — splitting one
target's surface across workers (breadth). XBOW's own suite is single-flag, single-class per
challenge (one exploitable path each — confirmed in `internal/bench/xbow_ledger`), so decomposition
has almost no surface to split there and would show ~zero lift *by construction* — measuring it on
XBOW risks a false-negative that wrongly kills the build at the Phase-A gate.

So the ablation splits by mechanism:

- **Phase C (decomposition) is measured on a BREADTH target** — the live many-route apps
  (`bench/juiceshop_full`, crAPI/VAmPI via `bench/api_fixtures`), N=3 trials, reporting coverage %,
  detection_rate, verified_rate, `$`/finding. The hypothesis is AgentCyberRange's: a serial agent
  that spends half its turns finding the surface loses; parallel workers over disjoint chunks cover
  more of it. If 2–3 workers show no coverage/detection lift on a broad target, **stop at Phase A**
  (which still shipped the deepened coverage ledger). That is a real outcome, cheaper to learn now.
- **XBOW stays the yardstick for Phase D's best-of-N tier** — variance reduction (independent full
  attempts at the SAME challenge) is the mechanism the 0.75→0.86 pass@1-vs-best-of-retry gap
  measures, and it is a DIFFERENT mechanism from decomposition. Conflating them under one XBOW
  ablation is the mistake this section exists to avoid.

Per §14.2 rule 5: record the number BEFORE building further on it, and against the neutral external
suite, not an in-house fixture that agrees with the code.

## Alternatives considered and rejected

- **LLM coordinator owning state** — rejected in D3: an adjudicator that believes things is
  unrecoverable and unauditable; every published fleet post converges on deterministic disposal.
- **One merged graph** — rejected in D1: overturnable trial verdicts inside an append-only substrate
  would let re-probes launder estate facts.
- **Big-bang new agent framework** — rejected in D2: workers are measured assets (the 0.86 lane);
  replacing them discards the only externally-benchmarked capability in the tree.
- **Deterministic-forever coordinator (no planner ever)** — rejected as dogma: decomposition of
  novel app shapes is genuinely open-ended judgment; refusing the model there re-creates the
  "deterministic spine with LLM bolted on" shape §10 removed. Propose/dispose resolves it.
- **Crawl-first with post-hoc filtering** — rejected in D4: spending budget before ranking is how
  unbounded exploration manifests even with caps; the caps then bind exactly where value is lowest.

## Honest risks

- **Worker interference on live targets** (lockouts, corrupted differentials) — mitigated by wave
  partitioning + per-worker sessions + governor; remains the main live-validation item for C.
- **Cost multiplication during measurement** — mitigated by bench-gating trials; still real.
- **Worldview drift into fiction** — mitigated structurally (evidence-or-refuse, Contested-not-
  overwrite, provenance-marked estate writes); every conflict resolution is logged per §2.5.
- **Two digests to keep honest** (worker-facing paged digest, report-facing coverage disclosure) —
  the recurring failure in this repo is a signal computed and shown to nobody; both surfaces are
  uicheck-guarded from Phase A onward.

## What this deliberately does NOT change

No detection logic (§13 holds — the fleet orchestrates agents, which orchestrate tools). No change
to the RoE Guard, consent, or HITL gates (workers remain per-action gated; the coordinator adds no
authority). No change to the ≤12-tool cap (worldview content rides prompts, not catalogs). No change
to the L1 engine or hook chain (§18.2 inv 1). No automatic activation: unset `TSENGINE_FLEET_*`
means today's behavior exactly, asserted by test.
