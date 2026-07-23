# ADR 0016 — Offensive-agent persistent world-model + cross-host chaining

Status: **Accepted** — P1–P3 + P5 built; P4 revised (see §3)
Date: 2026-07-23
Lineage: extends [ADR 0008 — XBOW web-exploitation parity](0008-xbow-web-exploitation-parity.md)

## 1. Context — the gap

The offensive agent (`internal/webagent`, the `web-investigate` / XBOW driver) is a ReAct loop
whose working memory is `Context` (`web.go:19`). Today that memory is **flat and transcript-shaped**:

- `Routes []string` — a bare list of URLs, no structure (no methods, params, forms, auth-requirement,
  or provenance per endpoint).
- `Defenses []string` — WAF/filter signatures as free text.
- `History []Turn` — the request/response evidence substrate, **head/tail-capped to the last ~24 turns**
  (`web.go:307`). Older evidence is dropped.
- `Findings []Finding` — recorded vulns.
- Explicitly **in-process, not durable** (`web.go:17`) — nothing persists across engagements.

The productized pentest (`internal/pentest`, ModeDeep `OpenEndedDriverIterative`) is worse for
free-roaming: it iterates **within one seeded finding** and its only cross-finding memory is
`engMem []FailedAttempt` (cap 16, `iterative.go:84`) — a shared *environment hint*, not a surface model.

**Consequences of the flat model (the XBOW-parity deficit):**

1. **No free-roaming discovery model.** The agent can't reason over "which endpoints have I found, which
   params are untested, which forms lead where" — it re-reads a capped transcript.
2. **No cross-host chaining.** `ssh_exec` (`ssh.go`) lands one credential-based hop, but there is no
   model of *host B's* newly-discovered surface, so the agent can't pivot: leaked cred → SSH host B →
   discover a web app on B → scan it. Each host is an island.
3. **No structured attempt memory.** "I already tried boolean-SQLi on `/search?q=` and it 403'd" lives
   only in the (capped, evaporating) transcript, so on a long engagement the agent re-tries dead ends.
4. **No persistence.** A re-run starts from zero; nothing learned about the target survives.

XBOW's edge is long-horizon coherence: a durable, structured mental model of the target that the
model reasons over instead of re-deriving from scrolling text. That is the gap this ADR scopes.

## 2. Decision

Introduce a **structured, persistent, evidence-grounded world-model** the offensive agent reasons over,
replacing the flat `Routes`/`Defenses` and supplementing (not replacing) the `History` evidence trail.
Unify the pentest `engMem` into the same model so both L2 offensive paths share one memory.

**Grounding invariant (non-negotiable, §10):** every world-model entity is *derived from a real `Turn`*
(a request the agent actually sent + the response it got) or a real tool result. The world-model is a
**structured index over evidence**, never a place the LLM writes free assertions. A node/edge that no
`Turn` supports cannot exist. This keeps the model consistent with the project's "tools are the hands,
evidence grounds every claim" discipline — the world-model is derived state, like `cloudgraph` is over a
cloud snapshot.

### 2.1 Data model (`internal/webagent/worldmodel.go`)

```
WorldModel
  Hosts     map[string]*Host        // keyed by host:port — the cross-host graph's nodes
  Endpoints map[string]*Endpoint    // keyed by method+URL-shape (params normalized: /items/1 ≡ /items/N)
  Identities []*Identity            // sessions/creds the agent holds (cookie, bearer, ssh key), + role
  Attempts   []*Attempt             // (endpoint × class × approach) → outcome + evidence turn
  Edges      []*PivotEdge           // host→host provenance (a leaked cred on A opens B)

Host      { ID; Reachable bool; Services []string; DiscoveredFrom string /*turn id*/ }
Endpoint  { Host; Method; URLShape; Params []Param; Form bool; AuthRequired bool; FromTurn string;
            Tested map[string]AttemptOutcome /* class → outcome */ }
Identity  { Kind (cookie|bearer|ssh); Value; Role; Host; FromTurn string }
Attempt   { EndpointKey; Class; Approach; Outcome (confirmed|failed|blocked); Reason; Turn string }
PivotEdge { FromHost; ToHost; Via (leaked-cred|ssrf|source-disclosure); Evidence string /*turn id*/ }
```

Every struct carries a `FromTurn` / `Evidence` turn id — the grounding link. `AttemptOutcome`
subsumes the pentest `FailedAttempt` (so `engMem` becomes a *view* over `Attempts` filtered to failures).

### 2.2 Integration

- `Context` gains `World *WorldModel`; `Routes`/`Defenses` become **derived views** over it (kept as
  accessors for back-compat so the 21 webagent test files don't churn).
- **Ingestion is automatic, not LLM-driven.** After each tool call that produces a `Turn`, a
  deterministic `World.Ingest(turn)` updates the model: a 200 to a new path → an `Endpoint`; a
  `Set-Cookie`/JWT → an `Identity`; an `ssh_exec` success → a new `Host` + a `PivotEdge`; a
  `*_confirmed` indicator → an `Attempt{confirmed}`; a WAF 403 → `Attempt{blocked}`. The LLM never
  writes the model; it *reads* a compact rendering of it (`World.Digest()`), so the model can't
  hallucinate surface (§10).
- **Cross-host chaining** becomes first-class: `ssh_exec` / a source-disclosure that reveals a new host
  adds a `Host` + `PivotEdge`; the scope guard (`Requester.HostInScope`) still gates every request, so a
  pivot can only reach an authorized host — the model *surfaces* the pivot, the guard *authorizes* it.
- **The pentest ModeDeep driver** takes a `*WorldModel` in place of the bare `engMem`, so its
  cross-finding learning and the webagent's surface model are one substrate.

### 2.3 Persistence (optional, platform-gated)

The model is in-process by default (unchanged blast radius). A `WorldStore` seam
(`Save(engagementID, *WorldModel)` / `Load`) lets the platform persist it per engagement so a re-run or a
resumed engagement starts from what was learned — the durable half, gated like every other platform store
(nil → today's ephemeral behavior). No secret is persisted (Identity values are redacted to a fingerprint,
mirroring the `CapturedSession` rule that never writes a live session to `vulnerabilities.json`).

## 3. Phases (incremental — each a tested, shippable unit)

1. **P1 — the model + deterministic ingest (host-side, no behavior change). ✅ BUILT.**
   `worldmodel.go`: `BuildWorldModel(History, Findings)` (pure) + `Digest()`. Pure + fully unit-tested
   (synthetic Turns → assert the model). Grounding test: empty evidence → empty model. **Design note:**
   the model is a *pure derivation* over the existing `History`/`Findings` rather than a mutable
   `Context.World` written per-tool — this avoided touching all ~21 tool call-sites (no behavior change,
   no churn) and keeps grounding trivially provable (the model *is* a function of the evidence).
2. **P2 — surface the digest to the LLM. ✅ BUILT.** `list_routes` now returns `Digest()` (endpoints +
   untested params + tested/blocked classes + auth + sessions + hosts) instead of a flat URL list, with
   unprobed routes listed as a to-do surface. Long-horizon coherence is measurable on the XBOW bench.
3. **P3 — cross-host chaining. ✅ BUILT.** An `ssh_exec` turn adds the SSH `Host` + a `PivotEdge` from the
   web host (creds discovered over HTTP → leaked-cred pivot) — the XBEN-042 chain, durable + in the
   digest. Source-disclosure pivots need no special parsing: reaching the new host ingests it like any
   evidence. The scope guard still authorizes every request (the model surfaces, the guard authorizes).
4. **P4 — unify pentest `engMem`. ⛔ REVISED (superseded by implementation reality).** The original plan
   assumed one shared memory. In practice the webagent world-model is derived from **HTTP Turns**, while
   the pentest ModeDeep `engMem` is **demo-predicate**-level (failed `DemoSpec` predicates across
   findings) — genuinely different granularities. The pentest driver has no `Turn` stream to build a
   world-model from, so a single shared model is the *wrong* abstraction; forcing it would only add a
   lossy bridge and risk regressing the tested driver. **Decision: the two memories stay separate by
   design.** The world-model is the webagent's substrate; `engMem` remains the pentest's finding-local
   spec-refinement hint. (Recorded honestly as a finding of the build, not a silent skip.)
5. **P5 — persistence (platform-gated). ✅ BUILT.** `worldstore.go`: `WorldStore` interface +
   `MemoryWorldStore` (JSON round-trip) + `WorldModel.Merge(prior)` (union semantics: a resumed
   engagement folds in the prior model — surface, held sessions, pivots, confirmed classes — deduped +
   idempotent). Secret discipline preserved: only the redacted model (identity fingerprints, never live
   tokens) is persisted. Platform wiring the store into the investigate loop is the gated half
   (nil → today's ephemeral behavior); the seam + serialization + merge ship and are tested.

## 4. Consequences

- **Positive:** long-horizon coherence (the XBOW edge), real cross-host chaining, no re-trying dead ends,
  one shared memory across the two offensive paths, optional cross-engagement learning.
- **Grounding preserved:** the model is derived-from-evidence, LLM-read-only — it *cannot* introduce a
  false positive; `record_finding` still gates on a real indicator + cited turn.
- **Cost/risk:** P1–P2 are contained (host-side Go, no sandbox rebuild, §12.6). P3 touches the scope
  guard's blast radius — the guard stays the authority; the model only *proposes where to look*. P5 adds
  a store seam but stays nil-by-default.
- **Non-goals:** this is not autonomy expansion — the RoE Guard, host allowlist, and containment
  circuit-breakers (the [agent-containment work](../../CLAUDE.md)) still gate every action. A richer
  world-model reasons better *within* the authorized envelope; it never widens it.

## 5. Status

P1–P3 + P5 are built + tested (host-side, no sandbox rebuild, §12.6). P4 is revised (the two offensive memories stay separate by design — different granularities). The remaining gated half is the platform wiring of the WorldStore into the investigate loop (nil → ephemeral, unchanged behavior).
