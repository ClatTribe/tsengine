# ADR 0016 — Dynamic tool selection for the L2 agents

**Status:** Accepted (library built). `internal/toolselect` ships the missing technique (task-based
retrieval) with a frontier-LLM refiner; wiring it into `webagent` / `cloudagent` / `internal/l2` is the
documented follow-on, sequenced after the concurrent agent-harness work to avoid a merge collision.

## Context

The two flagship L2 products are LLM agents over a tool catalog:

- **AI Offensive Agent** (`internal/webagent`) — **23 tools, all static, all in every prompt**:
  `list_routes`, `send_request`, `discover_content`, `graphql_introspect`, `browser_render`,
  `record_finding`, `confirm_exploit`, `oob_url`, `oob_check`, `tamper_probe`, `sqli_bool_probe`,
  `race_probe`, `session_idor_probe`, `bola_probe`, `nosqli_probe`, `privesc_probe`, `jwt_crack`,
  `crack_hash`, `try_default_creds`, `dispatch_oss` (a gateway to sqlmap/wpscan/nuclei/ffuf/hydra/
  padbuster), `ssh_exec`, `note_defense`, `finish`.
- **AI Security Engineer** (`internal/cloudagent`) — **11 tools, all static**: `list_resources`,
  `get_resource`, `resolve_access`, `find_paths`, `blast_radius`, `enumerate_attack_paths`,
  `detect_privesc`, `get_findings`, `record_issue`, `propose_fix`, `finish`.

**Invariant L2-CAP** (CLAUDE.md §2.6) says the LLM-visible catalog must stay ≤12, because tool-use
accuracy degrades steeply past ~a dozen tools. The offensive agent presents **23** every turn — ~2× the
cap — and neither flagship agent uses the phase-scoped harness that already exists in `internal/l2`.

The goal: **a large capability library, a small ACTIVE subset at a time, chosen by the task at hand.**

## The three standard techniques (and what tsengine already had)

1. **Phase-scoped catalog** — expose only the tools relevant to the current workflow phase. *Present* in
   `internal/l2` (`phase.go` `allowedInPhase`, OODA `triage→investigate→chain→report`).
2. **Dispatch gateway** — one LLM slot fronts a whole tool family (`tool=...`). *Present* as
   `dispatch_l2_probe` (l2) and `dispatch_oss` (webagent).
3. **Task-based retrieval** — rank the library against the current subgoal and surface only the top-k.
   **Missing.** This ADR adds it.

A fourth, hierarchical **sub-agent delegation**, also exists (`investigate_cloud` → `cloudagent`) and is
complementary; not changed here.

## Decision

Add `internal/toolselect` — a reusable, dependency-free selector — and adopt it in the agents to shape
the prompt's tool section each turn. Combine all three techniques rather than pick one:

```
CORE (always visible)      : send_request · record_finding · dispatch(...) · finish   (AlwaysOn tools)
  + PHASE-SCOPED eligibility: recon | exploit | prove   (Tool.Phases + Query.Phase/PhaseOrder)
  + TASK-RANKED specialists : top-k by relevance to Query.Task, capped at MaxActive
  + optional LLM REFINER    : frontier model proposes the final subset; framework disposes
```

### `internal/toolselect` API (built)

- `NewCatalog([]Tool{Name, Description, Tags, Phases, AlwaysOn})` — index once.
- `Select(Query{Task, Phase, PhaseOrder, MaxActive}) Selection` — deterministic BM25-style ranking over
  name (×3) / tags (×3) / description, with a small security synonym map (authz/idor→bola,
  privilege→privesc, …). Always-on CORE is always included; phase-ineligible tools are filtered; an
  irrelevant task surfaces only CORE (no slot-padding); result capped at `MaxActive` (default 12).
- `SelectLLM(ctx, Query, Generator) (Selection, fallbackUsed)` — the semantic layer. The model
  **proposes** from the full eligible candidate list; the framework **disposes**: closed-set (a
  hallucinated name is dropped — §10), cap (CORE prepended + truncated to `MaxActive`), and fallback to
  `Select` on any model error / unparseable answer. `Generator` is a minimal `Generate(ctx, prompt)
  (string, error)` seam — dependency inversion, so `toolselect` imports no LLM package (no import cycle
  when `l2`/`webagent` later import `toolselect`).

### Grounding (§10)

`toolselect` only ranks/filters the caller's **real registered tools** — it never invents one, and the
LLM refiner's picks are validated against the closed candidate set. Tool *selection* is heuristic (which
is fine — it only changes what the LLM sees); tool *execution* and finding *grounding* are unchanged. A
wrong selection can only cost a turn (the agent asks for a tool that wasn't surfaced and the next turn
re-selects), never a false finding.

## Integration recipe (the follow-on wiring)

Each agent already builds its prompt from a static `tools()` slice. The change is mechanical:

1. Build a `*toolselect.Catalog` once from the existing `tools()` (map each `toolDef` → `toolselect.Tool`;
   set `AlwaysOn` on the CORE set; add `Tags`/`Phases`). The rich existing help strings become
   `Description` verbatim.
2. Each turn, compute the agent's current `Task` (its latest subgoal / hypothesis — already in context)
   and `Phase`, call `Select`/`SelectLLM`, and render only `Selection.Tools` in the prompt's `TOOLS:`
   section (instead of all of `tools()`). Dispatch/execution is unchanged — a tool the model names that
   wasn't surfaced this turn simply isn't offered; next turn's selection can surface it.
3. For `SelectLLM`, adapt the agent's existing `l2.Client` to `toolselect.Generator` with a thin wrapper
   (`Generate(ctx, prompt)` → `client.Generate(ctx, "", []Message{{Role:"user", Content:prompt}}, nil)`,
   return the text). This adapter lives in a neutral package (importing both `l2` and `toolselect`), so
   neither core package depends on the other.

**Sequencing:** the wiring edits `webagent`/`cloudagent`/`l2`, which the concurrent agent-harness branch
also edits. To avoid a merge collision the library shipped standalone first (this ADR + the tested
package); the agent edits land once that branch is merged.

## Validation (end-to-end, including a frontier LLM)

Tested against **both real catalogs as data**:

- Offensive (23 tools): blind-SQLi → `sqli_bool_probe` (not jwt/ssh); JWT → `jwt_crack`; IDOR →
  `bola_probe`; SSH-creds → `ssh_exec`; XSS → `browser_render`; cap / always-on / phase / determinism.
- Cloud (11 tools): chain-phase privesc task → `detect_privesc` + `blast_radius`, `propose_fix` hidden
  until the remediate phase.
- **Frontier LLM via the claude-as-proxy pattern**: for tasks with *zero* lexical overlap with the right
  tool — "apply the same one-time discount code more than once if sent together" (→ `race_probe`), "a
  build robot can rewrite its own permissions" (→ `detect_privesc`) — BM25 misses but the frontier model
  picks correctly, and the disposal (closed-set + cap + fallback) holds. This is the semantic value the
  refiner adds over lexical ranking; goldens were audited against the real generated prompt.

## Consequences

- The offensive agent's visible catalog drops from 23 to ~7–9 per turn, honoring L2-CAP dynamically
  instead of by hand-trimming; the cloud engineer gains phase-scoping.
- New tools can be added to the library without worrying about the ≤12 cap — retrieval keeps the active
  set small automatically.
- Cost: one selection step per turn (BM25 is microseconds; `SelectLLM` adds one cheap LLM call, or none
  if the agent uses the deterministic `Select`). Selection thrash is bounded by caching the loadout per
  subgoal (recommended in the wiring).

## Alternatives considered

- **Embeddings/vector retrieval** — overkill for a few dozen tools; BM25 + curated tags matches or beats
  it at this scale with zero infra and full determinism. The `SelectLLM` refiner covers the semantic tail.
- **Hand-authored per-phase catalogs only** (what `l2` does today) — doesn't scale as the library grows
  and can't adapt within a phase to the specific subgoal. Retrieval composes with it, not replaces it.
