# ADR 0015 — Multi-language SCA reachability

**Status:** Accepted (built). Go + JavaScript/TypeScript + Python reachability ship at two honest
fidelity tiers; the `call_graph`-tier upgrade per non-Go language is a documented sandbox-tool follow-on.

## Context

SCA reachability triage answers the question that turns dependency-scanner noise into a real finding:
*"a scanner says this dependency has a vulnerable function — does THIS codebase actually call it, from an
application entrypoint?"* It is the difference between "you have 300 dependency CVEs" and "3 of them are
reachable — fix these first." Reachability is the moat the commercial SCA vendors (Snyk, Endor,
Semgrep Supply Chain, Socket) keep closed.

`internal/reachability` had this — but **Go-only**. It builds a real call graph with the stdlib
`go/parser`, then a language-agnostic solver (`Analyze`/`TriageSCA`) reports whether an entrypoint has a
path to the vulnerable symbol. A JS or Python CVE got no reachability signal at all.

**There is no importable cross-language library to drop in.** We checked: CodeQL is the most capable
multi-language dataflow engine but its CLI license bars closed-source commercial use (a customer would
each need GitHub Advanced Security); Semgrep's reachability is the paid Supply Chain tier; OSV-Scanner is
an importable Go library but its call analysis is Go+Rust only. The mature per-language OSS call-graph
engines (Jelly for JS, PyCG for Python, WALA/Soot for Java) are each a separate runtime you shell out to,
not a Go import. So multi-language reachability requires our own extraction regardless.

## Decision

**The leverage: the solver and the graph model were already language-agnostic — only extraction is
per-language.** So this is an *extractor* change, not a solver change.

1. **`Extractor` interface** (`extractor.go`): `Lang()` / `Detect(root)` / `Extract(root) (*Graph, error)`.
   `GoExtractor` wraps the existing `go/parser` path **unchanged**. Adding a language is adding one
   `Extractor`; the solver (`Analyze`, `TriageSCA`) never changes.

2. **Two fidelity tiers, carried on every verdict (§10 honesty):**
   - `call_graph` — a resolved intra-repo call graph (function → function). A "reachable" verdict cites
     the real call path; "not reachable" means no static path was found. **Go** today.
   - `import_use` — import + call-site extraction *without* full type/name resolution. A "reachable"
     verdict still cites a real import of the vulnerable package + a call to its symbol from an
     entrypoint-reachable function, but because cross-file dynamic dispatch isn't resolved, its "not
     reachable" is a **softer negative** than `call_graph`. **JS/TS + Python** today.

   The `Verdict` records `lang` + `fidelity`, so a consumer never treats a coarse-tier negative as a
   precise one. This is the core discipline: we never over-claim "safe."

3. **Pure-Go, host-side extractors for JS/TS + Python** (`js.go`, `python.go`). No Node/Python runtime,
   no CGo — the host binary keeps its static-binary property. A comment/string-blanking lexer (`lex.go`)
   keeps regex/brace matches out of literals (a `require()` in a comment or an `import` in a string never
   creates an edge); a declaration-header guard stops `function foo(` / `def foo(` counting as a call;
   the module top-level is its own entrypoint (it runs on import).

4. **Polyglot dispatch** (`dispatch.go`): `BuildGraphs` runs every extractor whose `Detect` fires;
   `TriageMulti` routes each SCA finding to the graph for **its** ecosystem (npm→JS, pip→Python, go→Go).
   An ecosystem-less finding in a single-language repo routes to the sole graph (back-compat); a finding
   whose ecosystem has no built graph (e.g. a Maven CVE) is reported `unknown_ecosystem` — **never
   silently safe** (§10). It still gates on severity via `gate.FromReachability` (`Reachable=false`),
   so it is honestly not-triaged rather than dropped.

5. **Wired end to end through the product path:** the importers carry the scanner's ecosystem onto the
   `SCAFinding` (Dependabot's `package.ecosystem`, Snyk's doc-wide `packageManager`); `tsengine
   reachability` and `tsengine gate --sca` build one graph per detected language and route via
   `TriageMulti`. A new `--lang` selects the graph for single-package queries.

## Why not X

- **Wrap CodeQL / Semgrep-SupplyChain** — license / paywall bar embedding on customers' closed code.
- **Import OSV-Scanner and get everything free** — its call analysis is Go+Rust; adopting it is a good
  future move for the Go/Rust spine + SCA plumbing, but it does not solve JS/Python reachability.
- **Hand-roll full call graphs for JS/Python host-side** — sound cross-function graphs need type
  resolution (interface/dynamic dispatch), which is language-specific and heavy. We ship the honest
  `import_use` tier now and leave `call_graph` fidelity to the OSS engines below.

## Consequences / follow-on

- **`call_graph`-fidelity upgrade per non-Go language** = wrap the mature OSS engines (**Jelly** for JS,
  **PyCG** for Python, **WALA/Soot** for Java) as **sandbox tools** (§12/§13 — heavy language runtimes
  belong in the sandbox, not the pure-Go host), normalizing their output into the same `Graph`. The
  extractor slots straight into the `Extractor` interface; only `Extract` moves to a sandbox dispatch.
  This is a sandbox-image change (gated), not a solver change.
- **Java** (and Ruby/PHP) join by adding one `Extractor` each — `import_use` host-side first, then the
  `call_graph` sandbox upgrade.
- **L2 integration**: the code-depth specialist (ADR 0013 / `internal/codeagent`) can call reachability
  as a grounded tool (`reachability_check`) so its exploitability claims are backed by the solver, not
  the model's hand-tracing — with L2's unique value being the dynamic-dispatch edges the static graph
  gives up on, always re-grounded (never asserted).
- **Platform SCA path**: today reachability is a CLI + CI-gate capability; wiring `TriageMulti` into the
  continuous platform scan (so dashboard SCA findings carry a reachability badge) is a natural next step.

## Grounding (§10)

Every "reachable" verdict cites a real import + call path in real source; every extractor's fidelity is
stamped so a negative is trusted proportionally; an unroutable ecosystem is flagged, never assumed safe.
The absence of a path lowers priority — it does not prove safety — exactly as the Go extractor always
promised.
