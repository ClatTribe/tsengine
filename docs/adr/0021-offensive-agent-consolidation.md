# ADR 0021 — One AI pentester: consolidating webagent into internal/pentest

**Status:** Proposed. Design for a strangler consolidation of the two offensive LLM agents
(`internal/webagent` + `internal/pentest`) into ONE productized AI pentester, keyed on the clean
boundary **detection is L1 (OSS + CVE-driven) — the agent EXPLOITS and REPORTS, it never re-detects**.
`internal/pentest` is the keeper; webagent's proven capabilities fold in as levels + primitives.
Nothing is built by this ADR; it sets the target shape so future capability work is wired ONCE.

## Context

tsengine has **two separate offensive LLM agents with no shared code** (verified: `internal/pentest`
does not import `internal/webagent`):

- **`internal/webagent`** — an open-ended, **target-first** agent loop (`Investigate(llm, cc, opts)`)
  over ~24 tools. Starts from a bare URL, discovers surface, hunts + exploits, can chain
  (`ssh_exec`, `dispatch_oss`→sqlmap/wpscan/hydra). Driven by `web-investigate`; `tsbench xbow` shells
  out to it. Actually exploits (flag capture) under authorization.
- **`internal/pentest`** — the **finding-first** productized pentest: an `Engagement` lifecycle + a
  `Driver` ladder (`PassiveDriver`→`ActiveDriver`→`OpenEndedDriverIterative`), the RoE Guard + consent +
  ownership gate, benign-by-construction verification, the VAPT report + scorecard + reattack loop.
  Takes findings the L1 scanners already produced and PROVES them safely.

Both honor the same §10 discipline — the model widens discovery, a deterministic predicate decides
truth — but implement it twice. **This is a TASK-split, which CLAUDE.md §2.2.1 rule 2 forbids**
("split by DOMAIN not by TASK; discover/verify/exploit within a domain are phases of ONE loop"). The
domain is web/API offense; "find-and-exploit" (webagent) and "verify-and-report" (pentest) are two
phases of ONE pentest we happened to build as two programs. pentest has the *packaging* of a pentest;
webagent has the *pentesting*. Neither alone is the product.

**The divergence already cost a measurable capability:** ADR 0019's exploit-intel sidecar was wired into
pentest but not webagent, so `tsbench xbow` (which drives webagent) cannot measure the product's newest
offensive capability. Every new capability must be wired twice and in practice gets wired once.

### The mislabel this ADR corrects

An earlier framing called webagent's per-class tools (jwt/race/upload/nosqli/tamper/graphql) "in-house
detection" and asked whether OSS + CVE-driven exploitation makes them redundant. Reading the code
settles it: these are **exploitation grounding, not detection** — jwt is "crack + FORGE", race is "the
FP-free PROOF of a limit-bypass", upload is "so the agent can reliably EXPLOIT an arbitrary-file-upload",
tamper "flips a value the server shouldn't trust and gets privileged access". They do not FIND a vuln;
they PROVE a suspected one by exploiting it, then a deterministic predicate disposes (§10). That is the
agent's legitimate job, not a scanner's. The boundary below makes this precise.

## Decision

**Build ONE AI pentester in `internal/pentest`, on a hard detect-vs-exploit boundary, delivering four
customer requirements.** webagent stops being a second brain; its proven capabilities become levels and
predicate kinds of the one pentest.

### The load-bearing boundary — detect vs exploit

- **DETECTION is L1's job and stays OSS + CVE/threat-driven (§13).** nuclei / sqlmap / semgrep / grype
  + `threatinformed.Plan` (CVE-targeted, capped) + the ADR-0019 exploit-intel feed decide *what might be
  wrong*. The agent NEVER carries an in-house detector, and any webagent tool that merely re-finds what
  OSS/nuclei already grounds is DROPPED (reached instead via `dispatch_oss`).
- **EXPLOITATION is the agent's job.** The agent takes what L1 surfaced (or what discovery seeded) and
  PROVES it by exploiting it, disposed by a deterministic predicate. This is why a customer buys a
  *pentest* over a *scan*.
- **The §13-sanctioned exception, kept deliberately:** the **business-logic authz classes** — BOLA/IDOR
  (`bola.go`), self-privesc/mass-assignment (`privesc.go`), session-state IDOR (`session_idor.go`),
  client-field tampering (`tamper.go`), limit-bypass race (`race.go`) — carry their OWN grounding
  because **no OSS scanner and no CVE feed can ground them** (their headers say so; §13 names authz
  business logic as the explicit no-OSS exception). These are NOT in-house detectors — they are the
  differential/parallel-request EXPLOITATION primitives an authz proof requires. They are kept, and this
  ADR records *why*, so a future reader does not mistake them for a banned in-house detector and delete
  them.

### The four customer requirements, as one pentest

| # | Requirement | How it's built | Reuses |
|---|---|---|---|
| 1 | **Bounded exploitation using CVE + OSS scanner** | detection stays L1 (OSS + `threatinformed.Plan`, capped) + exploit-intel (ADR 0019); the agent exploits what they surface, never re-detects | existing L1, `dispatch_oss`, ADR-0019 feed |
| 2 | **Verify + produce reports** | the Verify/Prove/Deep drivers + VAPT + scorecard + reattack — the outcome layer, unchanged | all of pentest today |
| 3 | **Discovery IF the customer asks, before exploitation** | an OPT-IN pre-phase that runs the EXISTING L1 §5.1 recon→fanout (katana crawl → `CollectSurface`) to seed the engagement, then exploits. Not a second agent — a phase flag | `internal/asset/web` recon (already built) |
| 4 | **Pentest capabilities (kill-chain, lateral movement, business-logic exploitation)** | `ssh_exec`/pivot as GENERIC RoE-gated `Attempt`s carrying cross-attempt state (a cred captured on host A feeds an attempt on host B); the §13-exception authz primitives as predicate kinds | webagent's proven probes |

### The level ladder = customer outcomes (the "various levels" made explicit)

All four levels flow through the SAME runner → RoE gate → scorecard → VAPT. A customer buys an OUTCOME
(a VAPT); the LEVEL is how deep the engine went to produce it.

| Level | Driver | Customer outcome | Gate |
|---|---|---|---|
| **L0 Verify** | `PassiveDriver` (today) | confirmed-vs-unconfirmed in the report | none |
| **L1 Prove** | `ActiveDriver` (today) | exploitation-proven findings in the VAPT | active-authorized |
| **L2 Deep** | `OpenEndedDriverIterative` (today) + webagent class primitives as predicate kinds | proves the HARD classes playbooks miss (jwt/race/upload/nosqli/authz) | active-authorized |
| **L3 Hunt** | webagent's loop, absorbed as a target-first Driver + optional discovery pre-phase | NET-NEW findings + kill chains — the real pentest | active-authorized + ownership-verified |

### Safety is a POLICY axis, never a fork

The reason two brains exist is real and MUST survive: webagent may actually exploit because it runs under
authorization; pentest must stay benign for customers. Consolidation does NOT collapse these into one
permissive agent. The RoE gate (`RulesOfEngagement.Check`: scope → budget → absolute destructive ban →
active-exploitation-requires-explicit-consent) is the mandatory disposition gate for EVERY attempt at
every level — pentest's existing inversion of control (agent proposes an `Attempt`, runner disposes via
`Check` before any side effect). "Actually exploit" (real sqlmap extraction, `ssh_exec`, flag capture) is
reachable ONLY under an RoE that authorizes active mode + ownership. The benchmark harness supplies a
fully-authorized RoE; the customer product supplies a consented, benign-capped one. Same core, different
policy — never a second codebase to keep the envelopes apart.

## Migration (strangler — feeds first, loop last; keeper = internal/pentest)

Both agents are mature and benchmark-load-bearing (`tsbench xbow`, the pentest scorecard), so we converge
from the edges inward and never merge the loops first. Each step ships behind tests and leaves both
benchmarks green.

1. **Shared context feed (the cheap fix that motivated ADR 0021).** The ADR-0019
   `ExploitIntelForFinding` seam (+ threat-intel + engagement memory) reaches webagent's PROPOSE step;
   add the with/without-exploit-intel ablation toggle to `tsbench xbow`. **Outcome: the ADR-0019 number
   becomes measurable and both paths share the feed — zero loop surgery.** This alone retires the defect.
2. **Probes → predicate kinds.** Register the FP-free deterministic disposers (bola/privesc/session_idor/
   tamper/race/nosqli/jwt/upload) as `PredicateKind`s in `pentest/primitives.go`'s library, so L2's
   `LLMSpec` can NAME them. Low risk — they are pure functions. Drop any webagent tool OSS/nuclei already
   grounds (reach it via `dispatch_oss`).
3. **Exploitation tools → L3 Attempts.** `ssh_exec`, `dispatch_oss`, the pivot logic become `Attempt`s
   the L3 driver emits, gated by `RoE.Check`; the `Engagement` carries cross-attempt state so kill-chains
   are generic, not per-finding.
4. **Discovery pre-phase.** Wire the existing L1 §5.1 recon as an opt-in engagement phase that seeds
   target-first runs.
5. **Loop last.** With feeds, predicates, tools, and policy shared, webagent's ReAct loop becomes the L3
   Hunt `Driver`; `web-investigate` becomes a thin `cmd` calling pentest at L3 with a fully-authorized
   RoE. Dedupe browser + OOB into pentest's `browser.go`/`interactor.go`. Only now is a loop merged.

The ADR is done when step 5 lands or is explicitly deferred with steps 1–4 in place (which already
removes the wire-twice tax and closes the ADR-0019 measurement gap).

## Why not X

- **Leave two agents.** The wire-twice tax is proven (ADR 0019 wired once), the benchmark cannot measure
  the product's capability, and §2.2.1 rule 2 names the task-split as the anti-pattern.
- **Rebuild the exploit classes as OSS scanners.** They are EXPLOITATION, not detection — and the authz
  subset is the §13-sanctioned no-OSS exception (no scanner can ground business-logic authz). Detection
  already IS OSS + CVE-driven upstream; that boundary is kept, not moved.
- **Keep discovery as a separate agent.** L1 §5.1 recon already does deterministic discovery; making it
  an opt-in pentest phase reuses it instead of maintaining a second hunting brain.
- **Make pentest call webagent (or vice-versa).** Wrong envelope: pentest must stay benign; webagent
  actually exploits. Nesting imports the wider envelope into the narrower product. Correct relationship:
  ONE core whose exploitation reach is an RoE policy, not a package boundary.
- **Big-bang rewrite.** Both are benchmark-load-bearing; a simultaneous merge risks regressing
  `tsbench xbow` verified_rate AND the pentest scorecard with no incremental proof. The strangler keeps
  both green.

## Consequences / follow-on

- **One number measures the product.** `tsbench xbow` (L3, fully-authorized RoE) and the pentest
  scorecard become configurations of one core; an offensive capability lands once and both see it.
- **Every context feed reaches every level** — exploit-intel, threat-intel, engagement memory, and any
  future feed (a model-tuning spike's richer context) — wired once.
- **Invariants preserved:** the ≤12-tool cap (§2.6) is unchanged (one specialist, not more tools); the
  RoE Guard / destructive ban / consent gate become the single disposition path; §10 propose/dispose
  holds because the predicate library is the union of two existing FP-free sets — no new FP surface.
- **Naming (§2.2.1).** The unified core is the AI AppSec / offensive specialist's web/API engine;
  pentest's engagement lifecycle + VAPT remain the product packaging over it. No product rename.
- **Not in scope:** the cloud offensive path (`internal/cloudagent`/`cloudengine`) and the code path
  (`internal/codeagent`) are separate DOMAINS with their own substrates and are correctly split — this
  ADR consolidates only the two web/API offensive brains.

## Grounding (§10)

The consolidation moves no truth-decision into the model. Detection stays OSS + CVE-driven at L1;
exploitation disposition remains a deterministic predicate over the live response (`DemoFromSpec`); the
predicate library is the union of two already-grounded sets; the safety envelope becomes one RoE policy
path rather than an implicit property of which package you called. A wrong context feed (ADR 0019) still
only widens what the agent TRIES, never what it marks true — now guaranteed on every level, not one.
