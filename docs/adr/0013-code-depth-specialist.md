# ADR 0013 — Code-depth specialist for the AI Security Engineer (G1)

**Status:** Proposed (design only — not built). The large, multi-session gap from the AI Security
Engineer (code/cloud defense) audit; this ADR fixes the shape so a future session builds it against a
settled design rather than improvising.

## Context

The AI Security Engineer (defense) is two agents:

- **The L2 Lead generalist** (`internal/l2`) — reasons over the whole `crossdetect` estate (unified issues
  + cross-surface attack paths), auto-invoked after a scan change. It reads code findings as unified-issue
  *digests*.
- **The cloud specialist** (`internal/cloudagent`) — an 11-tool ReAct agent over the `cloudgraph` IAM
  graph (`resolve_access`, `find_paths`, `blast_radius`, `detect_privesc`, …). The generalist delegates
  cloud depth to it via the `investigate_cloud` tool.

**The asymmetry (G1):** cloud has a depth specialist; **code does not.** The generalist can read a
SAST/SCA/secret finding's digest but cannot *open the source* to confirm/refute it, trace taint beyond
what `govulncheck` gives deterministically, or compute a leaked secret's blast radius across the repo. So
the "defends **code**" half of the product is currently shallow triage, not engineering — the largest
structural gap in the defense persona.

The product framework (docs/product-framework.md §2) already names the target: "a generalist over
crossdetect that **delegates cloud-depth to the cloud specialist**." G1 is the missing symmetric half:
delegate **code-depth to a code specialist**.

## Decision (proposed)

Build `internal/codeagent` — the code-surface twin of `cloudagent`. Same shape, same invariants:

- **A ReAct agent over a CODE graph, not the IAM graph.** Where cloudagent reasons over `cloudgraph`,
  codeagent reasons over the repository: the file tree, the dependency graph (lockfile → package →
  transitive), the call graph / taint where available, and the secret inventory.
- **Tools are the agent's hands, not its brain (§2.7).** A ≤~11 tool catalog, e.g.:
  - `read_file(path, range)` — read source to confirm/refute a finding (the anti-hallucination anchor:
    the agent cites real lines, §10).
  - `grep_repo(pattern)` — find usages / other occurrences of a secret or sink.
  - `dependency_paths(package)` — is the vulnerable dependency actually reachable (import path → call
    site), the SCA-reachability question, backed by `govulncheck`/import-graph, not model recollection.
  - `secret_blast_radius(secret)` — where else does this credential appear / what does it unlock
    (grep + the cross-surface bridge to cloud, reusing `crossdetect`).
  - `taint_trace(finding)` — re-fire CodeQL/semgrep-taint on the flagged sink (via the existing
    escalation path, §5.3), returning the source→sink path.
  - `record_issue` / `propose_fix` / `finish` — same commit/terminate discipline as cloudagent.
- **Grounding (§10) is non-negotiable:** every recorded issue cites a real file:line / a real reachable
  path from a tool result. The model reasons; the tools answer precisely and refuse ungrounded claims —
  exactly cloudagent's `record_issue` REJECTS-an-ungrounded-path rule, ported to code.
- **Delegation, not replacement.** The L2 Lead gets an `investigate_code` tool (conditionally added, like
  `investigate_cloud`, to keep the ≤12 cap) that runs codeagent over the repo asset. The generalist stays
  the altitude-split generalist; codeagent is the depth it delegates to for a code finding.
- **Findings enriched + risk-seeded like the cloud path.** codeagent output runs through `enrichFindings`
  (§11, the G3 pattern) and feeds `seedRisks` (the Task-2 auto-review pattern), so a code investigation is
  first-class and reaches the vCISO desk the same way a cloud investigation does.

## Execution model

Host-side, like cloudagent (§12.6) — it needs repo file access + the existing sandbox OSS escalation
(CodeQL/semgrep) via `dispatch_l2_probe`, not a new sandbox image. The repo tree is the surface (single-
stage, like the repository asset). It reasons over a **pinned repo snapshot** (a checkout / the connector's
tree), the code twin of the pinned `cloudsnap` cloud snapshot (#726), so a delegated run has stored state.

## Why not now

Genuinely multi-session: a repo graph model (import/call graph + taint adapter), ~5 grounded tools each
with its own backing (read/grep are easy; `dependency_paths`/`taint_trace` wrap existing OSS but need
careful reachability grounding), the `investigate_code` catalog wiring, and the codeagent↔cloudagent
bridge for a secret that spans both surfaces. Shipping it half-grounded would violate §10, so it is scoped
as its own campaign rather than rushed.

## How it will be measured

`tsbench defense` (this session's benchmark, ADR-adjacent) already scores code+cloud estates. codeagent's
value is the **agent-mode lift over the substrate baseline** on the code scenarios (a leaked secret whose
blast radius the substrate can't compute, a SCA finding the substrate can't prove reachable). The
substrate-vs-agent ablation is exactly the number that will justify building it — and tells us if it's
earning its tokens.

## Consequences

- Closes the last structural gap in the two-persona defense model (code gets a depth specialist,
  symmetric with cloud).
- Reuses every existing invariant (grounding, ≤12 cap, enrich-then-store, seed-risks, host-side execution)
  — no new architectural surface, just the symmetric package.
- Until built, the L2 Lead's code reasoning stays digest-level triage; this ADR is the honest record that
  it is a *known* gap with a settled design, not an oversight.
