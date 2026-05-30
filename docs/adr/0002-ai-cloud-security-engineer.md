# ADR 0002 — AI Cloud Security Engineer (L2 discoverer over a pinned inventory snapshot)

- **Status:** Proposed
- **Date:** 2026-05-30
- **Builds on:** ADR 0001 (L2 as a bounded discoverer)
- **Affects:** CLAUDE.md §6 (dashboard contract), §8, §10 (reproducibility), the cloud_account asset, the L2 layer

## Context

The `cloud_account` asset today is **rule-based detection only**: prowler +
scoutsuite emit CIS/known-misconfig findings (the L1 floor). That answers *"does
check X fail?"* with high recall on the catalog — but it is blind to anything
nobody wrote a rule for, and it dumps N isolated findings with no sense of which
few actually chain into a breach.

We want a second, complementary lens: an **AI Cloud Security Engineer** that
reasons over the *raw cloud state* — the full inventory and its relationships —
to surface **attack-path chains** (public ALB → EC2 role → assume → PII bucket),
**toxic combinations**, and **novel/contextual risk** that rules miss. Both
lenses ship, side by side: *"the tools flagged 24 CIS failures; the engineer
says 3 of them chain into a path from the internet to your PII bucket, plus 2
things no rule caught."*

Two earlier discussions shape this ADR:

1. **CloudQuery is the *eyes*, not the engineer** (the §13 line). prowler is a
   detector (ships the checks). CloudQuery / Cartography is an inventory/ELT
   engine that produces a queryable, relational/graph model of the account — it
   emits *facts*, not findings. The engineer is the LLM agent reasoning over
   those facts; the inventory engine is the substrate, wired registry-tier, not
   as a CSPM detector we author rules into.

2. **Reproducibility was misunderstood.** It does **not** mean "the detection
   process is deterministic." It means: *given a captured config + environment,
   the issue can be replicated.* It is a property of the **finding** (re-confirmable
   against the same state), not of the **process** (how it was discovered). This
   reframes everything below — see §"Reproducibility" and the companion §10 note.

3. **Real impact requires live validation — config-possible ≠ exploitable.** A
   static snapshot tells you what's *theoretically* exposed; only the live
   environment tells you what's *actually* exploitable, and the gap between them
   is where real impact lives ("SG open to 0.0.0.0/0" vs. *is anything
   listening and reachable through the full live path*; "role R trusts P" vs.
   *does the assume actually succeed at runtime*; runtime-only classes like SSRF
   aren't in config at all). A snapshot-only engine just rebuilds prowler with
   an LLM and inherits the CSPM disease (200 "criticals", mostly inert). The
   snapshot is therefore the **hypothesis layer**, not the conclusion — the
   engineer's value is *validating which hypotheses have real impact*, which
   means touching reality. The safety model below makes that validation
   **graduated and overwhelmingly read-only**, not forbidden.

## Decision

Build the AI Cloud Security Engineer as an **L2 bounded discoverer that reasons
over a pinned inventory snapshot**, ships a **dual-view** result, and is **safe
by construction** against the customer's account.

### Architecture

```
L1   prowler + scoutsuite ───────────────►  findings_raw   "Detection tools say"
        (deterministic recall floor — unchanged)

L3   inventory snapshot (CloudQuery / Cartography), read-only, pinned + hashed
        = the captured config (the hypothesis layer + reproducibility base)
                          │
L2   AI Cloud Engineer (LLM agent) ◄────────┘   hypothesize on the snapshot,
        then VALIDATE against live (graduated, read-only-first) to establish
        REAL IMPACT  ──►  ai_assessment  "AI engineer says"
```

- **L1 stays the floor.** prowler/scoutsuite are unchanged — reproducible,
  compliance-grade, the "tools say" column.
- **L3 snapshot is the hypothesis substrate.** One controlled, read-only sync
  builds a frozen, content-addressed graph. The agent forms attack-path
  hypotheses cheaply and comprehensively over this static data — but the
  snapshot is the *start*, not the end.
- **L2 engineer is the discoverer + validator.** It validates the handful of
  promising hypotheses against the live environment via the graduated ladder
  (below) to separate *possible* from *real impact*. Captured live observations
  become part of the evidence bundle. The snapshot makes this validation
  **surgical** (probe the 5 that matter, not blanket-scan 10,000) — which is
  the safety win, not isolation from live.
- **Dual-view dashboard.** `vulnerabilities.json` carries both `findings_raw`
  (detection) and a new `ai_assessment` block (engineer), each finding tagged
  with confidence + a replayable evidence bundle.

### Reproducibility (the corrected model)

A finding is reproducible iff **replaying its evidence against the pinned
snapshot re-confirms it** — no LLM in the loop. This makes AI-engineer findings
**first-class, attestable, audit-ready**, not second-class:

1. **Pin the environment snapshot.** The inventory graph at assessment time is
   content-addressed (`snapshot_hash`) — this *is* "given a config and an
   environment." (It replaces "pinned corpus" for cloud.)
2. **Every finding carries a deterministic evidence bundle** over that snapshot.
   *"role R trusts principal P"* is a fact in the config; *"path R → assume →
   S3-with-PII exists"* is a deterministic graph query. Replay → re-confirm,
   deterministically, regardless of how the LLM discovered it.

The evidence bundle does **double duty**: anti-hallucination guard **and** the
reproducibility artifact. The LLM's non-determinism affects *coverage stability*
(it may surface different subsets across runs) — a **recall** property, not
reproducibility — handled by the deterministic floor (stable on the catalog) +
temperature-0 + multi-pass + deterministic evidence-validation. The signed
attestation covers `snapshot_hash + findings + evidence + the live-call log`.

### The tool catalog (≤12, §2.7 "hands not brain", snapshot-first)

Most tools are **local-snapshot reads (zero live blast radius)**; live contact
is concentrated in **one** parameterized `validate` tool that the agent calls
*surgically* on promising hypotheses and that enforces the ladder's per-rung
gate. Exactly **≤12 slots** (the §2.6 cap):

| # | Tool | What it does | Blast radius |
|---|---|---|---|
| 1 | `query_inventory(typed)` | Curated typed primitives over the FROZEN snapshot (`list_resources`, `who_can_assume`, …) — never raw SQL, never live | **none** (local) |
| 2 | `resolve_permissions(principal)` | Effective IAM perms by simulating captured policies (cloudsplaining / policy_sentry) | **none** (local) |
| 3 | `attack_path(from,to)` | Graph reachability over the snapshot (PMapper / Cartography) | **none** (local) |
| 4 | `get_resource_config(arn)` | Full config of one resource from the snapshot (policy/SG/env) | **none** (local) |
| 5 | `get_data_classification(resource)` | **Metadata only** — Macie verdict, tags, naming. NEVER reads object contents | **none** (local) |
| 6 | `get_detector_findings()` | prowler/scoutsuite output, to corroborate / chain / FP-reduce | **none** (local) |
| 7 | `query_threat_intel(cve)` | KEV/EPSS for CVEs in exposed workloads (existing L2 tool) | external, read |
| 8 | `validate(hypothesis, rung)` | The single live-contact tool. `rung 2` live read-only state; `rung 3` passive reachability (no traffic); `rung 4` benign probe (no access used, nothing mutated); `rung 5` full exploitation → **refuses and queues for human approval**. Enforces budget/throttle; records observations into the evidence bundle | rung-scoped (≤ low for 2–4; 5 is human-gated) |
| 9–11 | `record_finding` / `record_hypothesis` / `finish_assessment` | Commit to the report (evidence + narrative + confidence) | local side-effect |

Snapshot collection itself is **not** an agent tool — it runs once in the L3
prepass, so the agent can't trigger arbitrary collection. Collapsing all
live-contact into the single gated `validate` tool keeps the catalog ≤12 *and*
gives one auditable chokepoint for every byte that touches the customer's
account.

## How the engineer must behave to keep the customer safe

Customer safety is a hard constraint, not a feature. An autonomous agent with
cloud access can cause outages, cost, false-alarm incident response, privilege
escalation, or the very data exposure it's meant to prevent. The behavior model:

1. **Read-only by construction — defense in depth.** (a) Creds are a scoped
   read-only role (`SecurityAudit`/`ViewOnlyAccess` or a least-priv read role),
   assumed via STS with a *session policy* that further restricts and is the hard
   cap even if the role is broader; (b) every tool is on a read-only allowlist;
   (c) a deny-guard rejects any non-`Get`/`List`/`Describe` API call. If the
   LLM "decides" to mutate, it physically cannot.

2. **Hypothesize on the snapshot; validate surgically against live.** Safety is
   *not* "never touch live" — that would forfeit real-impact detection
   (config-possible ≠ exploitable). It is *minimize and graduate* live contact.
   The snapshot lets the agent form hypotheses cheaply and comprehensively, then
   validate only the *handful that matter* against live — surgical, not a
   blanket scan of the whole account. That targeting is the safety win.

3. **Graduated validation ladder — "live" ≠ "exploit".** Real impact is
   established mostly on the *safe* rungs; only the last needs a human:

   | Rung | Establishes | Risk | Gate |
   |---|---|---|---|
   | 1 · static (snapshot) | what's *possible* per config | none | auto |
   | 2 · live read-only state | actual listening services, current session perms (`SimulatePrincipalPolicy`/`GetCallerIdentity`), drift | very low | auto |
   | 3 · passive reachability | path *actually* reachable vs full live network — **no traffic** (Access/Reachability Analyzer) | very low | auto |
   | 4 · benign active probe | "knock on the door": port accepts? endpoint 200 vs 403? assume-role trust *actually* works? — **no access used, no data read, nothing mutated** | low | budget + throttle |
   | 5 · full exploitation | walk the path end-to-end, prove the breach | high | **human-gated, benign-control, never destructive/exfiltrating** |

   `real_impact = config_possible ∧ live_reachable ∧ (sensitive_data ∨
   meaningful_privilege)` — the `live_reachable` term means rungs 2–4 are
   mandatory, not optional. Rung 5 is reachable only by `validate(_, rung=5)`,
   which refuses to execute and queues for explicit human authorization (the §11
   post_emit_verifier pattern). Live-probe observations are recorded into the
   evidence bundle, so the finding stays reproducible against the captured state.

4. **Never read the data — only metadata.** To judge "is this sensitive," the
   agent reads classification *signals* (Macie verdict, tags, naming), **never
   object contents**. The customer's PII/secrets never enter the LLM context,
   logs, or the model provider. Privacy and safety in one rule.

5. **Bounded, throttled, cost-capped, alarm-aware.** Live analysis calls are
   throttled and capped by an escalation-style budget; the controlled sync
   respects API rate limits; any live activity is announced/schedulable so it
   doesn't trip the customer's incident response as a real attack.

6. **Everything logged, attributable, replayable.** Every query and every live
   call is logged with the hypothesis it served — this is simultaneously the
   evidence bundle (reproducibility) and the safety audit trail. Nothing the
   agent does is invisible; the customer can see exactly what was touched.

7. **Bounded autonomy / fail-closed.** The agent autonomously *reads* and
   *reasons*; anything with a side effect beyond the snapshot is budgeted, and
   active exploitation is human-gated. If a tool is unsure an action is
   read-only, it refuses. If creds can't be scoped read-only, the assessment
   does not run. Default-deny on mutation.

8. **Tenant isolation.** One ephemeral sandbox per assessment; tenant-scoped
   snapshot; LLM context wiped per assessment; creds short-lived and never on
   disk (existing tsengine constraints).

## Consequences

**Positive**
- AI-engineer findings are evidence-backed, attestable, **compliance-grade** —
  the corrected reproducibility model removes the "non-deterministic ⇒
  second-class" objection.
- Detects **real impact**, not just config-possible issues — the validation
  ladder separates exploitable from theoretical, which is the whole point of an
  *engineer* vs a config linter.
- Minimal, **surgical** live blast radius: hypotheses form on the frozen
  snapshot; only the handful that matter get validated live, mostly on the
  read-only/passive/benign rungs; exploitation is human-gated.
- Dual-view gives the customer recall + compliance (tools) *and* prioritization
  + discovery + chains (engineer) — neither alone is enough.
- Generalizes: snapshot + query-tools + bounded discoverer + dual-view is the
  template for the repo (code graph) and api (call graph / BOLA-BFLA) discoverers.

**Negative / risks**
- Coverage variance (the agent may surface different subsets run-to-run). Tracked
  as a recall metric (p10/p90 over N), mitigated by the deterministic floor +
  temp-0 + multi-pass.
- Snapshot staleness — the assessment reflects the snapshot, not live drift.
  Acceptable and *required* for reproducibility; re-sync is a new assessment.
- Substrate cost/complexity (CloudQuery/Cartography sync). Mitigated by running
  it registry-tier / on-demand, not on every scan.

## Alternatives considered

- **CloudQuery as the CSPM detector** (write our own SQL controls). Rejected —
  §13 (no in-house detectors) + the reproducibility/sandbox clash. CloudQuery is
  the inventory substrate, not the rule engine.
- **Snapshot-only (never touch live).** Rejected — config-possible ≠
  exploitable, so it under-detects real impact and rebuilds a config linter, not
  an engineer. The snapshot is the hypothesis layer; live validation establishes
  impact.
- **Blanket live scanning (agent hammers the live account).** Rejected —
  unbounded blast radius, alarm-tripping, non-reproducible. The snapshot makes
  validation *surgical* (probe the few that matter), and live observations are
  captured into the evidence bundle.
- **Active exploitation to validate by default.** Rejected — unsafe. Analysis
  APIs prove reachability without traffic; active validation is human-gated.

## Companion change

CLAUDE.md §10 gets a clarifying note distinguishing **reproducibility of an issue**
(given a pinned config+environment, replay confirms — the invariant) from
**process determinism** (not required), and recording the **snapshot +
evidence-replay** model with the per-finding evidence bundle as the core artifact.
