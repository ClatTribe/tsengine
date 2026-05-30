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

## Decision

Build the AI Cloud Security Engineer as an **L2 bounded discoverer that reasons
over a pinned inventory snapshot**, ships a **dual-view** result, and is **safe
by construction** against the customer's account.

### Architecture

```
L1   prowler + scoutsuite ───────────────►  findings_raw   "Detection tools say"
        (deterministic recall floor — unchanged)

L3   inventory snapshot (CloudQuery / Cartography), read-only, pinned + hashed
        = the captured config+environment (the reproducibility artifact)
                          │
L2   AI Cloud Engineer (LLM agent) ◄────────┘   reasons over the FROZEN snapshot,
        proves with analysis (not exploitation)  ──►  ai_assessment  "AI engineer says"
```

- **L1 stays the floor.** prowler/scoutsuite are unchanged — reproducible,
  compliance-grade, the "tools say" column.
- **L3 snapshot is the substrate AND the safety boundary.** One controlled,
  read-only inventory sync builds a frozen, content-addressed graph. The agent
  reasons over *this static data*, not the live account.
- **L2 engineer is the discoverer.** An LLM agent over the snapshot, with the
  tool catalog below, emitting evidence-backed attack-path findings.
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

The agent is **90% local-snapshot reads (zero live blast radius)**, a couple of
**passive live analysis** calls (read-only, throttled), and **active validation
is a human-gated proposal** — the agent literally cannot exploit on its own.

| Tool | What it does | Blast radius |
|---|---|---|
| `query_inventory(typed)` | Curated typed primitives over the FROZEN snapshot (`list_resources`, `who_can_assume`, …) — never raw SQL, never live | **none** (local) |
| `resolve_permissions(principal)` | Effective IAM perms by simulating captured policies (cloudsplaining / policy_sentry) | **none** (local) |
| `attack_path(from,to)` | Graph reachability over the snapshot (PMapper / Cartography) | **none** (local) |
| `get_resource_config(arn)` | Full config of one resource from the snapshot (policy/SG/env) | **none** (local) |
| `get_data_classification(resource)` | **Metadata only** — Macie verdict, tags, naming. NEVER reads object contents | **none** (local) |
| `get_detector_findings()` | prowler/scoutsuite output, to corroborate / chain / FP-reduce | **none** (local) |
| `query_threat_intel(cve)` | KEV/EPSS for CVEs in exposed workloads (existing L2 tool) | external, read |
| `analyze_reachability(resource)` | AWS Reachability/Access Analyzer — computes *whether traffic could reach* WITHOUT sending any | **passive live**, read-only, throttled |
| `propose_active_validation(path)` | Does **not** execute — QUEUES an active-validation request for human approval | **none** (queues only) |
| `record_finding` / `record_hypothesis` / `finish_assessment` | Commit to the report (evidence + narrative + confidence) | local side-effect |

Snapshot collection itself is **not** an agent tool — it runs once in the L3
prepass, so the agent can't trigger arbitrary collection.

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

2. **Reason over the snapshot, not the live account.** The single biggest safety
   lever (and why the reproducibility reframe and safety align): one controlled,
   rate-limited, read-only sync — then all reasoning is over static local data.
   The agent does not hammer the live account; live access is the *exception*,
   gated, not the default.

3. **Prove with analysis, never exploitation.** The validation ladder:
   *reasoned* (snapshot says the path exists) → *statically validated* (AWS
   Access/Reachability Analyzer proves reachability **mathematically, sending no
   traffic**) → *actively validated* (actually assume a role / send a request) —
   which is **OFF by default**, requires **explicit human authorization**, uses
   **benign-control payloads only** (the §11 post_emit_verifier pattern), and is
   **never destructive or data-exfiltrating**. The agent emits a *proposal*; a
   human pulls the trigger.

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
- Near-zero live blast radius: the agent reasons over a frozen snapshot and
  proves with analysis APIs, not exploitation.
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
- **Agent reasons against the live account directly.** Rejected — unbounded live
  blast radius and non-reproducible. The pinned snapshot is both the safety
  boundary and the reproducibility artifact.
- **Active exploitation to validate by default.** Rejected — unsafe. Analysis
  APIs prove reachability without traffic; active validation is human-gated.

## Companion change

CLAUDE.md §10 gets a clarifying note distinguishing **reproducibility of an issue**
(given a pinned config+environment, replay confirms — the invariant) from
**process determinism** (not required), and recording the **snapshot +
evidence-replay** model with the per-finding evidence bundle as the core artifact.
