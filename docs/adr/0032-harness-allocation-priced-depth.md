# ADR 0032 — Harness allocation: the hypothesis sweep enters the scan path, models get tiers, and depth gets a price tag

**Status:** **ACCEPTED — D1, D2, D3, D4 IMPLEMENTED; D6 wiring-half DONE** on `main`.
- **D6 partial**: `traverse_estate` is now REACHABLE — `platformapi/estate_adapter.go` implements
  `l2.EstateGraph` over the composed graph and `runTranslate` sets `l2.Deps.Graph` from it
  (neighbors/paths/why/chokepoints all answer from graph contents with evidence refs; chokepoints
  exclude endpoints per estategraph semantics). Still open on D6: PERSISTING snapshots keyed
  (repo, commit) with heartbeat-skip.
- Open in sequence: **D5 stage trace**, **D7 envelope generalization**, **D8 HITL provenance
  lifts**, D6 persistence half. Platform rescan depth-passthrough rides the next API PR.

Implementation notes: tier override is env-only (`TSENGINE_MODEL_BREADTH` / `TSENGINE_MODEL_VERIFY`
rebind the model id on the resolved provider; provider/endpoint/keys are config-level). Disprover
is env-gated (`TSENGINE_SWEEP_DISPROVER=1`) and Verify-tier by default. Sweep findings enter at
`pattern_match` with counted refusals; disprover downgrades stay on the candidate evidence trail
and emit their own disclosure.

**What IS proposed:** eight engineering items that close the gaps three external analyses
converged on when pointed at this tree — [OpenWorker](https://github.com/andrewyng/openworker)
(specialist-roster validation),
[Aikido's head-to-head](https://www.aikido.dev/blog/aikido-finds-more-vulnerabilities-claude-security-mythos)
(Aikido audit **68/89 @ $75** vs Claude Security w/ Mythos **60/89 @ $157** vs Codex Security
**58/89 @ $125** on the same 89-vuln target), and
[DryRun's orchestration doctrine](https://www.dryrun.security/blog/your-agent-harness-is-not-an-orchestration-layer)
("if you depend on a model for your performance, you're cooked"; "don't spend probability cycles
on facts you can know"; evaluate the *conditions* that produced outputs).

**What is NOT proposed:** any new in-house detection engine (§13 holds — sweep candidates are
model-proposed and disposed by existing grounding); any change to the L1/L2 split; any private
self-graded head-to-head against Aikido/Claude Security (§14.2 rule 5 — if we publish numbers they
go through external keys; their 89-vuln corpus being theirs-alone is a caveat on THEIR number, not
a license for ours); MCP ingress or persona-bundle marketplaces (shareable prompt-personas cannot
enforce the ≤12-tool cap, grounding, or RoE — our specialists are compiled invariants); token-economy
work that regresses raw recall (§2.4 stands).

**Date:** 2026-08-25

**Depends on / reconciles:** §2.2.1 (specialist taxonomy), §5.3 (escalation — D1 extends its shape,
with one documented deviation), §10 (grounding), §11 (hook chain untouched), §14.2 rule 5,
CLAUDE.md §18.2 invariants (esp. inv 4 — one verifier), `POST /v1/code/sweep` +
`internal/codesweep` (built, tested, zero scan-path callers),
[docs/harness-improvement-program.md](../harness-improvement-program.md) (the offense-lane loop —
this ADR is its Engineer/code-lane counterpart), ADR 0030 (fleet Governor → D7 generalizes it),
ADR 0031 (launch-gap triage — several items here were its deferred M-sized rows, now specified).
**Supersedes:** nothing.

---

## Context

Three external analyses were run against the tree and reconciled with two internal ones. Where they
agree, they agree loudly:

- **Aikido's winning mechanism is task allocation**: small/cheap models chase many independent
  hypothesis threads; frontier reasoning is reserved for the stages where depth pays. They also
  surface a **pre-scan cost estimate with a user-tunable depth**, and criticize Claude Security for
  billing blind. We allocate one brain to every stage (`resolveAgentLLM`) and quote nothing before
  the run.
- **DryRun's architectural rules** map onto our tree with unusual precision — deterministic recon→fan-out,
  evaluators instead of model recall, propose/dispose grounding are exactly their prescription. But
  two critiques land cleanly:
  1. **The scanner defines the search space.** Our L2 reads `findings_enriched`; if no anchor
     nominated an authz/business-logic flaw, nothing hunts it. The ready-made answer already exists
     — `internal/codesweep` decomposes a repo into parallel model questions and disposes them
     against grounded indicators — but it sits behind `POST /v1/code/sweep` with **zero scan-path
     callers** (verified: sole caller is `platformapi/codesweep.go`).
  2. **Evaluate the conditions that produced outputs.** We log hook actions (`l15_audit_log`) and
     count sweep refusals, but there is no reconstructable per-scan trace of model-call → evidence →
     disposition at stage granularity.
- Two claims from earlier drafts of this analysis were **corrected during review** and are recorded
  so they do not resurface: (a) "estategraph has zero consumers" is stale — the cloudagent depth
  agent walks it live today (`cloudinvestigate.go` injects `Estate: d.estateOrNil(...)`); the real
  gaps are persistence across runs, webagent consumption, and the unwired `l2.Deps.Graph`;
  (b) gating an authz-flaw hunter on "OWASP-Bench logic-flaw classes" is a category error —
  BenchmarkJava has no business-logic/authz classes. Corrected gates appear in D1.

Per §0, ordering below is by customer confidence at risk; effort sizes only sequence within items.

---

## Decisions

### D1 — The hypothesis sweep joins the repository scan path (the search-space ceiling closes)

`internal/codesweep` becomes the repository asset's **post-anchor coverage stage**: after anchors
fire, deterministic host-side enumeration produces the sweep surface (routes, auth middleware,
trust boundaries, entry points — file facts, zero probability), `codesweep.Plan` decomposes it into
capped parallel model questions, and the existing grounded disposer keeps the ceiling at
`pattern_match` with counted refusals. Findings ride the normal enrich/store/grc pipeline.

Deviations and gates, stated:

- **This is a documented §5.3 deviation.** Escalation stages are signal-gated; the sweep is
  *breadth*-gated instead — triggered by depth dial (D2) and repo-size budget, because its purpose
  is precisely to hunt where signals do not reach (business logic, authz semantics). The deviation
  lives in the handler comment, not buried here.
- **Gates (corrected during review):** planted authz/business-logic fixtures authored fresh
  (must-find, with decoys); VAmPI-class API authz remains `apiauthz`'s lane, not swept; OWASP-Bench
  runs as **regression-only** (existing detection and FP counts may not move beyond noise bands);
  FP-rate on clean repos unchanged.
- **Caps + disclosure:** question count bounded (`TSENGINE_SWEEP_MAX`, default from depth dial);
  anything beyond cap emits `asset.CoverageRulePrefix` disclosure naming the un-swept span; silence
  when complete. Panel adjudication optional behind the Verify slot (D3) once it exists.

### D2 — Depth dial + pre-run quote, with quoted-vs-actual stored

`POST /v1/rescan` and pentest-create gain `depth ∈ {fast, standard, deep}`, mapping onto knobs that
already exist (`TSENGINE_FANOUT_MAX_URLS`, `ESCALATION_MAX`, `DEEP_MAX_ATTEMPTS`, fleet assurance /
MaxIters scaling, D1 sweep question cap). Before the run, a **quote** is computed by
`cloudengine.EstimateCost` over grounded size signals (repo LOC/file count, discovered URL count
from prior surface, image layers). Rules:

- Size signals insufficient to support a quote ⇒ return `quote: null` plus the named missing
  signal. An invented number is the same overclaim as a fabricated finding (§10).
- `Scan` gains `QuotedCostUSD` / `ActualCostUSD`; both render wherever cost renders. An overrun we
  hide is Aikido's Claude-Security criticism aimed at ourselves.
- The dial adjusts caps, never grounding: `deep` buys more hypotheses and more verification
  passes, not looser disposal.

### D3 — Tiered model routing: `ModelPolicy{Breadth, Verify}`

PlatformAPI Deps gains a two-slot policy. **Breadth** slot (cheap/configured model) serves
spec-gen, codesweep questions, cweattrib triage. **Verify** slot (tenant/operator frontier) serves
D-agent verification, panel adjudication, Lead final-report drafting. Default policy = same model in
both slots — zero behavior change, asserted by test. Ablation reports Δrecall/$ through
`improveloop`; routing earns its place measured, not claimed. This is the mechanism behind Aikido's
entire head-to-head result, and Provos demonstrated the floor makes it workable with open-weight
models.

### D4 — Disprover stage (downgrade-only, raw-evidence input)

For `Vulnerable` findings whose class lacks a deterministic predicate: an independent adversarial
pass with a different prompt and the **Verify** model slot, whose ONLY legal outputs are
`clean | abstain | downgrade-with-rationale`. Hard constraints, each pinned by test:

- Input is **raw turns/evidence only** — never the finder's conclusions. DryRun's poisoned-judge
  warning: a judge fed the finder's story just agrees confidently.
- It can never create a finding; abstain fails open (finding stands as-is); every action is
  ledgered with the vote + rationale.
- Disposal for predicate-covered classes remains purely deterministic — this stage exists to give
  uncovered classes a second look, not to blur the §10 bar.

Reuses the consensus-panel machinery; slots after D3 because the Verify slot is what makes it
affordable.

### D5 — Scan trace artifact (conditions-evaluation made reconstructable)

Append-only per-scan trace: one record per stage execution — stage name, input hash, brain/model,
token counts, disposition + reason. Signed through `pkg/ledger` so one verifier covers ledger,
evidence packs, and traces (§18.2 inv 4). This converts DryRun's "evaluate the conditions that
produced outputs" from aspiration to artifact: a wrong answer becomes diagnosable at stage
granularity, and `improveloop` gets real attribution instead of vibes. Rides the scan directory
(`trace.jsonl`) alongside `vulnerabilities.json`.

### D6 — Estate knowledge persists; the strangler finishes its wiring

Corrected scope (the original analysis overstated the gap): cloudagent consumes the walkable graph
today. What remains:

- **Persist** estategraph snapshots keyed `(repo, commit)` with an evidence-heartbeat skip
  (unchanged repo ⇒ re-derivation skipped, same pattern as `CaptureEvidenceSnapshot`) — DryRun's
  "preserve repository understanding" becomes our token-saving substrate.
- **Finish `l2.Deps.Graph` wiring** — `translate.go` sets it from the persisted snapshot;
  `traverse_estate` stops being built-but-unreachable.
- **Webagent Leads** read from the persisted graph where available (mechanism exists; source
  changes from ephemeral to persisted).

### D7 — One token envelope for every model subsystem

Extract the fleet.Governor core (atomic drawdown + latch-breaker + halt-with-disclosure) into a
shared package; codesweep questions, cweattrib, pentest spec-gen, and the D4 disprover each consume
the scan-scoped envelope. A subsystem that exhausts its share halts WITH disclosure — never silent
truncation rendered as completeness. Generalizes tonight's fleet invariant to every probabilistic
subsystem, which is also DryRun's token-budget-as-architecture point.

### D8 — HITL provenance lifts (from OpenWorker)

Approval cards gain an agent-provenance line ("diff authored by agent run `<id>`"); risk-class
overrides tighten-only within action tiers; unattended parked asks formalized as the inbox case of
queued actions. Small, batched with adjacent PRs.

---

## Anti-overfit / measurement rules (binding)

1. Dev/holdout split applies to code-lane benches too: planted authz fixtures are split; the
   holdout half is untouched until each lever's frozen evaluation.
2. Global mechanisms only — no CVE-id, package-name, or challenge hardcoding; the bench score-guard
   greps extend to all new prompt/harness text.
3. Every ablation labels brain + harness sha + pass index; free-tier results never sit unlabeled
   beside frontier numbers.
4. Keep/revert requires capture/recall delta WITHOUT precision loss — identical discipline to the
   offense loop.

## Sequencing

| Order | Item | Size | Tier |
|---|---|---|---|
| 1 | D2 estimate + depth dial | S | GA-adjacent (Aikido-parity UX) |
| 2 | D1 sweep into scan path | L | highest customer value; the ceiling closes |
| 3 | D3 ModelPolicy tiering | M | prerequisite for D4 |
| 4 | D4 disprover stage | M | after D3 |
| 5 | D5 trace artifact | M | lands with D3/D4 instrumentation |
| 6 | D6 estate persistence + wiring completion | M | standalone |
| 7 | D7 shared envelope | M | after multi-model is real |
| 8 | D8 HITL lifts | S | batch opportunistically |

## Consequences

**Better:** the scan path stops outsourcing business-logic discovery to luck; recall gains come
from allocation, not model worship; customers see a price before committing and quoted-vs-actual
after; wrong answers become diagnosable at stage granularity; estate understanding survives across
runs instead of being re-bought every scan.

**Harder:** D1's regression gates will fail PRs that degrade anchors — that is their function. D2's
refuse-to-quote path will occasionally decline to price a weird target — that is honesty, not a bug.
D4 adds latency to uncovered-class verdicts. D5 grows scan artifacts (bounded, signed). The sweep
adds model spend to repository scans — bounded by the envelope (D7) and surfaced by the quote (D2).

**Refusals restated:** no detection engine; no MCP/marketplace; no self-graded vendor duels; no
recall regression for tokens.

---

## Sources

- [Aikido — How Aikido finds more vulnerabilities than Claude Security at half the cost](https://www.aikido.dev/blog/aikido-finds-more-vulnerabilities-claude-security-mythos) (Aug 2026 head-to-head numbers)
- [Aikido — Move over, Mythos. Here comes any model with a good harness](https://www.aikido.dev/blog/mythos-vs-harness) (UCSB 4× harness delta; Provos GLM replication)
- [Cloudflare — Project Glasswing](https://blog.cloudflare.com/cyber-frontier-models/) (stage pipeline: Recon/Hunt/Validate/Gapfill/Dedupe/Trace/Feedback)
- [Provos — Finding Zero-Days with Any Model](https://www.provos.org/p/finding-zero-days-with-any-model/) (FSM orchestrator + journal; tiered execution validation)
- [DryRun Security — Your Agent Harness Is Not an Orchestration Layer](https://www.dryrun.security/blog/your-agent-harness-is-not-an-orchestration-layer) (model blast radius; conditions-evaluation; poisoned-judge rule; token budgets)
- [OpenWorker](https://github.com/andrewyng/openworker) (approval gating, model-agnostic seam, specialist roster — parity validation)
