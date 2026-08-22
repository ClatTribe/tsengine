# ADR 0018 — The Frontier Loop: simulation-driven self-improvement under bounded cost

**Status:** Proposed — items 3, 4 and 5 implemented (5 with one clause declined on design grounds, recorded in the table); item 2's cost discipline implemented and its driver blocked on item 1; item 1 half done — the capability axis is measured against three external answer keys, the market axis still needs deployed targets (see "What has shipped")
**Date:** 2026-08-21
**Supersedes:** nothing. **Depends on:** ADR 0002 (config-possible ≠ exploitable), ADR 0006 (active
exploitation + RoE), ADR 0008 (long-horizon agent), ADR 0014 (defense benchmark).

## Context

Six architecture documents were written proposing that tsengine evolve from `Scan → Enrich → LLM →
Report` into a **frontier system for cybersecurity** — a capable general model placed inside a rich
security environment, given tools and context, graded against objectively verifiable outcomes, and
improved from the resulting experience.

The documents were:

| # | Proposal | Altitude |
|---|---|---|
| A | "Frontier System Architecture & Learning Loop" — L1/L1.5/L2/L3/L4 behavioural model, trajectories, 18 acceptance criteria | architecture |
| B | Critique of a "Security Digital Twin" proposal — reuse the cloud substrate; build the **GitHub-Actions/Okta → AWS** bridge; independent ground truth | capability |
| C | Frontier-Systems framing (Midha, Stanford CS153) — the moat is the environment, not the model | strategy |
| D | "Learning & Verification Architecture" — variant of A, plus a verification policy and a terminal-status enum | architecture |
| E | Cost analysis — progressive cost escalation, model routing, bounded exploration, cost-per-insight | economics |
| F | Capability-learning framing — three environments, red as ground-truth generator, capability scorecard, staged product progression | strategy |

Every claim in all six was checked against this tree. **The architecture is substantially further
along than any of them assumed, and the two genuinely missing primitives are small.** This ADR records
what is already true, the three constraints that shape everything, and the smallest coherent change.

### Correction of record

An earlier analysis in this reconciliation asserted that `internal/estategraph` "is not wired into the
agents." **That was wrong**, and it changed a recommendation, so it is corrected here rather than
quietly dropped. The estate graph is wired on both agents:

- `cloudagent.Context.Estate *estategraph.Graph` with an `estate_context` tool — plus a guard
  (`estateOnlyNode`) that REJECTS a cloud path built out of estate ids, so a cross-surface pivot may
  inform reasoning without laundering an unproven hop into a recorded finding.
- The L2 Lead has `traverse_estate` (`internal/l2/tools_graph.go`) — one catalogue slot, four
  operations (neighbours / paths-from / why / choke-points), phase-scoped to Investigate+Chain, which
  **reports truncation rather than swallowing it**: "the agent must know the list stopped early, or it
  will reason as though it has seen every route and rule out the one it never got."

So "elevate L1.5 from enrichment to a traversable world model" — the headline ask of documents A, C and
D — is **built**. It is removed from the plan.

### What else is already built

| Proposed | Already in the tree |
|---|---|
| L1 perception; keep it deterministic | 35 OSS wrappers, `internal/asset/*`, recon→fan-out→escalation. §13 already forbids in-house detectors |
| Verification as a first-class primitive | `retest.Verify` (absence) + `retest.ApplyReattack` (exploit re-run, and **re-attack beats a scanner's silence**), `detect.Reconcile`, compliance control checks |
| "The LLM must not declare itself successful" | Structurally enforced: `requiredIndicator` gates `record_finding`; `DemoFromSpec` re-validates every LLM-proposed spec with a deterministic predicate; retest keys are stamped at propose time |
| Model-agnostic | `internal/l2/adapters`, `cloudengine.ClientForURL`, per-tenant key resolution |
| Progressive cost escalation (E §7) | The **rung ladder** — rung 0 reasoned → rung 3 symbolic/passive (`SnapshotOracle`) → rung 4 live. Plus §5.3 signal-gated escalation: "expensive tools fire targeted, never blanket" |
| Threat-relevance filtering of hypotheses (E §6) | `threatinformed.Plan(corpus, observed, opts)` — ranks CVE probes by KEV → EPSS → public exploit against *observed* product/version. Deterministic, LLM-free, **zero token cost** |
| Model routing (E §4) | `platform.AgentRole` — `RoleAnalysis` (triage/correlation/attack-path) vs `RoleCode` (patch/exploitation), independently configurable per tenant |
| Hard stopping rules (E §11) | `TSENGINE_FANOUT_MAX_URLS`=200 · `TSENGINE_ESCALATION_MAX`=50 · `TSENGINE_THREAT_PROBE_MAX`=25 · `TSENGINE_DEEP_MAX_ATTEMPTS`=3 · `l2.Budget{MaxTokens:2M, MaxIterations:60}` · `webagent` MaxRequests/MaxIters |
| Retrieve subgraphs; cache the world (E §13) | `traverse_estate`/`estate_context` return bounded neighbourhoods; `internal/l2/compaction.go` compacts **deterministically, no extra model call**, and "keeps the system prompt fixed (cache prefix stable)" — which is what earns the cached-input discount |
| "Compile intelligence down" (E §19–20) | Already an invariant. §5.3: "this engine handles the known signal→tool mappings deterministically (zero token cost); the open-ended reasoning stays L2." The escalation trigger tables **are** compiled-down intelligence |
| Don't run learning experiments on customers (E §17) | `webrange` / `synthgen` / `holdout` are exactly that venue — see below |

### The simulation substrate already exists

Documents A, C and D each said "do not build a Security Gym unless the codebase justifies it." None
checked. Two surfaces already have one, and the hard part — anti-circular ground truth — is solved:

- **Web** — `internal/webrange` is a **procedurally generated, seeded** vulnerable application
  (`Generate(seed, opts)`) served as an `http.Handler`, with a `Manifest` answer key, scored against
  the agent, runnable with **no API key**. It deliberately mixes real vulns with **decoys** that "look
  injectable (reflect input, accept a redirect param, take a filename, run a `ping`) but are safe."
  Recall measures whether the agent finds the real ones; the decoy count measures whether **grounding
  held** — "a circular detector would confirm the decoys too."
- **Cloud** — `cloudengine/synthgen.go` (seeded reachable + inert cases) and `cloudengine/holdout.go`,
  whose header states plainly that the in-distribution bench "is circular by construction and must not
  be read as a capability claim," and which therefore labels held-out cases with an **independent
  oracle** (`cloudiam` including permission boundaries and trust policies) that the engine does not run.
- **Defense** — `tsbench defense` / `defense-xbow`: patch the vuln, and the *recorded winning exploit*
  must stop capturing the flag **and the app must still function**.

## Decision

Adopt the frontier-system framing, with the amendments the evidence forces.

> **The durable asset is Security Context + Environment + Verification + Trajectories.**
> **Learning happens in synthetic estates and the customer's digital twin — never in production.**
> **Red generates the labels, as a replayable artifact rather than a second opinion.**
> **The improvement channel is the substrate, not the weights — except on one paid tier where it is
> both. Every loop is bounded by cost-per-verified-outcome.**

### Amendment 1 — Three venues, and learning happens in the first two

Three constraints make the customer's *live* estate the wrong place to learn, and all three dissolve
one tier up:

1. **BYOK breaks post-training.** `pkg/platform/plan.go`: a customer on their own key "may use AI on
   any plan, because that cost isn't ours," and Free is deterministic-only. You cannot post-train a
   model you do not host, and the pricing actively encourages tenants we do not host.
2. **Offence is consent-gated, so customer ground truth is structurally scarce.**
   `pentest.RulesOfEngagement.ActiveAuthorized()` requires `AllowActive` **and** a named
   `AuthorizedBy` **and** a recorded consent statement, plus the operator's `TSENGINE_ACTIVE_EXPLOIT=1`.
   This is correct and non-negotiable. It also means exploit-verified outcomes will never be abundant
   in production.
3. **Pooled customer trajectories cross §18.2 invariant 2.** Tenant isolation is the security boundary.

But "simulation vs production" is the wrong split, because it hides a third venue that already exists
and carries real customer state at zero production risk. There are **three**, and each may be used for
strictly different things:

| Tier | What it is | May be used for | Limit |
|---|---|---|---|
| **Synthetic** | `webrange.Generate(seed)`, `synthgen`, `GenerateHoldout` — procedurally generated estates with an independent answer key | Agent training, exploration, failure-mode discovery, benchmark expansion. **Unbounded exploitation** — we own the target | Distribution shift. A capability that scores here may not transfer |
| **Digital twin** | `internal/cloudsnap` — the tenant's latest cloud inventory, persisted "so the AI cloud engineer can reason over STORED cloud state," plus `SnapshotOracle`, which validates "purely over the snapshot — no live touch" | Customer-specific evaluation on **real** state: does our engineer reach the right conclusion about *this* estate? Regression testing a substrate change against real topologies | Read-only and symbolic. Cannot settle anything that depends on runtime condition evaluation (rung 4) |
| **Production** | The live estate | Only bounded, authorised action: `RoE`-gated validation, HITL-gated remediation | Consent-gated and scarce. **Never a training venue** |

Learning happens in tiers 1 and 2. Tier 3 contributes verified outcomes as a by-product of doing the
customer's actual work — valuable, but never solicited for the corpus's sake.

The synthetic tier's decisive property is that `webrange`'s seeded generator can synthesise **the
specific failure mode we just measured**, which is the one thing neither a digital twin nor a
production corpus can be asked to supply on demand.

### Amendment 1b — Red generates the labels; the recorded artifact is the oracle

Naming simulation as the venue does not say where ground truth comes from. It comes from **red**, and
the mechanism is already built for the code/web surface in `internal/bench/defensexbow.go`:

```
red agent attacks  →  captures flag  →  the RECORDED request sequence is persisted
                                                  ↓
                                        that artifact is the oracle
                                                  ↓
blue patches  →  replay the exact recorded steps against the patched build
                                                  ↓
                        flag gone AND app still functions  →  verified fix
```

The load-bearing detail is *why* the artifact is the oracle and not the agent: replaying a recorded
sequence "is a reproducible verdict (**unlike re-running the non-deterministic agent**)." A second
agent's opinion is not ground truth; a recorded exploit that either still works or does not, is.

This generalises. Every surface's label generator should follow the same shape — red produces a
**replayable artifact**, and that artifact grades blue:

| Surface | Red's artifact | Replay oracle |
|---|---|---|
| Web / code | Recorded HTTP step sequence (built) | Re-run steps, check flag |
| Cloud | The proven path + the `cloudiam.Authorize` query that permitted each hop | Re-evaluate the query set after remediation |
| Identity / CI-CD | The claim-context that satisfied the trust condition | Re-evaluate the condition against the changed policy |

The **anti-sabotage guard is mandatory in every instance**: a patch that breaks the app is not a fix,
and a blue agent optimised against an oracle without that guard learns to break things.

### Amendment 2 — The learnable surface is smaller than the documents claim

The flywheel works only where verification is grounded in something other than another model's
opinion. Testing the proposed policies against that bar:

| Policy | Verifiable? | Oracle |
|---|---|---|
| **Remediation** (what fix, did it work) | **Yes** | `retest.Verify` + `ApplyReattack` + regression tests. Fully built |
| **Verification** (what evidence is sufficient) | **Yes, retrospectively** | Every `ApplyReattack` **disagreement** — the rescan said fixed and the exploit still worked — is a labelled example that the evidence gathered was insufficient. Same for a `corroborated` finding a human later reinstates or suppresses (`tenanteval`) |
| **Investigation strategy** (next action) | **Terminal only** | Did the episode confirm the vuln / capture the flag. Intermediate steps are sparse-reward credit assignment |
| **Prioritisation** (what to look at first) | **No** | Has no ground truth without a counterfactual we never ran |

Documents A and D list prioritisation **first**. It is the least tractable of the four. The
**verification policy** — introduced only in document D, and listed last there — is the second-most
learnable, and its oracle is a by-product of machinery already running. We invert the order: capture
the verification-policy signal now, at zero marginal cost; do not attempt a learned prioritisation
policy.

### Amendment 3 — Post-training is a tier, not a layer

For BYOK tenants, "improvement" means the **substrate**: escalation trigger tables, tool selection
(`internal/toolselect`), context assembly, phase structure, verifier quality. All are testable against
a seeded range and shipped to every tenant on the next release — including tenants whose model we
never see.

Post-training the weights is possible only where we host the model *and* hold training consent. That
is a distinct, higher-priced offering:

> **Dedicated Model tier** — the tenant runs on our hosted model, grants explicit training consent, and
> receives a model post-trained on simulated scenarios plus (with consent) their own verified
> trajectories.

Two invariants govern it, and both are §18.2 invariant 2 applied to weights:

- **A model tuned on tenant A's trajectories MUST NOT serve tenant B.** Either the tune is
  tenant-dedicated, or its corpus is restricted to simulated + explicitly-consented-to-pool data.
- **Training consent is captured at episode-write time**, never inferred later. Retrofitting consent
  onto an existing corpus is not possible.

### Amendment 4 — Bounded exploration is a correctness property, not only an economy

Unbounded exploration does not merely cost money; it produces confident conclusions from searches that
silently stopped early. `traverse_estate` already reports truncation for exactly this reason. Every new
loop inherits that discipline: **a bounded answer presented as complete is a §10 grounding failure.**

## What we build

Five items, ranked by value-to-customer-done-right (§0), smallest coherent change first.

### 1. Populate the scorecard — run the benches, on two axes

`SCOREBOARD.md` is already the capability meta-loop every document asked for, with neutral external
bars per category. It currently reads:

> **1 at/above par · 0 below · 7 pending a live run.**

No self-improvement claim is checkable without this. It is also the baseline every future Δ is measured
against. Blockers per row (sandbox image, deployed target, LLM key) are to be enumerated and closed
one at a time. **This gates everything below.**

**But one axis is not enough, because the existing one answers a different question.** SCOREBOARD is
organised by **asset** (web / repository / api / container / ip / domain / cloud). That is the right
shape for *"is our SAST at par with Fortify?"* — a competitive question, and the reason each row
carries a neutral external bar. It is the wrong shape for *"is our engineer getting better at
remediation?"* — a learning question, which cuts across every asset.

So the scorecard becomes **dual-axis**, and the two are not interchangeable:

| Axis | Question | Rows | Bar |
|---|---|---|---|
| **Asset** (exists) | Are we at par with the category leader? | web · repository · api · container · ip · domain · cloud | Neutral external leaderboards (WAVSEP, OWASP Benchmark, CIS) |
| **Capability** (new) | Is the engineer improving? | threat validation · attack-path discovery · investigation · exploit verification · remediation · regression verification | Our own prior score. **Internal instrument, not a market claim** |

The capability axis is what Δbenchmark-per-dollar is computed over, and what a simulation loop moves.
Each capability row must name the harness that produces it (`tsbench defense`, `defense-xbow`,
`webrange`, `cvepatch`, `integration`, `cloud-baseline`) so a number is traceable to a runnable
command, never asserted.

Two honesty rules carry over from §14.1.1 and apply to **both** axes:

- **Report Youden (TPR+TNR−1), never bare precision.** A system that abstains 95% of the time scores
  beautifully on precision and is useless. This error has now appeared in three of the six source
  documents; it is called out here so it does not appear in a fourth.
- **Report coverage / unknown-rate alongside every score.** A capability evaluated on 5% of the
  relevant space is not succeeding merely because it was conservative.

### 2. The simulation improvement loop

The loop runs in tier 1 (synthetic), with tier 2 (digital twin) as the transfer check — never against
a live estate:

```
measure (SCOREBOARD / tsbench)
      ↓
identify the weakest measured capability
      ↓
generate seeded scenarios targeting THAT weakness   (webrange.Generate / GenerateHoldout)
      ↓
improve the SUBSTRATE — triggers, tool selection, context, verifiers, prompts
      ↓
re-measure on HELD-OUT seeds
      ↓
stop when Δbenchmark / $ falls below threshold
```

Three rules keep it honest:

- **Improve against one seed range; measure on another.** Tuning and scoring on the same seeds
  reproduces exactly the circularity `holdout.go` was written to escape.
- **Decoy pass-rate is a gate, not a metric.** A change that raises recall while confirming a decoy is
  a regression, because it traded grounding for a number.
- **Log what was dropped.** A bounded sweep that reports only its hits reads as complete coverage.
- **Confirm transfer on the digital twin before claiming the capability moved.** A synthetic gain that
  does not reproduce against real stored customer topologies is a gain against our own generator, not
  against the world. This is the distribution-shift check that tier 2 exists to provide.

### 3. GitHub Actions → AWS OIDC validator

The only proposal across the six that **widens the verifiable surface**, and it is a customer-valuable
capability on its own. Verified absent: zero hits for `AssumeRoleWithWebIdentity` or
`token.actions.githubusercontent.com` anywhere in the tree.

It needs no new schema. `estategraph`'s existing edges carry the chain exactly:

```
Okta user --owns--> GitHub repo --assumes--> AWS role --grants--> data (SensHigh)
```

And `cloudiam` is roughly 80% of the evaluator already: it parses trust policies with a `Principal`
element and supports `StringEquals`/`StringLike`, which is literally what matching
`token.actions.githubusercontent.com:sub` against `repo:org/name:ref:refs/heads/main` requires.

Missing, precisely: (a) the `Federated` principal form, (b) an OIDC **claim-context** input type
(`sub`/`aud`/`repository`/`environment`/`ref`), (c) the workflow-metadata ingest. **(a) and (b) are
buildable against fixtures with zero credentials and land before (c).**

**Do not introduce a `VALIDATED_PRECONDITIONS | BLOCKED | UNKNOWN` verdict enum.** It is coarser than
the rung ladder already shipped: `SnapshotOracle` distinguishes "gated by a runtime condition — needs
live validation (rung 4)" from both BLOCKED and a bare UNKNOWN, and collapsing them loses the
distinction ADR 0002 exists to preserve.

### 4. The `Episode` record

The one outright missing primitive. Audited against document D's 13 acceptance criteria, the tree
scores **6 pass · 4 partial · 1 fail · 2 constraints** — and the single failure ("capture initial and
final security state") is *why* three of the four partials are partial. Nothing snapshots a security
state, so nothing can diff one, so a delta cannot be attributed to an episode, so the corpus is not
trainable.

Design rules:

- **Extend `ledger.Step`; do not build a second recorder.** `pkg/ledger` is already a signed,
  canonical-JSON, replayable trajectory with `{Seq, At, Thought, Tool, Args, Observation}` and
  nil-safe capture wired into webagent / cloudagent / llmredteam. It needs per-step **cost** and a
  **verification** link.
- **Bracket the episode with a `SecurityState` snapshot** (before / after). This is the missing object.
- **Keep the four existing status vocabularies as separate fields. Do not add a fifth enum.** Document
  D proposes `SUCCESS | FAILURE | FALSE_POSITIVE | INCONCLUSIVE | HUMAN_ESCALATION`, which flattens
  four independent axes that the tree deliberately separates:

  | Axis | Question | Values |
  |---|---|---|
  | `l2.StopReason` | why the loop stopped | running / cancelled / stalled / finished / max_iterations |
  | `types.VerificationState` | how much to trust the finding | pattern_match → corroborated → verified |
  | `platform.FixStatus*` + `retest.Status*` | did the fix close it | fixed / still_present / closed_with_proof / still_exploitable |
  | `tenanteval.Verdict` | what the human said | keep / suppress |

  Collapsed, the system can no longer express *"the loop finished cleanly, the finding is verified
  real, and the fix did not close it"* — which is exactly the case `ApplyReattack` was written to catch.
- **Fields that exist from day one because they cannot be retrofitted:** `difficulty`, `agent_version`,
  `training_consent`, and the cost block.
- **Failed episodes are retained**, first-class.

### 5. Unified state-delta + verification-policy signal

- One `SecurityStateDelta` carried by the episode, unifying the three sources that each compute one
  today (`detect.Reconcile` finding-diff, `clouddrift.Diff` config-diff, `retest` fix-verification).
- **Log every `ApplyReattack` disagreement and every `tenanteval` reversal as a labelled
  evidence-sufficiency example.** This is the verification-policy corpus, and it is free.

## Cost discipline

The economics amendment: **document E's unit-economics section assumes operator-funded inference, and
ours largely is not.** For a BYOK tenant our COGS is sandbox + storage, not tokens; Free is
deterministic-only by design. The COGS anxiety that motivates E's "sell a research budget" pricing is
already architecturally mitigated, so **pricing is not restructured by this ADR.**

What we adopt from E:

1. **Cost per verified outcome becomes a first-class metric.** `l2.Outcome` already carries
   `CostUSD`/`Tokens`/`Iterations`; nothing divides it by verified outcomes and SCOREBOARD has no cost
   axis. The episode cost block closes this at near-zero marginal effort.
2. **Learning efficiency — Δbenchmark per dollar — is the stopping rule for simulation spend.** If
   $1k of runs moves a bench 78→86% and the next $10k moves it 86→87%, stop. This is the mechanism
   that prevents the simulation loop from becoming the unbounded exploration it was built to avoid.
3. **Escalate on expected value, never by default.** The rung ladder, `threatinformed.Plan`, and the
   `ESCALATION_MAX` / `THREAT_PROBE_MAX` / `FANOUT_MAX_URLS` caps already implement this; new loops
   register their own cap rather than inheriting "unbounded".
4. **Graduate discoveries out of the LLM loop.** When a pattern recurs, encode it as a deterministic
   trigger or evaluator (§5.3). Instrument how often this happens — it is the mechanism by which
   marginal COGS per customer *falls* as the system learns.

Not adopted: E's specific model/pricing table (post-dates verification and is not load-bearing), and
E §29's ">90% precision" gate — precision alone is gameable by abstaining. **Use Youden (TPR+TNR−1)
plus an explicit coverage/unknown rate**, per §14.1.1, exactly as every other bench in this repo does.

## What we explicitly do not build

- **A Security Gym.** `webrange` + `synthgen` + `holdout` + the XBOW/defense suites are it.
- **A parallel graph schema.** `cloudgraph` stays the authority for cloud IAM semantics; `estategraph`
  stays the evidence-gated cross-surface join. Neither is replaced.
- **A security foundation model.** The model stays replaceable; the environment is the asset.
- **RL, reward models, or fine-tuning in this phase.** Capture reward-agnostic signals first.
- **A learned prioritisation policy.** No oracle.
- **New verdict enums** that flatten the rung ladder or the four status axes.
- **A vendor-owned benchmark presented as a market claim.** One source document proposes owning "100,000
  security environments and 1 million verified security tasks" and scoring every frontier model on it.
  The capability axis above is an *internal instrument* and is legitimate as such. It must never be
  published as a neutral leaderboard, because **a benchmark's value is its neutrality**, and a vendor
  scoring its own product against ground truth it authored is precisely the circularity `holdout.go`
  exists to escape: "the ground truth is defined by the code under test." §14.2 already requires
  competitor citation and anti-overfit source-greps for this reason. A neutral claim requires
  independent labelling or an external leaderboard — which is why the asset axis keeps its external
  bars and the capability axis does not get one.

## Consequences

**Positive.** The moat compounds where it is cheapest and safest to compound it — simulated estates we
own, graded by oracles independent of the code under test. Substrate improvements ship to every tenant
including BYOK. Post-training becomes a coherent premium tier rather than an architectural assumption.
Cost-per-verified-outcome makes "is this agent worth running" answerable.

**Negative / accepted.** Simulated scenarios are not production; a capability that scores well on
`webrange` may not transfer, which is why held-out seeds, the decoy gate, and the digital-twin transfer
check are mandatory rather than advisory. The verification-policy corpus accumulates slowly, because it
is fed by disagreements. The Dedicated Model tier adds a weights-level isolation obligation that did
not previously exist. The capability axis has no external bar by construction, so it can show
improvement without showing competitiveness — which is exactly why the asset axis is kept and why the
capability axis is barred from marketing use.

**Invariants preserved.** §10 grounding (no verdict from a model where a tool can answer, truncation
reported not swallowed) · §13 no in-house detectors · §18.2 inv. 2 tenant isolation, now extended to
weights · inv. 3 HITL before any write · inv. 4 every decision signed · §21 offence stays inside RoE
and scope, and **the learning system never optimises for successful offensive action outside the
authorised boundary**.

## What has shipped

Against the build list above, as of 2026-08-21 on `feat/frontier-ghoidc`:

| Item | State |
|---|---|
| 1. Populate the scorecard (dual-axis) | **capability axis done · market axis half.** Five rows measured live: SAST 46.54% Youden (at par on the neutral leaderboard), container SCA 1.000 + FP-control pass, repo SCA 1.000, web per-class (sqli 57.58%, aggregate withheld and why), api 1.000. Cloud needs LocalStack; domain is not runnable in a box by design; ip needs a sandbox built with its toolset. **Running the rows is also what found the two bugs that made the scoreboard untrustworthy** — a truncated scan scoring as a capability result, and all 36 wrappers reporting a tool that never ran as a clean scan. Both fixed and guarded; that is the gate working, not a detour from it |
| 2. Simulation improvement loop | **done.** `internal/improveloop` had the two halves that are arithmetic — the stopping rule (Δ per dollar against a floor) and the anti-circularity guard (`Compare` REFUSES when a change was scored on seeds it was tuned against) — plus `Weakest` and `HoldoutSeeds`. `driver.go` adds the missing piece: `Next(baseline, rounds, plan)` sequences rounds as a PURE FUNCTION OF THE JOURNAL, so the loop can be resumed, inspected and replayed rather than held in a process's memory. It owns the discipline around the improvement step (which stays a person's or an agent's): the target is the weakest ELIGIBLE capability rather than the one most recently discussed; held-out seeds exclude every previous round's fixtures for that capability, not just the last one, since round 1's seeds are as circular in round 3 as they were in round 2, AND seeds merely SCORED on are excluded too because the next change was made knowing that result; a REGRESSION blocks its capability until reverted rather than triggering a retry that compounds it against a baseline nobody meant to keep; INCOMPARABLE blocks as a harness fault rather than being reported as a bad capability; a round that ERRORED never becomes a score; and a stop from the round cap or the budget says it is a BOUND, NOT A CONCLUSION — the remaining capabilities were not judged fine, they were not reached. |
| 3. GitHub Actions → AWS OIDC validator | **done, and widened.** `internal/ghoidc` (AWS) + `internal/gcpwif` (GCP, the two-object join) + `cloudiam` Federated principal + `estateingest/ghoidc.go` (the repo→role estate edge) + `estateingest/ghidentity.go` (the human→code hop, or an honest report of why it cannot close) |
| 4. `Episode` record | **done.** `ledger.SecurityState` / `Diff` / `Episode` bracket a run; `Diff` refuses a scope mismatch and a half-bracket, `GrantConsent` refuses once an episode has closed (so consent cannot be back-filled onto data already collected), failed episodes are retained, and `CostPerVerified` reports no ratio rather than zero. Persisted as `platform.EpisodeRecord` through all five stores, served at `GET /v1/episodes`, rendered on `/eval`. Wired on the cloud and code agents; identity has no agent, so it is deliberately NOT bracketed — that would make the episode a fourth change detector |
| 5. State-delta + verification-policy signal | **done, with one clause DECLINED.** The verification-policy corpus ships (`retest` disagreements machine-readable; `tenanteval` gained `SourceEvidenceInsufficient`/`SourceAcceptedRisk`/`SourceHumanVerdict`; `platform.Feedback` + the UI control). `ledger.SecurityStateDelta` exists and every `Episode` carries it. **The "unifying the three sources" clause is declined as written**, and this is a design judgement rather than remaining work: `detect.Reconcile`, `clouddrift.Diff` and `retest.Verify` do not merely compute deltas differently — they produce DIFFERENT ENTITY TYPES with different lifecycles (an Incident with an SLA clock and an ack state; a Finding; a FixVerification on an Action). Collapsing them yields either a delta that has lost the entity semantics, or a lowest-common-denominator row nothing can act on — and it would make the Episode the fourth change detector that §4 deliberately refuses to create. One delta TYPE carried by the episode is the useful reading and is what shipped. Revisit only if a concrete consumer needs the three reconciled, which none does today |
| Free threat intelligence | **done** — KEV `knownRansomwareCampaignUse` and `dueDate` were being parsed and discarded; both now drive the SLA clock, with CISA's date used as an ABSOLUTE deadline rather than a window restarted by our discovery |

**The pattern worth recording.** Four of the six shipped changes were not new capability at all — they
were signal the product was already producing and throwing away: two KEV fields, the re-attack
disagreement, and the accepted-risk verdict. None needed new customer friction or a new integration.
Before building a new source of truth, it is worth checking what the existing ones already say and are
not being asked.

## Open questions

1. **Training-consent contract.** Required before the first episode is written, not after.
2. **Which capability does the first simulation loop target?** Answerable only once SCOREBOARD is
   populated — that is the point of ordering it first.
3. **Dedicated Model tier price and hosting shape.** Product decision, not an engineering one.
