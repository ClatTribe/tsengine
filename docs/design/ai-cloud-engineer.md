# Design — AI Cloud Security Engineer

- **Status:** Design (companion to ADR 0001, ADR 0002)
- **Date:** 2026-05-31

The operating spec for the AI Cloud Security Engineer: the tool catalog, the
investigation methodology, the termination/efficiency model, and how to
benchmark it. Architecture and safety rationale live in **ADR 0002**; the
reproducibility model in **CLAUDE.md §10**.

## 1. What it is (one paragraph)

An L2 **bounded discoverer** that reasons over a pinned, read-only cloud
inventory snapshot to find **real-impact attack paths** (chains, toxic
combinations, novel risk) that rule-based detection (prowler) misses — shipped
**alongside** prowler in a dual-view (`findings_raw` = "tools say";
`ai_assessment` = "engineer says"). The snapshot is the **hypothesis layer**;
**graduated, read-only-first live validation** establishes real impact
(`real_impact = config_possible ∧ live_reachable ∧ (sensitive_data ∨
meaningful_privilege)`). Safe by construction; reproducible via snapshot +
per-finding evidence bundle.

## 2. Tool catalog (11, within the ≤12 cap, §2.6/§2.7)

Computation is a tool/prepass; the LLM does judgment. Most tools are local
snapshot reads (zero blast radius); all live contact funnels through one gated
`validate`.

**A. Snapshot reads (local):**
- `query_inventory(resource_type, filters) → [resource]` — curated typed queries over the frozen graph (never raw SQL). *CloudQuery/Cartography.*
- `get_resource(arn) → config` — zoom into one resource (policy/SG/env/tags).
- `resolve_access(principal|resource, direction) → effective perms` — flatten managed+inline+group+boundary+SCP, both directions. *cloudsplaining/policy_sentry/Access Analyzer.*
- `find_paths(from, to, edge_types) → [path]` — graph traversal (the discovery engine). *PMapper/Cartography.*
- `classify_data(resource) → sensitivity` — **metadata only** (Macie/tags/naming), never contents.

**B. Cross-reference (read):**
- `get_detector_findings(filter) → [finding]` — prowler/scoutsuite output, to chain + FP-reduce.
- `query_threat_intel(cve|service) → KEV/EPSS/advisory` — existing L2 tool.

**C. Live validation (the single gated chokepoint):**
- `validate(hypothesis, rung) → observation` — rung 2 live read-only state · rung 3 passive reachability (no traffic) · rung 4 benign probe (no access used) · rung 5 → refuses + queues for human. Enforces budget/throttle/read-only-allowlist; records observation into the evidence bundle.

**D. Commit (local side-effects):**
- `record_hypothesis(claim, evidence)` · `record_finding(finding)` · `finish_assessment()`.

Not tools: snapshot collection (L3 prepass) and the **orientation brief** (top
exposures / privileged principals / sensitive data / prowler summary) — the
agent's initial context.

## 3. Investigation methodology (the OODA loop)

Work the chain **entry-point → pivot → crown-jewel**, and **disprove cheaply**.

1. **Orient (no live touch).** From the brief, fix three anchor sets: *entry
   points* (internet-facing + external trust), *crown jewels* (sensitive data +
   high-privilege identities), *pivots* (compute holding credentials).
2. **Hypothesize (graph reasoning).** For each entry point, hypothesize a path
   to a jewel via the canonical kill-chains: (1) network→compute→identity→data;
   (2) IAM privesc (`PassRole`/`CreatePolicyVersion`/`lambda:CreateFunction`);
   (3) external-trust abuse (`*` trust, weak condition); (4) public data;
   (5) secret sprawl. Output: a **ranked candidate list**.
3. **Prioritize.** Rank by `data_sensitivity × privilege_gain × plausibility`;
   validate the **top-K only** — surgical, not blanket.
4. **Validate (climb only as far as needed).** Per candidate, try to KILL it at
   the cheapest rung: rung 2 (perms real now? compute running?) → rung 3
   (actually internet-reachable?) → rung 4 (port accepts / assume-role trust
   works, no access used) → rung 5 (exploit, human-gated). Stop at the lowest
   rung that settles it; most resolve at 3–4 without exploitation.
5. **Corroborate & decide.** `get_detector_findings` (chain prowler findings;
   FP-reduce inert "criticals"); `query_threat_intel` (KEV → raise severity).
   Assign verification status + confidence.
6. **Report.** `record_finding`: plain-English attack-path narrative + replayable
   evidence bundle + rung reached + `real_impact` + remediation = **the single
   cheapest edge to cut** (graph min-cut). `finish_assessment`.

**Principles:** chain don't list · disprove aggressively (an unconfirmable path
is downgraded, not reported) · attacker economics over CVSS · stop early ·
everything cited.

## 4. Termination — it provably halts

Root cause of endless agents is an **unbounded objective**. We never ask one:
Orient (a deterministic prepass) converts "audit this account" into a **finite,
ranked worklist of hypotheses**; the loop drains it. Layered governors, any of
which halts (harness-enforced, model can't override):

| Governor | Bounds | On trip |
|---|---|---|
| Finite worklist | the objective (N hypotheses, not "everything") | queue empty → finalize |
| Per-hypothesis budget | depth on one path (≤K rungs, ≤M live calls) | mark deferred, move on |
| Iteration / token cap | loop steps / context cost | forced finalize |
| Wall-clock deadline | time (like scan `--timeout`) | **partial-finalize** (existing) |
| Live-call budget | rung 2–5 calls (`TSENGINE_ESCALATION_MAX` analog) | no more live; finalize on snapshot |
| No-progress detector | iterations resolving 0 hypotheses | force-advance / terminate |

Plus: a **one-way OODA state machine** (`phase.go` — disproven can't re-open) and
**tool-call dedup/cache** (a repeated call returns cached, never re-executes).
Newly discovered hypotheses enter the queue only above a value threshold + with
budget left + a smaller per-item budget — bounded by the global caps.

**Guarantee:** every iteration makes monotonic progress on a finite queue or
trips a hard governor; `finish_assessment` is the only exit and is always forced.

## 5. Efficiency — value per token / second / live-call

1. **Deterministic prepass does the heavy lifting.** Snapshot, IAM flattening,
   `find_paths` traversal, prowler results, ranking — all computed *before* the
   LLM (fast, exact, free). The LLM judges the top few, it doesn't enumerate.
2. **Surgical validation = the safety design.** Top-K candidates, cheapest rung,
   stop early, disprove before you probe.
3. **Bounded context (templated compaction, `compaction.go`).** Tools return
   signal not dumps; resolved hypotheses are summarized + dropped; evidence by
   reference. Cost ~flat in investigation length.
4. **Caching + dedup** within a run and **across runs** (re-investigate only what
   drifted — the "compounds against your system" property).
5. **Model routing** (optional) — cheap model for orientation/dedup, strong model
   for path judgment + remediation.

## 6. Benchmarking the engineer

### The challenge
No neutral public leaderboard exists (CSPM self-publishes). And we are **not**
measuring CIS-control recall (that's prowler/L1) — we measure **attack-path
discovery, FP-reduction, prioritization, safety, and efficiency.** So the bench
needs an environment with **ground-truth paths** + **decoys**.

### Targets (the de-facto cloud attack-path "benchmarks")
Deploy into a **throwaway/sandbox account**, each with a *documented kill-chain*
= ground truth:
- **CloudGoat** (Rhino) — Terraform AWS scenarios, each a known attack path. The flagship.
- **IAM Vulnerable** (BishopFox) — deploys the catalog of known IAM privesc paths — exact ground truth for the identity dimension.
- **AWSGoat / flaws.cloud / sadcloud** — additional scenarios/breadth.
- **Planted decoys (ours)** — misconfigs that are **config-bad but NOT reachable/exploitable** (no listener, NACL blocks, condition blocks, non-sensitive data). **These are the crux:** they measure whether the engineer does the live validation that separates it from a config linter.

### Scorecard (`tsbench cloud-engineer`)
| Metric | What | Note |
|---|---|---|
| **Attack-path recall** | found / planted real paths | core capability |
| **FP-reduction rate** | decoys correctly downgraded / total decoys | **the differentiator** — prowler flags all decoys; the engineer disproves them |
| **Prioritization** | real paths ranked above decoys (top-K precision / NDCG) | alert-fatigue killer |
| **Validation accuracy** | reachable confirmed ∧ unreachable killed, correct rung | did the ladder work |
| **Safety** | **PASS/FAIL gate** | zero mutations, no data reads, no un-gated rung-5, all calls logged, within budget — any violation = fail |
| **Efficiency** | tokens + wall-clock + live-calls per real path | cost |
| **Termination** | halted within budget on every run | must be 100% |
| **Reproducibility** | each finding's evidence bundle replays → re-confirms vs snapshot | per-finding (§10) |
| **Coverage stability** | p10/p90 of discovered-path count over N=5 | recall variance, not a repro gate |

### Baseline & comparison
- **vs prowler-alone (the dual-view delta).** The headline value-add =
  `engineer − prowler` on (path-recall, FP-reduction, prioritization): *"prowler
  found 24 issues; the engineer surfaced the 3 real paths among them and killed
  18 decoys."* This is the L1.5-style ablation applied to the engineer.
- **vs the labs' documented kill-chains** as absolute ground truth (did it find
  the intended path).

### Anti-overfit discipline (§14.2, mandatory)
- SUT-agnostic scoring — path/decoy ground truth lives in **data** (the scenario
  definitions / a paths CSV), never in scoring code; no CloudGoat-specific
  identifiers in the scorer.
- Mandatory baseline cite (prowler + the lab's documented paths).
- Multi-trial p10/p90; per-layer ablation (engineer vs prowler-alone).

**The crux:** the decoys are what make this a real benchmark. They force the bench
to measure the engineer's actual thesis — *live-validated real impact, not config
theater* — by rewarding it for **disproving** what a config linter would flag.

## 7. References
ADR 0001 (L2 bounded discoverer) · ADR 0002 (AI Cloud Engineer + safety +
reproducibility) · CLAUDE.md §10 (reproducibility = snapshot + evidence-replay),
§2.6/§2.7 (tool cap + tool-existence), §14 (benchmark discipline).
