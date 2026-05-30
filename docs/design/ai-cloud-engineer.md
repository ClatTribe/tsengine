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

### Two-tier targets

**Tier 1 — real labs (the fidelity anchor).** Deploy into a throwaway account,
each with a *documented kill-chain* = ground truth:
- **CloudGoat** (Rhino) — Terraform AWS scenarios, each a known attack path. Flagship.
- **IAM Vulnerable** (BishopFox) — the catalog of known IAM privesc paths — exact identity-dimension ground truth.
- **AWSGoat / flaws.cloud / sadcloud** — extra scenarios/breadth.
- **Planted decoys (ours)** — config-bad but NOT reachable/exploitable (no listener, NACL/condition blocks, non-sensitive data). The crux: they measure whether the engineer *disproves* what a config linter flags.

Tier 1 is slow + infra-bound but **high fidelity** — it is the truth anchor.

**Tier 2 — LLM-generated synthetic scenarios (scale + anti-overfit).** Because
the engineer reasons over the *snapshot* (ADR 0002), a benchmark scenario is just
a synthetic **(snapshot graph + live-oracle + labels)** — no real cloud needed.
Precedent: OWASP Benchmark (our SAST bench) is itself template-generated.

```
template primitives (deterministic) ─► LLM composer ─► materializer ─► deterministic VERIFIER ─► bench
  prowler check_ids (the misconfigs)    arrange into     render the        confirm each planted     score vs
  PMapper privesc edges (the moves)     complex multi-   snapshot +         path IS reachable &      verified
  network/trust/exposure primitives     step scenarios   live-oracle +      each decoy is NOT        labels
                                        + noise + decoys  ground-truth       (reject if intent ≠ fact)
```
- **Primitives are deterministic** (prowler checks, PMapper edges) — building blocks are mechanical, not LLM imagination.
- **The LLM only *composes*** — arranges primitives into complex scenarios buried in realistic noise + decoys (what hand-written labs can't scale).
- **The deterministic verifier is load-bearing** — independently confirms every label (planted path reachable, decoy inert) over the synthetic graph *before* admitting the scenario. The LLM proposes; a mechanical checker confirms. This + template-derived (not LLM-judged) ground truth defuses the "grading your own homework" circularity.
- **Generate fresh scenarios per CI run** → memorization-proof (§14.2 taken to the limit); thousands of exactly-labeled cases, no infra.

**Two non-negotiables:** (1) the deterministic verifier on every label; (2) Tier 1
as the **calibration anchor** — if the Tier-2 score diverges from the Tier-1 score,
the generator's realism is off → tune. Synthetic gives scale + anti-overfit of the
*reasoning*; real gives fidelity of the *live-probe execution*. Synthetic never
replaces real.

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

## 7. Build plan (proposed changes)

Phased so each slice is independently shippable + testable. Reuses the existing
L2 core (`internal/l2`), orchestrator, replay (§9), and tracer.

| Phase | Build | New / changed |
|---|---|---|
| **C0 · Snapshot substrate (L3)** | Wrap CloudQuery/Cartography as a read-only prepass → normalized inventory graph; content-address it (`snapshot_hash`). Define the graph schema (resources, identities, edges, data-class). | `internal/snapshot/` (schema + ingest), `internal/tool/cloudquery` (or cartography) |
| **C1 · Safety harness (BEFORE any agent touch)** | Scoped STS session-policy generator; mutation deny-guard (reject non-`Get`/`List`/`Describe`); live-call budget; audit logger; the gated `validate(rung)` tool. | `internal/cloudsafety/`, `internal/l2/tools_validate.go` |
| **C2 · Deterministic reasoning tools (local)** | `query_inventory`, `get_resource`, `resolve_access` (wrap cloudsplaining/PMapper for effective perms), `find_paths` (PMapper/Cartography traversal), `classify_data` (Macie/tags). | `internal/cloudreason/` + tool wrappers |
| **C3 · Cloud-engineer agent** | Orientation-brief prepass; the cloud catalog over the L2 ReAct loop; worklist + termination governors; `record_hypothesis/finding`, `finish_assessment`. | `internal/l2/cloud/` (catalog), reuse `agent.go`/`phase.go`/`compaction.go`/`budget.go` |
| **C4 · Dual-view contract** | Extend the dashboard with the `ai_assessment` block (attack-path findings + evidence bundle + prowler correlation + remediation). | `pkg/types/scan.go` (`AIAssessment`), dashboard renderer |
| **C5 · Test (two-tier)** | Tier 1: CloudGoat/IAM-Vulnerable harness + scorer. Tier 2: synthetic generator + **deterministic verifier** + scorer. Scorecard + CI non-regression gate. | `internal/bench/cloudengine.go` (+ `_test.go`), `internal/bench/synthgen/`, `tsbench cloud-engineer` |
| **C6 · Wrapper interface** | The `tswrap` contract + control endpoints (below). | extend `internal/replay` HTTP surface |

**Invariant compliance:** ≤12-tool catalog (§2.6); no in-house *detector* — we
wrap CloudQuery/PMapper/cloudsplaining (§13); the deterministic prepass keeps the
recall floor (prowler) intact; reproducibility = `snapshot_hash` + evidence
bundle (§10).

## 8. Wrapper (`tswrap`) interface — what's exposed to the user

`tswrap` is the consumer-facing wrapper (the tsengine analog of `webappsec`). The
engineer exposes one **artifact** + a small **control plane**, rendered as the
two audience views (§6 dual-audience).

### 8.1 The artifact — `ai_assessment` block on `vulnerabilities.json`
Sits alongside `findings_raw` (prowler "tools say"). Per attack-path finding:
- `narrative` — plain-English chain ("internet → ALB → EC2 role → assume data-role → PII bucket") **[non-security view]**
- `path_graph` — nodes + edges, for the wrapper to render the attack-path visually
- `real_impact` + components (`config_possible`/`live_reachable`/`data_sensitivity`/`privilege`)
- `verification_status` + `rung_reached` + `confidence`
- `evidence_bundle` — every query + live observation, **replayable vs `snapshot_hash`** **[security-engineer view]**
- `corroborates[]` — which prowler `finding_id`s this path chains; `downgrades[]` — which prowler "criticals" it proved inert
- `remediation` — the single cheapest edge to cut + config diff + retest criteria
- `affected_resources[]` (ARNs)

Plus assessment-level: `snapshot_hash`, `audit_log` (every query + live call), `attestation` (signs `snapshot_hash + findings + evidence`), `pending_validations[]` (rung-5 awaiting human approval).

### 8.2 Control plane (HTTP, extends the §9 replay surface)
- `POST /assess {cloud_account, scope, budget, active_validation_policy}` → run an assessment.
- `GET /assessment/{id}` → the dual-view artifact (both lenses + correlation).
- `POST /approve-validation {assessment_id, hypothesis_id}` → **the human-in-the-loop gate** for rung-5 active validation. tswrap is *where the human authorizes* live exploitation; nothing rung-5 runs without it.
- `POST /replay {assessment_id, hypothesis_id | tool, args}` → re-investigate one hypothesis / dig deeper (the §9 replay, extended to cloud hypotheses).
- `GET /audit/{assessment_id}` → the full query + live-call log (the trust surface: "exactly what the agent touched").

### 8.3 The two views tswrap renders (mirrors §6 dual-audience)
- **Security-engineer view:** prowler `findings_raw` + the engineer's evidence bundles + replay/verify + the audit trail + the approve-validation queue. (Trust + drill-down.)
- **Developer / PM / compliance view:** the prioritized attack-path list + plain-English narrative + "fix this first" remediation + compliance evidence pack. (Actionable without a security background.)

### 8.4 Safety surfaced to the user
tswrap must *show* the safety envelope so the customer trusts it: the scoped
read-only role in use, the live-call budget + what was spent, the full audit log,
and the human-gated `pending_validations` queue. **Nothing rung-5 executes from
the agent — only from a human clicking approve in `tswrap`.**

## 9. References
ADR 0001 (L2 bounded discoverer) · ADR 0002 (AI Cloud Engineer + safety +
reproducibility) · CLAUDE.md §6 (dashboard contract), §9 (replay/control plane),
§10 (reproducibility = snapshot + evidence-replay), §2.6/§2.7 (tool cap +
tool-existence), §13 (wrap OSS), §14 (benchmark discipline).
