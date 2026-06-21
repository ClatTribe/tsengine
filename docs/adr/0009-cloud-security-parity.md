# ADR 0009 — Cloud-security parity with Aikido Cloud + Wiz

**Status:** accepted (2026-06-22) · phased implementation in progress
**Context:** CLAUDE.md §3 (cloud_account asset), §5.3 (escalation), ADR 0002 (AI Cloud Engineer)

## Why

Our customer (security-conscious SMB) needs cloud security that is *at par* with the
tools they evaluate us against — **Aikido Cloud** (developer-first CSPM in an all-in-one)
and **Wiz** (the agentless CNAPP leader). Today our cloud lane is strong on *reasoning*
(grounded attack-paths, a deterministic IAM evaluator, FP-reduction) but has real
**coverage** gaps against those two. This ADR names the gaps and lays out a phased,
architecture-respecting plan to close them.

Non-negotiables that bound every phase:
- **Wrap OSS; never build an in-house detector** (§13). New coverage routes existing
  tools (trivy/grype/prowler/scout) over more of the cloud surface — it does not add a scanner.
- **Grounded (§10).** A finding cites a real config/tool signal; nothing is inferred from
  data we never read. DSPM uses the *classification metadata* on a node, never the bytes.
- **Snapshot-driven + LLM-free where possible** (mirrors `cloudengine`), so each phase is
  deterministic and testable offline; the live scan stays sandbox-/credential-gated.
- **Platform additive (§18.2 inv 1).** No change to the engine's detection contract.

## The gap analysis (vs Aikido Cloud + Wiz)

| Pillar | Wiz | Aikido Cloud | Us today | Gap |
|---|---|---|---|---|
| **CSPM** (config/CIS) | ✓ | ✓ | ✓ prowler + scoutsuite | none (parity) |
| **CIEM** (entitlements/privesc) | ✓ deep | partial | ✓-lite `cloudiam` + `cloudfox` | depth, not presence |
| **Attack-path graph** (toxic combos) | ✓ flagship | partial | ✓ `cloudengine` (grounded + verifier) | **ahead on grounding/FP-reduction** |
| **Cloud-to-Code** (IaC trace) | ✓ | ✓ | ✓ `cloudtocode` | none |
| **DSPM** (sensitive-data exposure) | ✓ | partial | ✗ — sensitivity is only a *path characteristic*; a directly-public sensitive store with no onward chain is **not** flagged | **GAP 1** |
| **CWPP / agentless workload vuln** | ✓ flagship | ✓ (container) | ✗ — cloud lane is config+IAM only; no CVE scan of running images/compute | **GAP 2** |
| **Multi-cloud reasoning** (GCP/Azure) | ✓ | ✓ | AWS-shaped reasoning (ARNs/SCP/assume-role); `prowler`/`scout` are multi-cloud but `cloudgraph`/`cloudiam` are AWS-first | **GAP 3** |
| **Proven CIS recall** (a number) | self-published | — | scorer built but **sandbox-gated**; no neutral number | **GAP 4** |
| **Live cloud remediation** | ✓ | partial | ✗ — honest read-only stub (gated runbook, machine-readable target) | **GAP 5** |

## The plan — phases (one PR each, self-paced)

### Phase 1 — DSPM-lite (data-security posture) · *this PR*
A standalone **data-exposure** finding for every store that is **public ∧ sensitivity-classified**
— the zero-hop exposure the multi-hop path finder structurally misses. Modeled as a one-hop
`internet → store` attack path so it reuses all downstream rendering (severity, narrative,
graph, compliance). Deduped against stores already covered by a discovered path. Grounded:
emits only when `Node.Public ∧ Node.Sensitive≠none`. Severity: high (low-sens) / critical
(high-sens). Compliance via the existing public+sensitive control crosswalk (GDPR Art. 32 /
Art. 5(1)(f), CCPA, PCI 3.4, HIPAA, SOC2 CC6.1, …). Fully offline-testable + demoable.

### Phase 2 — Agentless workload coverage (CWPP)
From the cloud inventory snapshot, deterministically **extract the container-image / compute
references** of running workloads (ECR/ECS/EKS/Lambda-image/EC2-AMI) and produce a **scan plan**
that routes them through our existing container-image tools (trivy/grype) — "agentless" because
it reads the account inventory, not an in-VM agent. Workload CVEs attach back to the compute
node so `cloudengine` can chain *internet → vulnerable workload → privesc* (the Wiz toxic-combo).
The extractor/planner + attack-path enrichment are offline-testable; the trivy run is
sandbox-gated like the rest. (§13 holds — reuses tools, adds no scanner.)

### Phase 3 — CIS-recall scoreboard (the proof number)
A neutral CIS-baseline fixture (mock account → expected CIS findings) + a scorer reporting our
**CIS recall vs Prowler/Scout** so we can publish a defensible number (anti-overfit guards §14.2).

### Phase 4 — Multi-cloud reasoning (GCP/Azure)
Teach `cloudgraph` ingest + `cloudiam` the GCP (IAM bindings, org policy) and Azure (RBAC, mgmt
groups) shapes so attack-path reasoning + the effective-permission evaluator are provider-parity,
not AWS-only.

### Phase 5 — Live AWS remediation Apply (gated)
A reversible AWS write-path (block-public-access / restrict resource policy) reached only after
the HITL gate, tested against a fake AWS client (the Okta-suspend pattern) — promotes the
read-only runbook to a real apply.

## Honest framing

We are **not** out-scanning Wiz on the whole estate. Phases 1–2 close the two coverage gaps
that matter most for an SMB (sensitive-data exposure + workload CVEs) by routing OSS tools over
more surface; phases 3–5 close the proof, breadth, and remediation gaps. Where a phase's live
number needs the sandbox image or cloud credentials, that stays gated and is stated as such —
never a falsely-confident claim.
