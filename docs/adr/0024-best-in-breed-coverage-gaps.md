# ADR 0024 — The best-in-breed coverage matrix: what "AI Security Engineer + AI Pentester for cloud, code, identity" actually covers, and the gaps

**Status:** Proposed — **gap accounting + a build proposal.** Revised three times; the third pass
(below) EXECUTED probes rather than re-reading, added C11–C18, and put a Sprint 0 in front of P1. Records the honest state of the
(agent × asset) matrix, compares it to the autonomous-pentest incumbents (NodeZero / Pentera / XM
Cyber), and proposes a concrete, sequenced path to close the cells that are now competitively
load-bearing. Supersedes the earlier "accounting only" framing after competitor research
(2026-08-23) showed one of the "structural" boundaries was merely unbuilt.

**P1 implementation status (be exact):** *interface, agent tool, path-authorization semantics and
fake-tested wiring implemented; live AWS/GCP/Azure provider adapters, platform injection, persisted
proof evidence and a controlled live benchmark NOT implemented.* P1 is a seam, not yet a capability.
Do not describe it as shipped provider proof until P1a–P1d below are done.

**And P1 is a SECOND seam, not the first (C11).** `internal/cloudengine/live.go` already implements
this ladder — rung 2 (`iam:SimulatePrincipalPolicy`), rung 3 (passive network reachability), rung 4
(a benign `sts:GetCallerIdentity` probe), rung 5 refused and queued for a human — per edge, budget-
bounded, gated through `cloudsafety.Guard` whose allowlist already contains `"Simulate"`. It has NO
non-test constructor, `cloudsafety.NewGuard` has NO non-test caller, and `Analyzer` has exactly one
implementation: a mock. This ADR mentioned `cloudengine` once, in P5, about LLM wire protocols, and
proposed building the ladder again. **P1a is therefore a wiring task with a design decision in front
of it — which ladder survives — not a subsystem to write.**
**Date:** 2026-08-23
**Depends on / reconciles:** the focus decision (2026-08-17, [specialist-roadmap.md](../specialist-roadmap.md) §1),
ADR 0002 (AI Cloud Security Engineer — read-only, config-possible ≠ exploitable), ADR 0006 (active
exploitation + RoE), ADR 0013 (code-depth specialist, G1), ADR 0018 (frontier loop), ADR 0020
(research gaps vs the literature). **Supersedes:** nothing.

## Context

An eng review (2026-08-23) traced the sentence *"we implemented a best-in-breed AI Security Engineer
and AI Pentester for cloud, code, and identity assets"* against the actual wiring. The claim implies a
2×3 grid — two products (defensive engineer, offensive pentester) across three assets (cloud, code,
identity) — six best-in-breed cells. The tree does not fill in six cells. Three are empty or are a
weaker capability than the label asserts. The claim also OMITS the two surfaces where we are
strongest and most externally validated — **web/api offense** and **compliance** — so the sentence
is simultaneously over-claiming and under-selling. The matrix below is the full picture.

This is the §10 failure mode the whole engine is architected to prevent — *manufacturing false
confidence* — pointed at our own positioning instead of at a finding. A buyer who is sold "AI pentester
for cloud and identity" and gets read-only graph discovery plus deterministic MFA checks feels the gap
in the first demo. The fix is not to hide the gaps: it is to state the matrix honestly, size each
missing cell, and bind the naming so the gap is auditable rather than aspirational marketing.

### The matrix as built (verified against the tree, not the docs)

Rows are asset surfaces; columns are the two products. `[key]` names the NEUTRAL answer key — a
corpus we did not write — because a cell scored only against our own fixtures is not evidence
(§14.2 rule 5).

```
                    AI SECURITY ENGINEER              AI PENTESTER
                    (defense: find + fix)             (offense: prove by RUNNING it)
                 ┌────────────────────────────────┬────────────────────────────────────┐
                 │ BUILT + MEASURED               │ DELIBERATELY NOT BUILT             │
   CLOUD         │ internal/cloudagent            │ read-only BY CONSTRUCTION          │
   [IAM-Vuln,    │ grounded graph; validatePath   │ (live.go:20-22, cloudsafety)       │
    CloudGoat]   │ refuses ungrounded paths       │ = attack-path DISCOVERY, not       │
                 │ NEUTRAL: IAM-Vulnerable 64.5%  │ exploitation. ADR 0002.            │
                 │ · Rhino GCP 65.2%              │ WHY: proof == the mutation (B1)    │
                 │ (in-house: 16/16 primitives,   │ SEE C11 — the ladder EXISTS in     │
                 │  agent 100% recall, 0 invented)│ cloudengine, unwired.              │
                 ├────────────────────────────────┼────────────────────────────────────┤
                 │ BUILT, depth gap open          │ N/A — collapses into web/api       │
   CODE          │ codeagent + codesweep          │ "exploiting code" needs a RUNNING  │
   [OWASP Bench] │ propose/dispose, Refused count │ instance — which IS the web/api    │
                 │ SAST 46.54% Youden — 3rd on    │ column. Static-only = SAST (L1).   │
                 │ cohort (Checkmarx 47/Fortify 35)│ WHY: no target without a twin (B2)│
                 │ G1 code-depth open (ADR 0013)  │                                    │
                 ├────────────────────────────────┼────────────────────────────────────┤
                 │ BUILT + MEASURED               │ N/A — offense has no meaning here  │
   WEB / API     │ (web/api findings feed the L2  │ internal/pentest + internal/webagent│
   [XBOW 104]    │  Lead + L1.5 enrichment; the   │ RoE-gated, canary-proofed,          │
   *** the       │  defensive work here is L1/L1.5│ predicate-disposes, benign-by-      │
   omitted       │  not a dedicated agent)        │ construction.                       │
   strength ***  │                                │ ** XBOW 89/104 = 85.6% **           │
                 │                                │ vs MAPTA (published SOTA) 76.9%     │
                 ├────────────────────────────────┼────────────────────────────────────┤
                 │ BUILT + MEASURED               │ N/A — compliance is not exploitable│
   COMPLIANCE    │ internal/grc + the L1.5        │ There is no "prove it by running   │
   [OpenCRE,     │ compliance.map hook; 25        │ it" for a control mapping. The     │
    SCF, CCM]    │ frameworks, evidence packs,    │ offensive analogue is the VAPT     │
                 │ OSCAL component-def + assess-  │ report, produced FROM the pentest  │
                 │ ment-results.                  │ column.                            │
                 │ ** 96% crosswalk (48/50 CWEs)**│                                    │
                 ├────────────────────────────────┼────────────────────────────────────┤
                 │ EMPTY — no LLM at all          │ EMPTY                              │
   IDENTITY      │ internal/operate + internal/   │ internal/identitythreat = fixed-   │
   [CISA SCuBA]  │ sspm are DETERMINISTIC rule    │ window ITDR rules (impossible_     │
                 │ engines (zero Generate/Client/ │ travel, password_spray, mfa_       │
                 │ Anthropic refs — grep-verified)│ removed_then_access...). No agent. │
                 │ SCuBA 0.993 (SHALL 0.990)      │ WHY: proof == account takeover(B1) │
                 └────────────────────────────────┴────────────────────────────────────┘

  CLAIMED (cloud/code/identity × 2)  : 2 of 6 cells built, 1 deliberate, 1 N/A, 2 empty
  ACTUAL best-in-breed claims        : 3 — cloud defense, web/api offense, compliance
                                          (exactly the 2026-08-17 focus triad)

  TWO AXES THIS GRID DOES NOT SCORE, and both change the reading (C15, C16):
    FIX        every number above measures FIND. The engineer is defined "find + fix"
               and the fix half has NO recorded number in any cell — `tsbench defense`
               and `defense-xbow` define remediation-capture as the hero metric and
               have never produced one.
    CONTINUITY a cell can be BUILT and still not be MONITORED. Four producers re-derive
               each pass (asset scans, SaaS posture, OSINT, cloud drift). The cloud
               engineer, the code engineer, codesweep, ghoidc/gcpwif/samltrust, TPRM,
               device posture, dataplatform and the identity ITDR ingest are all
               ONE-SHOT, and absence-as-evidence then works against them.
```

Three facts behind the grid, each grep-confirmed:

1. **Identity has no LLM agent.** `internal/operate` and `internal/identitythreat` contain no
   `Generate`/`Client`/`Anthropic`/`openai` reference — they are deterministic rule engines. Good ones.
   But an "AI Security Engineer for identity" is exactly the overclaim CLAUDE.md §2.2.1 and the focus
   decision forbid ("identity ships as a *capability, not a claim*").

2. **"AI pentester for cloud" is attack-path discovery, not exploitation.** `cloudagent/live.go:20-22`
   — *"read-only... never probes, sends traffic, or mutates."* This is a blast-radius decision (ADR
   0002), not an oversight. The active-exploitation pentester (`internal/pentest`, `internal/webagent`,
   the RoE `ActiveDriver`) targets **web + api** only.

3. **The strongest agent isn't in the claimed list.** The web/api active pentester is the most
   capable, most externally-benchmarked agent in the tree (XBOW 85.6%, above published SOTA), and
   compliance is at 96% crosswalk corroboration — yet BOTH were omitted from the "cloud, code,
   identity" framing.

### Why the boundaries are where they are (the two questions this ADR must answer)

The empty cells are not uniformly "not built yet." Two of them are empty for a **structural** reason
that would not change with more engineering effort, and saying so is the difference between a roadmap
and an excuse.

#### B1 — Why the pentester stops at web/api: benign proof exists there and nowhere else

The pentester's whole grounding model (ADR 0006) is: the LLM proposes a `Demonstration`, and a
**machine-checkable success predicate** over the live response decides whether it is proven. The
model never upgrades a finding itself. That model requires a proof that is **benign by construction**
— `internal/pentest/active.go:18-28`: *"carries a unique canary, reads a benign signal, and never
writes, deletes, or exfiltrates"*, under an **absolute destructive ban** in the RoE (`roe.go:110`).

All five shipped playbooks are benign because the *observation* is separable from the *damage*:

| Playbook | What proves it | Damage done |
|---|---|---|
| `ssrfCanary` | the canary URL was fetched | none |
| `sqliBoolean` | true/false response differential | none — extracts nothing |
| `openRedirect` | the 30x `Location` header | none |
| `reflectedCanary` | the canary appears in the response | none |
| `idorRead` | victim-private marker readable by attacker session | read-only |

**On cloud and identity that separation does not exist.** Proving "this principal can escalate to
admin" means *actually attaching the policy*. Proving "this account can be taken over" means
*actually taking it over*. There is no canary for having become root — **the proof IS the mutation**.
So the RoE's destructive ban does not merely discourage cloud/identity exploitation, it forbids it,
and the read-only cloud agent (ADR 0002) is that ban honored rather than a missing feature.

This is a recognized boundary, not our invention: the literature's answer is **digital-twin /
risk-mitigated exploitation** (arXiv 2604.22427) — validate the destructive exploit against a
sandboxed replica of the customer's environment, never production. That is **ADR 0020 gap G1**,
currently *untouched, XL, and product-gated*: *"G1 lifts the ban only against a twin, never prod."*

> **So the honest sentence is:** the pentester covers web/api because those are the vulnerability
> classes whose exploitation can be *proven without causing harm*. Extending it to cloud/identity is
> gated on building a twin, not on writing more playbooks.

#### B2 — Why "code exploitation" is not a separate cell

Exploiting code requires a *running instance* of that code. Once it is running and reachable, it is a
web/api target and the web/api pentester is the tool. Without a running instance the only options are
static analysis (which is L1 — SAST/SCA/reachability, already built) or, again, a twin. So the empty
`code × pentester` cell is not a missing agent; it is the same G1 twin dependency wearing a different
label. Building a distinct "code exploitation agent" would duplicate `internal/pentest`.

#### B3 — Why identity posture is deterministic, and what that genuinely costs

Deterministic here is a **correctness choice, not a shortcut**. The identity questions are
*decidable*: "is MFA enforced on this admin?", "is this OAuth grant admin-scoped?", "did this
suspended account keep a role binding?" — each is answered by a field in an IdP API response. There
is no reasoning gap for a model to fill, so adding one would spend tokens and import hallucination
risk for **zero recall gain**, which is precisely what CLAUDE.md §13 and §10 forbid. The result is
measurable: **CISA SCuBA 0.993 detection recall / 0.990 on mandatory SHALL policies** (145/146
detectable, 100/101 SHALL, 119 rules execution-proven live — re-ran 2026-08-23; the 0.322 in the
roadmap and 0.753 in CLAUDE.md are both STALE), against an execution-proven answer key (every mapping
is asserted by building a violating snapshot and checking the real assessor fires). That is the
strongest external key in the repo, and it was earned with no LLM at all.

What deterministic rules genuinely *cannot* do is **open-ended correlation**. `identitythreat`'s
rules are fixed-window sequence detectors — `impossibleTravel`, `passwordSpray`, `spraySuccess`,
`mfaFatigue`, `concurrentSession`, `mfaRemovedThenAccess`. Each is a hand-written 1- or 2-step
pattern. An agent could chain an arbitrary N-step narrative across identity + SaaS + cloud ("MFA
removed → login from new ASN → OAuth grant to an unverified app → that app's token used against
Drive") and explain it. That is the real, narrow gap (**G-IDENTITY-AGENT**, L) — and note it is a
*narrative/correlation* gap, not a detection-coverage gap.

> **So the honest sentence is:** identity posture is deterministic because the questions are
> decidable and an LLM would add risk without adding recall. The gap an agent would close is
> multi-step incident narrative, which is worth stating plainly rather than hiding behind the word
> "deterministic".

## Competitive reality — do these gaps need closing? (researched 2026-08-23)

The gaps only matter if a competitor turns them into a lost deal. Two classes of rival exist, and they
answer the question differently.

### The autonomous-pentest incumbents DO exploit cloud + identity in production

| Competitor | What they claim (verified via their 2026 material) | Where it hits our matrix |
|---|---|---|
| **Horizon3 NodeZero** | "Safely executes attacks against Active Directory and cloud identity — harvests credentials, escalates privilege, moves laterally, in PRODUCTION." First AI to fully solve GOAD (Game of Active Directory). **Just expanded into web-app pentesting (2026-07)** — our strongest lane. 5,200+ orgs. | Fills BOTH the cloud×pentester and identity×pentester cells we leave empty — and is now entering web/api, our lead. |
| **Pentera Cloud** | Agentless; "executes safe real-world exploits" of IAM privilege-escalation paths in production, with an auditor-followable replay trail. | Fills cloud×pentester with the exact "prove by exploiting" claim we said was structurally impossible. |
| **XM Cyber** | Safely exploits weaknesses to produce "empirical evidence of exploitability", entirely virtual so production is untouched. | Fills cloud/identity×pentester via the simulation route. |

**This forces a correction to B1 above.** B1 said cloud/identity exploitation is impossible without
damage because "the proof IS the mutation." That is only true for *literal* exploitation. The
incumbents prove exploitability three OTHER ways that are benign, and we ship NONE of them:

1. **Provider-authoritative dry-run.** AWS `SimulatePrincipalPolicy`, GCP `testIamPermissions`,
   Azure `checkAccess` — the cloud provider itself answers "would this action be allowed?" WITHOUT
   performing it. This is a benign, authoritative proof of privilege-escalation reachability, and
   `grep` confirms **we call none of them** (`live.go` only re-reads config). This is the single
   highest-leverage missing primitive: it upgrades our cloud agent from "config-possible" (what a
   policy permits, on paper) to "provider-confirmed AUTHORIZATION" (what AWS itself says it would
   authorize — see C1: that is not the same as exploitable) — the exact ADR-0002 ladder rung we defined and never built.
2. **Digital-twin exploitation.** Replay the customer's snapshot into a sandbox, exploit destructively
   there, never touch prod (ADR 0020 G1). This is how you prove an identity takeover benignly.
3. **Non-destructive credential validation.** "This leaked cred still authenticates" is provable with
   one benign auth attempt (our `ssh_exec` already does exactly this for the web lane).

So B1's honest form is narrower than first written: **literal** destructive exploitation is banned,
but **proof of exploitability** on cloud/identity is achievable benignly and the incumbents ship it.
We do not. That is a real capability gap, not a structural impossibility.

### The compliance/GRC incumbents do NOT pentest — and that is our edge, kept

Vanta, Drata, Sprinto, Cynomi surface posture and hand a human a ticket; none prove exploitation.
Our web/api pentester + grounded cloud engineer + signed evidence already lead them. No gap to close
here — the risk is the OPPOSITE (spending effort chasing pentest incumbents and losing the
operating-model moat the GRC buyers pay for).

### Verdict on "do we need the missing capabilities?"

| Cell | Competitor pressure | Need it? |
|---|---|---|
| cloud × pentester (exploitability PROOF) | **High** — NodeZero/Pentera/XM all ship it | **Yes** — via dry-run + twin, NOT literal mutation |
| identity × pentester | **High** — NodeZero solved GOAD | **Yes, but gated** — via twin; high blast radius |
| identity × engineer (agent) | Low — detection already 0.993 | **No agent needed for detection**; only for multi-step narrative (nice-to-have) |
| code × engineer depth (G1 ADR 0013) | Medium — Snyk Agent Fix shipped | **Yes** — but it is depth, not a missing cell |
| web/api × pentester | We LEAD; NodeZero entering | **Defend** — publish the XBOW 85.6% headline |

The uncomfortable finding: we told ourselves cloud/identity exploitation was structurally out of
scope, and three well-funded incumbents are winning deals by proving it benignly. The focus decision
(cloud DEFENSE + web/api OFFENSE + compliance) is still coherent, but "cloud offense is impossible"
was wrong — it is *unbuilt*, and now competitively load-bearing.

## External review corrections (2026-08-23)

An independent review of this ADR and the P1 scaffold raised six corrections. Five are accepted and
folded in below; the code defects are already fixed on this branch. Recording them because the two
code findings are exactly the failure mode this ADR exists to police, authored by the ADR itself.

### C1 — "provider-confirmed exploitable" was an overclaim (ACCEPTED, fixed)
A policy-simulator ALLOW confirms **authorization** for one (principal, action, resource, context)
tuple at one moment. It does NOT prove exploitability, which additionally needs network reachability,
credential acquisition, session context we did not supply (MFA / session tags / ExternalId / source-IP
conditions), resource policies the simulator does not auto-retrieve, policy types it does not support,
role-chaining and session-policy behaviour, service-side validation, and the remaining actions of a
multi-step workflow. AWS states plainly that simulation can differ from live behaviour
([IAM policy simulator docs](https://docs.aws.amazon.com/IAM/latest/UserGuide/access_policies_testing-policies.html)).
The rung is renamed throughout, and the tool now disclaims exploitability in the same sentence it
reports an ALLOW.

### C2 — one allowed hop cannot prove a whole path (ACCEPTED, fixed)
The first scaffold stamped `Issue.ProviderConfirmed` if **any** hop returned ALLOW — so a five-hop
path could read as provider-backed on one allowed `iam:PassRole`. Now `pathAuthorizationStatus`
requires **every authorization-requiring hop** to be confirmed, and `Issue.AuthorizationCoverage`
carries `confirmed/required` so a PARTIAL proof stays visible instead of collapsing to a bare false.
Network-reach hops are excluded from the denominator (a network fact is the *next* rung, not this
one) rather than counted as authorized. Pinned by a mutation-verified regression test.

### C3 — the verification ladder is now explicit (ACCEPTED)
```
config_possible → provider_authorization_confirmed → runtime_preconditions_validated
                → twin_exploited → production_proven
```
P1 implements exactly the second rung and must never announce a higher one. A DENY is authoritative
for that tuple and time only — it does not prove alternative paths to the same target are closed.

### C4 — proof freshness / re-validation (ACCEPTED → P1c)
A provider result is point-in-time; IAM, trust policies, SCPs and OIDC conditions change. Every
persisted proof must carry snapshot hash, provider-result timestamp, request-context hash, a coverage
statement, and an expiry/revalidation trigger invalidating it on relevant config drift. Otherwise a
customer reads days-old "confirmed" evidence as current.

### C5 — P2 credential validation is not an S-sized extension (ACCEPTED, re-sized S→M+)
A benign auth attempt is still an **active authentication event**. It needs: customer-owned in-scope
identities only; never third-party or unverified leaked credentials; explicit authorization separate
from scan consent; lockout-safe rate limits; audit evidence and customer-visible disclosure; a proven
credential→account mapping before testing. `sts:GetCallerIdentity` establishes credential *liveness*
only — not the downstream privilege path.

### C6 — P3 twin optimism (ACCEPTED, re-scoped)
`awsinventory` builds an attack GRAPH; it does not generate a faithful Terraform replica of IAM
policies and trust conditions, SCPs/boundaries/session behaviour, OIDC federation, Okta policy,
resource policies, KMS, network endpoint policies, secrets, or runtime state. "Replay a customer
snapshot into a twin" is withdrawn as a near-term promise. Lab-first instead:
`known lab topology → controlled Terraform fixture → snapshot/graph ingestion → safe destructive proof
→ fidelity comparison`. Customer-specific replicas only after that.

### C7 — P4a was STALE (ACCEPTED, corrected)
This ADR said "consolidate the `codeagent` on another branch." That is wrong: the code specialist is
already present and wired — `internal/codeagent`, `internal/platformapi/codeinvestigate.go`,
`codesweep.go`, and `autofix.go` (which routes to `codeagent.ProposePatch`, "execution-verified in
tsbench cvepatch"). The residual gap is narrower: code graph / dependency / taint depth, a
production-quality verifier integration, a neutral execution-verified benchmark result, and a measured
agent lift over the deterministic substrate. ADR 0013's "design only — not built" needs the same fix.

### Follow-up corrections (2026-08-23, second pass)

A re-read of the merged P1 code against this document found three more defects — all the shape this
ADR exists to police, and all authored by it. Fixed on this branch.

**C8 — C1 was applied to one tool of two.** The exploitability disclaimer landed on
`check_reachable`'s result text but not on the `resolve_access` CATALOG description, which still read
`ALLOW=confirmed exploitable`. That is the more frequently called tool, and a catalog description is
the sentence the model consults when deciding what to record — so the correction recorded above as
applied "throughout" was still live in the highest-leverage text in the system. The guard now checks
every tool description, because fixing the instance is what let it survive the first time.

**C9 — provider DENIALS were discarded.** The probe map stored only ALLOWs, and the tool instructed
the model "DENY = do not record it". An authoritative provider refusal is the strongest negative
evidence this system can obtain about a move, and it was computed and dropped — collapsing "we asked
the provider and it said no" into "we never asked", the one distinction §10 exists to preserve. It
also made provider coverage unreportable and left P1d unscoreable: a simulator adapter cannot be
benchmarked while half its outcome space is discarded. Every verdict is now recorded and
`Report.Probes` carries tested/allowed/denied/unknown with per-move records and the prober's own
`Coverage()` line — nil when no prober was wired, so "we did not look" never renders as a clean
account. This partly discharges the **provider coverage disclosure** gap category below.

**C10 — "blast radius: none" was wrong, and the loop was unbounded.** Read-only is not
side-effect-free: every simulate call writes an event into the CUSTOMER's audit trail and consumes a
rate-limited quota. The tool called the provider afresh for every question, including already-answered
ones, with no ceiling — and a throttle answers UNKNOWN, degrading proof quality exactly when coverage
looks thinnest. Authoritative answers are now reused within a run; UNKNOWN is deliberately NOT cached
(freezing a transient throttle would make a temporary failure permanent); `DefaultProbeBudget` caps
live calls; and an exhausted budget is reported as NOT TESTED, never as anything the provider said.
The Status table's "none" for P1 should read *read-only, but it writes to the customer's audit trail
and spends their quota*.

**Also fixed:** the agent's `ProviderConfirmed` / `AuthorizationCoverage` had **no consumer outside
`internal/cloudagent`** — dropped when an Issue became a stored Finding, so nothing downstream (store,
issues, incidents, GRC, UI) could tell a provider-confirmed path from a config-possible one, and P1's
customer-visible value was zero. The finding now carries both, and its description states which rung
it stands on: confirmed, PARTIAL with its real hop coverage, or config-possible — three renderings
that must stay distinguishable, since rendering any two alike is how an unproven claim acquires the
authority of a confirmed one. Both the probe and `check_live` also ran on `context.Background()`, so a
scan timeout could not interrupt a live cloud call (§15); they now take the caller's context.

**Still open from the same re-read:** identity gets no proof rung anywhere in P0–P5 — Okta appears
once in this document, inside a list of things the twin cannot replicate; threat intelligence is
absent from this ADR entirely, and cloud attack paths carry no MITRE ATT&CK attribution while every
L1 finding does (`grep` over `cloudagent`/`cloudengine`/`cloudinvestigate` → no `MITRETechniques`);
and the customer feedback loop has no case source for a disputed path or proof, so P1's output cannot
enter `tenanteval`. The last item on that list — `cloudIssueToFinding` stamping
`VerificationVerified` on every agent path regardless of rung — is promoted to **C12** below, because
its consumers turned out to be the VAPT report and the customer-facing urgency line.

### Third pass (2026-08-23) — executed, not read

The first two passes were re-reads. This one RAN the code: three probes compiled against the tree and
each failed, and the rest are `grep`-confirmed absences of a caller. The distinction matters because
every finding below is a thing the documents already described correctly at the level of intent — the
defect is one layer down, in what the wiring actually does with it.

**C11 — the P1 ladder was already built, and P1 built a second one.** `internal/cloudengine/live.go`
implements `Analyzer` + `LiveValidator`: rung 2 `iam:SimulatePrincipalPolicy`, rung 3 passive network
reachability (`ec2:DescribeNetworkInsightsAnalyses`), rung 4 a benign `sts:GetCallerIdentity` probe,
rung 5 never auto-run and queued to `Pending` for a human — evaluated PER EDGE, budget-bounded, every
call gated through `cloudsafety.Guard`, whose read-only allowlist already contains `"Simulate"`. That
is P1 and P2 together, plus the runtime-preconditions rung C3 named and no P-item proposed. It is
entirely dormant: `NewLiveValidator` has no non-test constructor, `cloudsafety.NewGuard` has no
non-test caller, and `Analyzer` has exactly one implementation, a mock in `live_test.go`. This ADR
mentions `cloudengine` once — in P5, about LLM wire protocols. So the highest-leverage item in the
plan was scoped as a subsystem to write when it is a subsystem to WIRE, and the work now carries a
decision that did not exist before: **which of the two ladders survives.** They must not both ship —
two implementations of "the provider said ALLOW" with different semantics is how a rung comes to mean
different things on different screens.

**C11a — the ladder decision, made (P1a).** C11 said the work carried a decision that did not exist
before: which of the two ladders survives. **The `cloudagent` / `cloudprobe` seam survives; the
`cloudengine` one is superseded.** Not because it is newer — the older one is richer, covering rungs
3 and 4 that nothing else does — but because its INTERFACE cannot express the call:

- `Analyzer.PermActive(principal, action)` has **no resource parameter**, and passes the graph EDGE
  KIND as the action (`string(e.Kind)` — "assume_role", "privesc"). `SimulatePrincipalPolicy` needs a
  real IAM action and `ResourceArns`. The tuple the provider evaluates cannot be built from it.
- It returns `(bool, error)`, so there is **no UNKNOWN**. `guarded()` maps an error to false and
  renders it "not reachable / not active" — a throttle, an expired session or a role without
  `iam:SimulatePrincipalPolicy` would silently close every path it touched. That is C9 and C10 as a
  type signature: the strongest negative evidence and the absence of evidence share one value.

`cloudprobe.Decision` carries `Allowed`/`Known`/`Why` over the real `(principal, action, resource)`
tuple, which is why it is the one that can be wired honestly. What `cloudengine` had that the survivor
does not is worth naming rather than losing: `cloudsafety.Guard` (read-only allowlist + live-call
budget, and `NewGuard` has no non-test caller either), plus rung 3 (passive network reachability) and
rung 4 (a benign `sts:GetCallerIdentity` probe). Rung 3 is the "runtime preconditions validated" rung
C3 defines and no P-item proposes; rung 4 is most of P2. Both are now follow-ons against the surviving
seam rather than a second implementation.

**C12 — every cloud agent path is stamped `verified`, and two consumers render that as proof.** The
second pass recorded the stamp (`cloudinvestigate.go:232`) as still-open. Its blast radius was not
recorded, and it is where the harm is. Executed:

```
Explain(cloudagent finding, rung=config_possible) →
  urgency = "now"
  because = "we proved it is exploitable on your system, not just possible"
```

`explain.go` already carries the guard for exactly this overstatement — an `assessorTools` allowlist
whose comment says conflating an assessor's certainty with a pentester's proof "put *Fix today — we
proved it is exploitable* on a Vercel setting nobody had attacked". `cloudagent` is not in the set.
The second consumer is worse because it leaves the building: `grc/vapt.go` `isVerified` counts the
same finding as **tool-confirmed (corroborated or re-verified)** in the VAPT report a customer hands
an auditor. C1 corrected the sentences that DESCRIBE the rung; the two surfaces that render a VERDICT
were untouched, which is C8's lesson repeating one layer out. The tree already contains the right
answer, written by the sibling: `codeinvestigate.go:285` refuses `VerificationVerified` for the code
agent and explains why in eleven lines. The reasoning exists; it was applied to one agent of two.

**C13 — the cloud cell cited our own number where the neutral key it names says 64.5%.** The matrix
brackets `[IAM-Vuln, CloudGoat]` as the cloud cell's answer key and then printed "16/16 privesc
primitives · agent 100% recall" — both in-house. BishopFox IAM-Vulnerable scores 64.5% and Rhino's
GCP catalogue 65.2%, and NEITHER number appeared anywhere in this document (`grep -c` → 0) while both
are registered in `claimcheck`. Web/api and compliance cite neutral numbers in the same grid. So the
one cell where the in-house and neutral keys disagree by 35 points is the one that showed the
in-house figure, unlabelled — §14.2 rule 5 failing inside the document that invokes it. Fixed in the
matrix above: the neutral numbers lead, the in-house ones are parenthesised and marked as ours.

**C14 — `code × pentester` is N/A, not EMPTY.** B2 already argues it correctly: exploiting code needs
a running instance, and a running instance IS the web/api column. Rendering that conclusion as EMPTY
in the grid manufactures a gap the ADR's own reasoning says does not exist, and a future session
reading only the picture would go build a duplicate of `internal/pentest`. Marked N/A.

**C15 — the fix half is unmeasured in every cell.** The engineer column is defined "defense: find +
fix". Every number in the grid, and all six claims in `claimcheck.Registry()`, measure FIND.
`tsbench defense` and `tsbench defense-xbow` exist, and CLAUDE.md §14 names remediation-capture as
their hero metric — "the defensive XBOW-clean hero metric", execution-verified through the same
`retest.Verify` the product uses. Neither has ever produced a recorded number. This is not a build:
it is a run, and until it happens "AI Security Engineer" is measured on half of its own definition.

**C16 — a cell can be BUILT and not MONITORED, and this GATES P1.** `runner.RescanTenant` has exactly
four continuous producers (`runner.go:352,359,364,369`: asset scans, SaaS posture, OSINT, cloud
drift). The cloud engineer, the code engineer, `codesweep`, `ghoidc`/`gcpwif`/`samltrust`, TPRM,
device posture, `dataplatform` and the identity ITDR ingest are all ONE-SHOT — nothing re-derives
them on a pass. `detect.Reconcile` and `retest.Verify` then reason from their absence. Both probes
executed, both fail:

```
incident status after 3 routine passes: resolved (absent=2)
fix verification:                       fixed — "1 of 1 confirmed fixed in re-scan"
```

The first: the cloud engineer's own attack-path incident resolves itself, on a tenant whose only other
asset scans clean, with nobody having fixed anything. The second is worse — `FixStatusFixed` is
TERMINAL, so a remediation against a cloud path is permanently marked confirmed by a pass that never
ran the agent. `runner.go:379` names the shape ("the ingest-incident-survives-a-scan-pass case is a
documented follow-on") but frames it as an ingest edge case, so nobody connected it to the flagship
agent. This is the same absence-as-evidence failure the three degraded-pass guards exist to prevent,
arriving through a door those guards do not watch: the pass is not degraded, it is COMPLETE — it just
never asked the agent.

**It is a prerequisite for P1, not a parallel item.** P1c worries a provider proof will go STALE.
C16 means it goes AWAY: a `provider_authorization_confirmed` path is stored as a finding, nothing
re-derives it, and two passes later its incident is resolved and any remediation against it is
terminally "fixed". Shipping P1 before C16 spends a live provider call to produce evidence the next
monitoring pass deletes.

**C17 — the guards and this document were left stale by their own fixes.** `claimcheck`'s package
comment names four headline claims — SCuBA, XBOW, SAST, "96% crosswalk corroboration" — and the
registry holds six claims, none of them the crosswalk. The guard written to stop headline drift does
not cover a quarter of the headlines it names. Same shape twice in this ADR: C10 states the Status
table's "blast radius: none" for P1 "should read *read-only, but it writes to the customer's audit
trail and spends their quota*" and the table was not edited; C7 corrected P4a and the P4a Status row
still said "consolidate other-branch `codeagent`". Both corrected below. Adjacent doc drift found the
same way: CLAUDE.md still says `internal/estategraph` has no consumer ("the substrate ships first,
deliberately") — it now has seven, including `cloudagent.Context.Estate`.

**C18 — the grid's row set is smaller than the product's asset set.** Five rows against seven focus
assets: `container_image`, `ip_address` and `domain` have no row in either column. And there is no
`ai_application` row at all, though ADR 0012 fixed the approach, the **garak wrapper is built and
registered on both the host and sandbox sides**, and `ctoreadiness/items.go:44` states honestly that
nothing can be pointed at it because `pkg/types` has no such asset type. A product named *AI*
Security Engineer whose coverage matrix has no row for testing the customer's own AI application is
an omission worth stating, particularly as it is the cheapest new row in the document: the tool
already exists and is unreachable.

### Gap categories added
| Gap | Why it matters |
|---|---|
| Full-path proof semantics | Stops a multi-hop path reading as confirmed on one allowed action (C2) |
| Proof lifecycle / freshness | Stops stale authorization evidence being read as current (C4) |
| Provider coverage disclosure | A simulator error, missing policy, unsupported service or absent context must become `unknown`, never a clean result |
| Cross-surface CI identity proof | GitHub OIDC / GCP WIF trust-condition → provider authorization → target permission is MORE differentiated than generic IAM simulation |
| Proof persistence | Provider results need immutable evidence, ledger linkage, and report/UI representation |
| Controlled live benchmark | P1 needs a deployed test account with real simulator outcomes, not only fake-simulator tests |
| Consent boundary for credential checks | P2 is an active authentication event (C5) |
| Code runtime beyond web/API | Workers, CLIs, libraries, CI pipelines and supply-chain execution are real runtimes; "code exploitation == web/api" is usually-but-not-always true |
| Capability measurement | ADR 0020's benchmark-headroom and neutral repair-score gaps are prerequisites for any "best-in-breed" claim |
| **Proof CONTINUITY** (C16) | A cell can be built and not monitored. Absence-as-evidence resolves the incidents and terminally confirms the fixes of every one-shot producer — including the cloud engineer. **Gates P1**: proof the next pass deletes is worth nothing |
| **Rung-faithful verification status** (C12) | `VerificationStatus` is the field the VAPT report and the urgency line read. Stamping `verified` on every rung hands a config-possible path the authority of an exploited one, in the two places a customer sees |
| **The FIX half of "find + fix"** (C15) | Every measured number is a detection number. `tsbench defense`/`defense-xbow` define the metric and have never been run to a recorded value |
| **Neutral-key discipline inside the grid** (C13) | A cell must print its neutral key's score or say it has none. Printing the in-house figure under a neutral bracket is §14.2 rule 5 failing inside the document that cites it |
| **Row set vs asset set** (C18) | `container_image`, `ip_address`, `domain` have no row; `ai_application` has neither row nor asset type, though garak is built and registered on both sides |

## Decision — the proposal

Close the two cells the incumbents made load-bearing, using the BENIGN proof methods (dry-run + twin),
never literal destructive mutation. Do it as a ladder of increasing blast radius, gated so each rung
ships value before the next is authorized. The focus triad (cloud defense · web/api offense ·
compliance) is unchanged; this ADDS an offensive proof capability to the cloud engineer rather than
a new headline product.

### P0 — Fix the naming NOW (0 code, ships today)
The pitch claims six cells and delivers three; it omits web/api offense (85.6% XBOW, above SOTA) and
compliance (96% crosswalk). Retire "AI pentester for cloud/code/identity." Ship:
> *"An AI pentester that proves web & API vulnerabilities by exploiting them (85.6% XBOW, above
> published SOTA); an AI security engineer that finds and fixes cross-surface attack paths across
> cloud and code; deterministic identity & SaaS posture at SCuBA 0.993 with no LLM. Cloud/identity
> exploitation-PROOF is on the roadmap via provider dry-run + digital twin."*
Every claim in that sentence is checkable in this tree today. **Do this first, regardless of the rest.**

### P1 — Provider-authoritative dry-run (THE unlock; S–M; highest leverage)
Add one read-only, benign primitive to the cloud engineer: ask the provider "would this action be
allowed?" without performing it.
- **AWS:** `iam:SimulatePrincipalPolicy` / `SimulateCustomPolicy`
- **GCP:** `iam.permissions.testIamPermissions`
- **Azure:** `Microsoft.Authorization/checkAccess`
- **Wiring:** a new `LiveReader`-sibling `ExploitProber` on `cloudagent.Context` (read-only, isolated
  in its own SDK package like the `*remediate` packages so core stays SDK-free). A new agent tool
  `check_reachable(principal, action, resource)` returns the provider's own allow/deny. `validatePath`
  gains a rung: a recorded issue may cite `provider_confirmed` when the simulate call said ALLOW.
- **Grounding (§10):** the PROVIDER is the oracle, not the LLM — zero new FP surface. A deny is
  authoritative (the path is closed); an error/unsupported is `unknown`, never "safe."
- **Why first:** it is benign by construction (no mutation, no twin needed), it is the exact ADR-0002
  "config-possible → provider-confirmed authorization" rung we defined and skipped, and it directly
  answers Pentera's "safe real-world exploit of IAM privesc." Ships the cloud×pentester cell at the
  "proven reachable" tier without ever touching customer state.

### P2 — Non-destructive credential/identity validation (S; reuses web machinery)
"This leaked credential still authenticates" and "this token still grants admin scope" are provable
with ONE benign auth attempt — exactly what `webagent/ssh_exec` already does for the web lane. Extend
the same pattern to cloud/identity creds surfaced by OSINT/code-leak: attempt an auth (STS
`GetCallerIdentity`, a Graph `/me` call), read the identity back, mutate NOTHING. Grounded: the auth
succeeds or it doesn't. Partially fills identity×pentester at the "credential live" tier.

### P3 — Digital-twin exploitation (XL; product-gated; the full unlock — promote ADR 0020 G1)
For the proofs P1/P2 can't reach (an actual privilege-escalation execution, an actual account
takeover), replay the customer's pinned snapshot into an ephemeral sandbox and exploit DESTRUCTIVELY
there. `awsinventory` + Terraform already reconstruct the cloud graph; the twin is IaC replay + a
`twin-active` RoE mode that lifts the destructive ban ONLY against the replica, never prod. This is
ADR 0020 G1, currently untouched/XL/product-gated. It is the only path to literal cloud/identity
exploitation and it fully fills both empty pentester cells — but it is a real infrastructure
commitment (provision, tear down, cost), so it stays gated on a product decision. **Do not start P3
before P1 ships and earns the pull.**

### P4 — Code-depth specialist (XL; ADR 0013; depth not a cell) and the identity narrative agent (L)
- **Code depth (G1, ADR 0013):** the SAST→agent gap; Snyk Agent Fix shipped this shape, so we follow
  not lead. Consolidate the `codeagent` on the other branch, don't rebuild.
- **Identity narrative agent (G-IDENTITY-AGENT):** detection is already 0.993 with no LLM, so an agent
  buys only multi-step incident NARRATIVE ("MFA removed → new-ASN login → OAuth grant → token hits
  Drive"). Real but low-pressure; do it only after P1–P3, and only on `agentloop` + the new
  `llmclient` (P5), never a fork.

### P5 — Extract `internal/llmclient` (S; enabler; independent lane)
`internal/l2/{anthropic,openai}.go` and `internal/cloudengine/{anthropic,openai,gemini}.go` duplicate
the wire protocol. Extract transport + wire types into one package (each stack keeps its own
higher-level `Generate` shape — they differ). Unblocks every new agent (P4) cheaply. Can run in
parallel with P1.

### Sequencing (revised again after the third pass)

The change from the previous sequence is a tier ADDED IN FRONT, and the reason is not tidiness: R2
(C16) is a hard prerequisite for P1, because a provider proof that the next monitoring pass resolves
is a live cloud call spent on evidence we delete. Everything in Sprint 0 REPAIRS a capability the
tree already has, which per §0 outranks adding one — the value at risk is the three best-in-breed
claims we can already make, not a cell we cannot.

```
NOW      P0   correct external positioning AND this ADR's status (0 code, time-sensitive:
              NodeZero entered web-app pentesting, the lane we lead and do not advertise)

Sprint 0 — REPAIR WHAT IS BUILT (blocks P1; every item protects an existing claim)
         R1   rung-faithful VerificationStatus (C12). cloudIssueToFinding stops stamping
              `verified` below the provider-confirmed rung; `explain.assessorTools` and
              `grc/vapt.isVerified` stop reading a config-possible path as proof.
              Copy codeinvestigate.go:285 — the sibling already made this call correctly.
         R2   proof continuity (C16). Either re-derive the one-shot producers on a pass, or
              exempt their keys from `detect.Reconcile`'s resolve and `retest.Verify`'s
              confirm. The second is smaller and honest: an agent surface nothing re-ran is
              not evidence of absence. Pin with the two probes from C16 as regression tests.
         R3   measurement integrity. Register the 96% crosswalk claim in `claimcheck` (C17);
              run `tsbench defense` + `defense-xbow` to a RECORDED number and register it,
              closing the fix axis (C15); keep the neutral figures in the grid (C13, done).

Sprint 1 — CLOUD PROOF (P1, re-scoped by C11)
         P1a  DECIDE which ladder survives, then write ONE live `cloudengine.Analyzer`
              (3 methods, AWS SDK, its own package like the *remediate ones). This yields
              rungs 2 AND 3 AND 4 together, not P1's rung 2 alone — the subsystem, the
              Guard, the budget and the per-edge semantics are already written and tested.
         P1b  full-path AuthorizationProofPlan semantics (per-edge RequiredCheck,
              partial/unknown states)  ← the every-hop rule is in; the plan struct is next
         P1c  persist evidence: snapshot hash, timestamps, context hash, coverage, expiry
         P1d  controlled AWS integration benchmark (real simulator outcomes, not the fake)
         P5   llmclient extraction (independent lane; no customer value, pure enabler)

Sprint 2 — CI-IDENTITY PROOF (promoted: this is the MOAT item)
              GitHub OIDC / GCP WIF / SAML trust condition → provider authorization →
              target permission. This ADR already says it is more differentiated than
              generic IAM simulation and then sequenced it behind everything; ghoidc,
              gcpwif and samltrust exist, so on top of P1a it is small. "This public
              repository can assume this production role, and the provider agrees" is a
              sentence the incumbents' generic IAM simulation does not produce.

Decide   P2   customer-AUTHORIZED credential liveness validation (M+, consent-gated).
              The ONLY identity proof rung in the whole plan, and rung 4 is already
              specified in cloudengine/live.go.
         AIA  the `ai_application` asset type (C18) — cheapest new row: garak is built,
              registered host+sandbox, and unreachable for want of a types.AssetType.
         P3   lab-first twin execution venue (NOT customer-snapshot replay)

Later    identity multi-step narrative agent · code graph/taint depth (P4a, already wired)
              · MITRE attribution + threat intel on cloud paths · a tenanteval case source
              for a disputed path or proof
```
The capability worth building is not generic cloud pentesting. It is **evidence-backed,
provider-validated cloud and CI identity AUTHORIZATION-path proof, with explicit uncertainty and
continuous re-validation** — which extends the real advantage (deterministic graph + context +
verification) without claiming a policy simulator has compromised anything.

## What "5 of 5 surfaces" would actually require

The question this ADR gets asked is "what closes the matrix". Stating the target precisely is half the
answer, because two of the cells counted as gaps are not gaps and one of the surfaces has no neutral
key to be measured against.

**The target grid is five surfaces × two columns, with compliance as an OUTCOME riding on all five
rather than a sixth row.** Compliance has no offensive column (a control mapping cannot be exploited)
and no independent defensive one (it annotates the other five at emission, §8) — modelling it as a row
double-counts the same evidence.

A cell counts as CLOSED only when all four hold: the capability exists · a NEUTRAL key scores it ·
it is continuously monitored · and it reports the rung it actually stands on.

| Surface | Engineer (find + fix) | Pentester | What closing it needs |
|---|---|---|---|
| **web** | find: continuous, L1/L1.5, no agent · fix: built [#1397], **unmeasured** | **closed** — XBOW 85.6% > MAPTA 76.9% | Publish the offence number (P0). Engineer side needs the live WAVSEP number (§16, target-gated) and R3's fix number. |
| **api** | find: continuous · fix: built [#1397], **unmeasured** | capability real, **no neutral key** — `apiauthz` live-wired behind an operator env + per-request consent, plus `bola_probe`/`privesc_probe`; CLAUDE.md §14 says "None public — internal only" | Find a neutral corpus, or **state plainly that none exists**. Do not fill the cell with a fixture score — that is C13 again. |
| **cloud** | 64.5% neutral · fix unmeasured · one-shot | seam only | R1 + R2 → P1a (wire the dormant `Analyzer`) → P1c → P1d. |
| **code** | 46.54% SAST · `cvepatch` fix execution-verified but unscaled | **N/A by construction** (B2/C14) | Mark N/A, not empty. Then P4a depth + a scaled `cvepatch` number. |
| **identity** | SCuBA 0.993 detection · fix = account-suspend on three IdPs only | empty | P2 credential liveness with the C5 consent boundary. Detection needs nothing. |

Note what the FIX column does to the two cells that look finished: web and api offence are the
strongest work in the tree, and the engineer beside them has a fix path that shipped days ago and has
never been scored. That is C15 stated per-surface — the fix axis is unmeasured in **all five**, not
only in the weak cells.

Two honest consequences of that table. **First, seven of the ten cells are decided by work already in
the tree** — wiring `cloudengine.Analyzer`, registering numbers in `claimcheck`, running a benchmark
that exists, marking one cell N/A. Only P2, P3 and the api neutral key are genuinely new. **Second,
literal cloud/identity EXPLOITATION proof is P3 and nothing else.** P1 and P2 close those cells at the
authorization and credential-liveness rungs, which is real and sellable and is not what NodeZero and
Pentera claim. Saying "5 of 5" while P3 is unbuilt would be the same overclaim C1 corrected, moved up
to the level of the grid.

## Consequences

- **Positive:** the pitch matches the wiring; every best-in-breed claim is checkable in this tree; the
  deliberate non-gaps (read-only cloud) are auditable, not accidental; a future session cannot silently
  re-scope the product by picking up whichever gap looks closest to hand.
- **Negative:** the marketable surface shrinks from "six cells across three assets" to "three focus
  claims + honest capabilities." This is the focus decision's intended cost, restated.
- **Neutral:** the four real agents (cloud engineer, code engineer, web/api pentester, plus the L2
  Lead) were reviewed as well-engineered — grounding is structural, the loop terminates, the RoE gate
  is correct. The gaps here are coverage/naming, not quality.
- **Corrected by the third pass:** that last sentence was true of the agents and false of the seams
  around them. C11, C12 and C16 are not coverage or naming — they are a ladder built twice and wired
  never, a verification rung that reaches a customer-facing report as proof, and continuous monitoring
  that deletes the agents' own findings. The recurring shape across all three is the one CLAUDE.md
  keeps naming: **the capability was built and the wiring that makes it survive was not**, so the
  document describing it stayed accurate about intent while the product did something else. The
  practical consequence for this ADR is a Sprint 0 that adds no capability at all.

## Status of each item

| Item | Effort | Blast radius | Status |
|---|---|---|---|
| **P0** naming binding | 0 code | none | Proposed — **do now** |
| **R1** rung-faithful VerificationStatus | S | none | **Blocks P1** — the stamp reaches the VAPT report and the urgency line (C12) |
| **R2** proof continuity | S–M | none | **Blocks P1** — a proof the next pass resolves is worth nothing (C16) |
| **R3** measurement integrity | S | none | Registers the crosswalk claim; runs the fix benchmark to a number (C15, C17) |
| **P1** provider dry-run (`check_reachable`) | S–M — **wiring, not writing** (C11) | read-only, but each simulate call writes to the CUSTOMER's audit trail and spends their rate-limited quota (C10) | Seam built TWICE (`cloudagent` + the dormant `cloudengine` ladder), wired zero times. Blocked on R1+R2 |
| **P2** non-destructive cred validation | S | one benign auth attempt | Proposed — reuses `ssh_exec` pattern |
| **P3** digital twin (ADR 0020 G1) | XL | destructive, but only vs replica | Proposed — **product-gated**, do not start before P1 |
| **P4a** code depth (ADR 0013) | XL | none | Proposed — `codeagent` is ALREADY wired (C7); the residual is graph/taint depth + a scaled neutral number |
| **AIA** `ai_application` asset type | S | active-by-nature — RoE + consent + ownership (ADR 0012) | Proposed — garak is built and unreachable (C18) |
| **P4b** identity narrative agent | L | none | Proposed — after P1–P3, on `agentloop`+`llmclient` |
| **P5** `internal/llmclient` extract | S | none | Proposed — parallel lane, unblocks P4 |

**Competitor watch:** NodeZero entered web-app pentesting (2026-07) — our lead lane. Publishing the
XBOW 85.6% headline (P0) is now time-sensitive, not cosmetic.
