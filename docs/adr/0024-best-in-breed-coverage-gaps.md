# ADR 0024 — The best-in-breed coverage matrix: what "AI Security Engineer + AI Pentester for cloud, code, identity" actually covers, and the gaps

**Status:** Proposed — **gap accounting + a build proposal.** Records the honest state of the
(agent × asset) matrix, compares it to the autonomous-pentest incumbents (NodeZero / Pentera / XM
Cyber), and proposes a concrete, sequenced path to close the cells that are now competitively
load-bearing. Supersedes the earlier "accounting only" framing after competitor research
(2026-08-23) showed one of the "structural" boundaries was merely unbuilt.

**P1 implementation status (be exact):** *interface, agent tool, path-authorization semantics and
fake-tested wiring implemented; live AWS/GCP/Azure provider adapters, platform injection, persisted
proof evidence and a controlled live benchmark NOT implemented.* P1 is a seam, not yet a capability.
Do not describe it as shipped provider proof until P1a–P1d below are done.
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
                 │ 16/16 privesc primitives       │ exploitation. ADR 0002.            │
                 │ agent 100% recall, 0 invented  │ WHY: proof == the mutation (B1)    │
                 ├────────────────────────────────┼────────────────────────────────────┤
                 │ BUILT, depth gap open          │ EMPTY (collapses into web/api)     │
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

  CLAIMED (cloud/code/identity × 2)  : 2 of 6 cells built, 1 deliberate, 3 empty
  ACTUAL best-in-breed claims        : 3 — cloud defense, web/api offense, compliance
                                          (exactly the 2026-08-17 focus triad)
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

### Sequencing (revised after external review)
```
NOW      P0   correct external positioning AND this ADR's status
Sprint 1 P1a  AWS-only LIVE simulator adapter (SimulatePrincipalPolicy)
         P1b  full-path AuthorizationProofPlan semantics (per-edge RequiredCheck,
              partial/unknown states)  ← the every-hop rule is in; the plan struct is next
         P1c  persist evidence: snapshot hash, timestamps, context hash, coverage, expiry
         P1d  controlled AWS integration benchmark (real simulator outcomes, not the fake)
         P5   llmclient extraction (independent lane)
Sprint 2 CI-IDENTITY PROOF — GitHub OIDC / GCP WIF trust condition → provider authorization
              → target permission. More differentiated than generic IAM simulation, and it
              builds on ghoidc/gcpwif which already exist.
Decide   P2   customer-AUTHORIZED credential liveness validation (M+, consent-gated)
         P3   lab-first twin execution venue (NOT customer-snapshot replay)
Later    identity multi-step narrative agent · code graph/taint depth (P4a, already wired)
```
The capability worth building is not generic cloud pentesting. It is **evidence-backed,
provider-validated cloud and CI identity AUTHORIZATION-path proof, with explicit uncertainty and
continuous re-validation** — which extends the real advantage (deterministic graph + context +
verification) without claiming a policy simulator has compromised anything.

## Consequences

- **Positive:** the pitch matches the wiring; every best-in-breed claim is checkable in this tree; the
  deliberate non-gaps (read-only cloud) are auditable, not accidental; a future session cannot silently
  re-scope the product by picking up whichever gap looks closest to hand.
- **Negative:** the marketable surface shrinks from "six cells across three assets" to "three focus
  claims + honest capabilities." This is the focus decision's intended cost, restated.
- **Neutral:** the four real agents (cloud engineer, code engineer, web/api pentester, plus the L2
  Lead) were reviewed as well-engineered — grounding is structural, the loop terminates, the RoE gate
  is correct. The gaps here are coverage/naming, not quality.

## Status of each item

| Item | Effort | Blast radius | Status |
|---|---|---|---|
| **P0** naming binding | 0 code | none | Proposed — **do now** |
| **P1** provider dry-run (`check_reachable`) | S–M | none (read-only, provider is oracle) | Proposed — **the unlock**, not started |
| **P2** non-destructive cred validation | S | one benign auth attempt | Proposed — reuses `ssh_exec` pattern |
| **P3** digital twin (ADR 0020 G1) | XL | destructive, but only vs replica | Proposed — **product-gated**, do not start before P1 |
| **P4a** code depth (ADR 0013) | XL | none | Proposed — consolidate other-branch `codeagent` |
| **P4b** identity narrative agent | L | none | Proposed — after P1–P3, on `agentloop`+`llmclient` |
| **P5** `internal/llmclient` extract | S | none | Proposed — parallel lane, unblocks P4 |

**Competitor watch:** NodeZero entered web-app pentesting (2026-07) — our lead lane. Publishing the
XBOW 85.6% headline (P0) is now time-sensitive, not cosmetic.
