# Specialist roadmap — where we lead, where we don't, and what each gap costs

Companion to [security-engineer-tasks-benchmarks.md](security-engineer-tasks-benchmarks.md)
(the measurements) and CLAUDE.md §2.2.1 (the specialist taxonomy). That doc answers
*where do we stand*. This one records **the strategic focus decision** and **the size of
each gap**, so a future turn does not silently re-scope the product by picking up
whichever gap looks closest to hand.

---

## 1. The focus decision (2026-08-17)

> **Be best-in-breed in CLOUD + OFFENSE + COMPLIANCE. Everything else is deliberately
> not a headline claim.**

Rationale: those three are where we already have either a measured lead or a structural
advantage nobody else pairs, and together they are a coherent product — *find the
cross-surface attack path, prove it by exploitation, and produce the audit evidence*.
The other three specialists each require building an agent that a well-funded incumbent
has already shipped (AppSec) or an entire telemetry ingestion tier (SOC), or have no
neutral yardstick to be "best" against at all (EASM).

Three deep specialists beat six shallow ones. The failure mode this decision exists to
prevent is spreading across all six and leading in none.

### What this means concretely

| Decision | Consequence |
|---|---|
| **Cloud, offense, compliance are the claims.** | Marketing, benchmarks, and the launch gate lead with these. Each must have a *neutral* number or an explicit UNVERIFIED. |
| **AppSec / SOC / identity-SaaS / EASM stay CAPABILITIES, not claims.** | They ship, they are honest about depth, and they are never described as best-in-breed. The §2.2 table's "behind" rows are the intended state, not a backlog we are quietly failing to burn down. |
| **No new specialist without displacing one of the three.** | Per CLAUDE.md §2.2.1 rule 1, a new surface becomes a tool a specialist calls — not a seventh headline. |

---

## 2. Where the three focus areas actually stand

| Focus area | Neutral benchmark | Measured | Gap to "best in breed" |
|---|---|---|---|
| **Cloud** | IAM-Vulnerable (Bishop Fox) · CloudGoat (Rhino) | substrate **16/16** privesc primitives, cross-account + GCP/Azure chains; frontier-brain agent **100% recall, 0 invented** over the proxy (§2.4) | **Small.** Live 31-scenario Terraform deploy is the remaining depth item. |
| **Offense** | XBOW 104-challenge | **85.6%** (89/104); a frontier-brain agent verifies findings FP-free over the proxy (§2.4) | **Credibility.** Published research SOTA is MAPTA at **76.9%**; we are above it. |
| **Compliance** | OpenCRE (OWASP) · SCF · CSA CCM | **96%** crosswalk corroboration (48/50 CWEs) | **Small.** The SCF/CCM axis is unrun (needs an operator-supplied matrix export); OSCAL assessment-results is the next artifact. |

### 2.4 The agents, driven by a frontier brain over the proxy

Both focus agents are exercised end-to-end by pointing their standard LLM seam
(`LLM_BASE_URL`) at a file-relay proxy backed by a frontier model, so the run measures
the **product's** agent loop — its tools, its grounding, its scoring — with a capable
brain, not the deterministic substrate and not a hand-picked script. Latest runs:

Two COMPLETE scored suites now exist, each sweeping every distinct reasoning shape
plus a false-positive control, driven end to end by the frontier brain over the proxy:

**Cloud** — `cloudagent.TestAgentNeutralSuite`, **7/7**:

| Scenario | Shape | Result |
|---|---|---|
| single_hop_attach_user_policy | single-hop privesc | reached admin |
| passrole_lambda | passrole → compute | reached admin |
| multi_hop_assume_then_privesc | assume → privesc | reached admin |
| data_exfil_assume_then_read_pii | assume → read PII bucket | reached the PII crown jewel |
| cross_account_assume | acct 111 → acct 222 admin role | reached admin |
| fp_boundary_blocked | privesc finding, boundary blocks it | **declined — recorded nothing** |
| fp_scp_blocked | privesc finding, SCP blocks it | **declined — recorded nothing** |

**Offense** — `webagent.TestWebAgentNeutralSuite`, **4/4**:

| Scenario | Class | Result |
|---|---|---|
| open_redirect | `open_redirect` | recorded + **verified** (external_redirect, reproduced) |
| sqli_error_based | `sqli` | recorded + **verified** (sql_error, reproduced) |
| reflected_xss | `xss` | recorded + **verified** (reflected_input + js_executed in real Chrome) |
| safe_endpoint | seeded `sqli` on a safe route | **declined — recorded nothing** |

The negatives are the point of both suites: a recall-only agent that always "reaches
admin" / "confirms the seed" scores 100% on the positives and FAILS the FP-control. The
grounding guard was observed working live on every call — the cloud agent's `record_issue`
accepts a path only if it exists in the graph and ends at a crown jewel (and the two
effective-permission blocks made `detect_privesc` return "no move", so it declined); the
web agent's `record_finding` rejects any class whose deterministic indicator was not
produced (the safe endpoint fired no indicator, so it declined). The model proposes; the
framework disposes.

Both suites are CI-safe — they `t.Skip` unless `LLM_BASE_URL` is set — so they document
the run without breaking the deterministic suite (152 packages green).

Earlier per-scenario proxy runs (a prowler-grounded account scored vs the `cloudiam`
answer key: 100% recall, 0 invented; a single IAM-Vulnerable multi-hop; a live
open-redirect) are subsumed by these suites.

The honest asymmetry: all three are close, and the two things standing between us and a
defensible public claim on cloud + offense are the *same* thing — **a funded frontier
model key and one clean autonomous run each**. That is a purchasing decision, not an
engineering project, and it is the highest-leverage item on this page.

### 2.5 The cross-surface benchmark (the wedge, measured)

The product's wedge claim — *connect code + cloud, and one engineer finds the path across
them* — had no measurement. The per-specialist suites cannot supply one by construction:
the cloud suite seeds a cloud-only account, so re-running it would report the same 7/7
whether or not cross-surface traversal existed. **A cross-surface capability needs a
fixture with two surfaces in it.**

`internal/bench/crosssurface.go` (`TestCrossSurface_*`) is that fixture, and it measures
**substrates, not model wording** — so it is deterministic, needs no LLM, and runs in CI.

| substrate | internet → customer-PII bucket |
|---|---|
| cloud graph alone | **not found** |
| joined estate graph (cloud + code) | **found** |

**Lift: yes.** The scenario is built so the cloud-alone miss is *genuine*: `deploy-role`
can read the crown, and nothing in the account exposes it — no public compute runs as it,
no trust policy admits an outsider. **A cloud scanner is correct to report no path**; from
cloud data alone there isn't one. The path exists only because a long-lived key for that
role sits in a public repository, which is a fact on the *code* surface. Neither tool is
wrong — the estate is what makes the sentence sayable.

Two guards keep the number honest:

- **The isolation assertion.** If a change ever lets the cloud graph find this path alone,
  the test *fails* — because the fixture would have stopped being a two-surface test and
  the reported "lift" would be an artefact.
- **A no-lift control.** The same scorer, given an account that already exposes the crown
  itself, must report **no lift**. A benchmark that can only ever report success is not
  measuring anything.

**The second join (2026-08-18): web → cloud.** A second fixture asks a *different* question —
not "can the internet reach the crown" but **"what does this pentest target reach?"**, which is
what decides whether the AI pentester spends its budget on a login form fronting a PII warehouse
or one fronting a marketing page.

| substrate | answers "what does app.example.com reach?" |
|---|---|
| cloud graph alone | **not found** |
| joined estate (web + cloud) | **found** — regulated data, via instance → role → bucket |

The cloud graph cannot answer it *at all*, and not for want of an edge: **a hostname is not an
identifier a cloud account holds.** Only the inventory asserting "this DNS name is that resource"
makes the question answerable — so the join is grounded on that assertion, and a paired refusal
test proves a resource merely *named* after the host is never joined to it.

This was wired end to end: `LeadsForRoutes` and `Context.Leads` both already existed with tests,
and **nothing in production populated them** — zero non-test assignments, the same inert-wiring
shape as the access-key join. `runWebDiscovery` now derives leads from the tenant's estate, and
the test asserts they *arrived at the agent*, not that the code compiles.

**The third join (2026-08-18): identity × OSINT.** Three detectors already name the same person
and cannot hear each other — OSINT finds a credential in a stealer log, the identity posture finds
an admin with no MFA, SaaS posture finds who owns the org. `estategraph.Canonical` already maps an
email to one shared `principal:` id, so **two detectors naming alice@acme.com converge on one node
with no matching logic at all**; what was missing is that nothing turned those findings into nodes.
`estate::exposed-identity-no-mfa` reports the result: critical on an admin, high otherwise.

Each half alone is routine — a breached credential is one of thousands in a dump, a missing second
factor is a hygiene item. Together they are a working way in with no remaining step.

**This join deliberately gets NO benchmark fixture.** Its baseline would be "does any single
finding already say this?", which is trivially zero — a benchmark that can only report success,
which is precisely what the other two fixtures' controls exist to prevent. The honest measurement
here is the **refusal set**, all tested: half the evidence is not the claim (each half is already
its own detector's finding); one surface asserting both is not cross-surface; and a leaked API
token is a *machine* credential, never a person's password.

**The fourth join (2026-08-18): warehouse × cloud.** `FromWarehouse` was the last built-but-never-called
ingest — `composeEstate` passed `nil`, so `dataplatform` estates never reached the graph. A warehouse
grantee that is a GCP service account canonicalises into the shared `principal:` namespace and lands on
the very node the cloud inventory created, so *"this Snowflake table is read by an identity an attacker
can reach through cloud IAM"* becomes derivable. Neither side can say it alone: the warehouse assessment
has no view of cloud IAM, and a warehouse table is not a cloud resource at all.

**Honest limit, pinned as a test.** Nothing persists a grant snapshot, so the warehouse joins only at
the moment it is posted; an estate composed later has no warehouse in it. Detection therefore runs at
ingest, while the snapshot is in hand. `TestEstate_WarehouseIsNotInALaterComposedEstate` asserts the
gap and says to update the caveat and the roadmap together when persistence lands — so closing it is a
deliberate act rather than something a future reader assumes already happened.

**Making the joins reachable (2026-08-18).** Auditing my own work found the identity join was
effectively unreachable: cross-surface detection fired from only **two** ingest doors (cloud
inventory, warehouse), and the identity join's halves arrive through neither — so it only fired for
a tenant who happened to re-post a cloud inventory afterwards.

Two fixes, in order, because the first is a prerequisite for the second:

1. **Content-derived finding ids.** Detection was minting a fresh id per run, so re-running over an
   unchanged estate filed a *second copy* of the same fact — proved with a test that went 1 → 2
   before the fix. One cross-surface fact is one finding; otherwise "how many issues do I have"
   becomes a function of how often we looked. The id now derives from rule + endpoint, which is also
   what `detect.Reconcile` keys an incident on, so a finding and its incident stay in step.
2. **A pass-level hook** (`DetectEstateEachPass`, wired to `runner.Service.AfterPass`). It belongs
   there rather than at each ingest handler because a cross-surface fact needs *two* surfaces and the
   second can arrive through any of a dozen doors — or through a scan, which is not a door at all.
   Wiring doors one by one means the next door added silently does not join. The two inline ingests
   stay for immediate feedback; the hook is what guarantees the join is eventually found. Affordable
   unconditionally because the detections are deterministic and LLM-free — unlike the auto-review,
   there is no budget to gate.

**The boundary this surfaced.** The cloud agent can *see* a cross-surface path via
`estate_context` but cannot *record* one: `record_issue` grounds against the cloud graph.
That is the correct split — cross-surface paths are the deterministic estate detector's
output — but the generic refusal described it **wrongly**, telling the model to find a
public entry point that does not exist, which is an invitation to invent one. The refusal
now names the real boundary and says what to do instead
(`TestRecordIssue_EstateNodeRefusalNamesTheRealBoundary`), while an invented *cloud* id
still gets the ordinary grounding refusal.

---

## 3. Gap sizing (the roadmap)

Sizes are engineering effort at this codebase's granularity, not calendar time.
**S** ≈ a focused session · **M** ≈ a few days · **L** ≈ a week-plus · **XL** ≈ a project
with a design decision inside it. "Blocked on" names the real precondition, because
several of these are not effort-bound at all.

### 3.1 Focus-area work (do these)

| # | Item | Size | Status | Why it matters |
|---|---|---|---|---|
| F1 | **Offense complete run** — scored multi-class suite | **S** | **done via proxy (§2.4)** — 4/4, all positives verified, FP-control declined | A scored, CI-committed suite over distinct vuln classes + a false-positive control. The external XBOW 104 headline (vs MAPTA 76.9%) is the remaining marketing artifact, not a capability question. |
| F2 | **Cloud complete run** — scored neutral suite | **S** | **done via proxy (§2.4)** — 7/7, 5 shapes reached target, 2 FP-controls declined | Establishes the cloud claim on third-party ground truth (IAM-Vulnerable / Rhino), recall AND specificity. |
| F3 | **SCF / CSA CCM cross-check run** — the second and third compliance axes | **S** | needs an operator-supplied matrix export (SCF is CC BY-ND: parseable, not redistributable) | Parser + cross-check are already built and tested. A data-acquisition task. |
| F4 | **Live IAM-Vulnerable Terraform deploy** (31 scenarios) | **M** | AWS credentials + spend | Moves cloud from offline-transcribed to live-verified. Offline already covers the primitives. |
| F5 | **OSCAL assessment-results** (per-tenant findings-as-evidence) | **M** | **done** — `internal/grc/oscal_ar.go` + `GET /v1/compliance/oscal/assessment-results` | The FedRAMP-ingestible artifact; component-definition ships alongside it. |
| F6 | **Cross-account S3 data-access precision** | **S** | **done 2026-08-19** — see §3.3 | Closed the one known modelling gap in cross-account reasoning. It was over-approximating, not merely imprecise. |

### 3.2 Non-focus gaps (sized, deliberately deferred)

Recorded so the cost is known and nobody re-discovers it, and so a future turn does not
start one of these thinking it is small.

| # | Item | Size | Blocked on | Note |
|---|---|---|---|---|
| N1 | **AppSec patch agent** | **XL** | a product decision + likely a branch consolidation | Three ordered parts: (a) `Action.Patch` field — **S**, and today `PlanBackports` computes a relocated hunk with nowhere to put it; (b) connector `FetchFile`/`CommitFiles` — **M**; (c) the agentic propose→sandbox→test→re-scan loop — **L**. Snyk Agent Fix shipped this architecture in May 2026, so we would be following, not leading. **A `codeagent` with these pieces exists on another branch — consolidate, never rebuild.** Genuine head start: `retest.Verify` is already the verification oracle. |
| N2 | **SOC investigation agent** | **XL** | ~33 GB disk + a design decision | Needs a SIEM/log connector (Sentinel/Splunk/Elastic), an alert+entity graph, and a `query_logs` tool. We score **0 by construction** today — verified against the exported API, not assumed. Upside if ever taken: every competitor self-reports (Dropzone <1% FN, Prophet ~96% FP-reduction), so a neutral ExCyTIn-Bench number would be the only verified figure in that market. |
| N3 | **Identity/SaaS to SSPM parity** | **L** | Graph/Admin-SDK scopes; Google needs a design call | SCuBA **0.993** recall / **0.990** SHALL today (145/146 detectable, 100/101 SHALL — up from 0.322/0.426 when this row was written). DETECTION is no longer the gap: what remains is *fetch surface*, not logic — the rules exist and are execution-proven, but some of the state they read is not retrievable yet. M365 live fetch ships; **Google Workspace settings are not in the Directory API** — ScubaGoggles reconstructs them from Admin *Reports* change events, inferring state from the absence of a change, which is materially more FP-prone than reading a settings endpoint. That is a decision, not a port. |
| N4 | **EASM benchmark** | **M** | nothing — but it is *definitional* work | No neutral benchmark exists (analyst comparisons only). Options: subfinder/amass discovery-rate parity on an owned domain, or define one publicly as we did for the defense bench. Not worth doing while EASM is not a claim. |

### 3.3 The cross-account fix (2026-08-19)

`canReadBucket` passed `cloudiam.PolicySet{SameAccount: true}` **unconditionally**, so the
same-account union rule (identity policy OR bucket policy suffices) was applied to every bucket in
the estate. For a bucket in another account that is an over-approximation with teeth: a principal
whose identity policy allowed `s3:GetObject` was reported as having access even when the other
account's bucket policy granted it nothing — **a path AWS would deny**. On a product whose claim is
that no finding reaches a customer unverified, a fabricated cross-account route to someone else's
data is the worst shape of wrong.

`cloudiam.Authorize` already implemented both rules correctly; nothing could tell it which applied.
The reason is a genuine AWS asymmetry: an IAM ARN carries its account, but an S3 ARN
(`arn:aws:s3:::name`) **does not**, so bucket ownership cannot be derived and has to be reported.
`S3Bucket.OwnerAccount` now carries it, and `cloudiam.AccountOf` is exported so both sides parse
identity ARNs the same way.

Three cases, and the third is the interesting one:

| ownership | rule | why |
|---|---|---|
| known, same account | union | unchanged |
| known, cross account | both sides must allow | correct, and stricter |
| **unknown** | union, but marked **conditional** | dropping it loses real access on every estate that does not report ownership; asserting it fabricates |

The unknown case follows `PruneUnauthorized` and `PruneUnreachable`, where missing data never
prunes — the edge is kept for recall and carries a condition, which makes `Path.Conditional()` true
so nothing downstream presents it as proven impact (ADR 0002). The condition is stamped **only when
the missing ownership actually changes the answer**: if both policies allow, or neither does, who
owns the bucket is irrelevant and a condition would be noise.

Every fixture now declares bucket ownership. Three did not, and the evaluator correctly reported
their resource-policy-only grants as ambiguous — which is how the omission surfaced.

### 3.4 Housekeeping (done)

| Item | Status |
|---|---|
| **`cmd/tsbench` build break** | **Fixed 2026-08-17** — see §4. |

---

## 4. The tsbench fix (2026-08-17)

`cmd/tsbench` had not compiled in this tree, which took **every** benchmark lane with it —
the CLI could not be built at all, so no lane was runnable from the command line.

Cause: untracked work-in-progress from the defense-xbow campaign
(`cmd/tsbench/defensexbow*.go`) imports `internal/codeagent`, the LLM patch proposer,
which lives on a different branch and is **not present in this tree**.

Fix, chosen to destroy no work in progress and vendor nothing across branches:

- The three files that import `codeagent` are gated behind **`//go:build codeagent`** —
  the same build-tag convention already used in this directory (`//go:build integration`).
  They stay exactly where they are and compile with `go build -tags codeagent ./cmd/tsbench`
  once the package lands.
- `firstNonEmptyEnv` was **extracted** to an untagged `cmd/tsbench/env.go`, because it is
  also used by `discover.go` and `impact.go` — gating the file that defined it would have
  broken two other lanes.
- `defensexbow_disabled.go` supplies a `!codeagent` stub whose error names the missing
  package and the exact rebuild command. The subcommand **says why it is unavailable**
  rather than failing to link or, worse, silently reporting a zero.

**This unmasked two pre-existing failures** that the build error had been hiding:
`discover.go`'s tests point at `fixtures/discovery/` and `fixtures/discovery-scans/`,
which also live in the other worktree. Per this repo's own convention for out-of-band
corpora (WAVSEP, OWASP Benchmark), they now **skip loudly as UNVERIFIED** naming the
missing path — never a silent pass, and a *partial* corpus still fails, so a scenario
going missing remains a real regression.

Result: **152 packages green, zero failures** — the first fully green `go test ./...` in
this tree. Every non-defense-xbow lane is runnable again.

---

## 5. Review triggers

Revisit the §1 focus decision if any of these becomes true:

- **The agent runs move from per-scenario proxy to a scored full-suite pass.** The cloud +
  offense capability is proxy-verified (§2.4); the remaining step is running the whole
  benchmark suite under one driver and publishing the aggregate, which validates or
  falsifies the focus thesis with a single headline number per claim.
- **The ICP starts buying on AppSec autofix.** N1 stops being deferrable — the market,
  not the architecture, would be making that call.
- **A neutral AI-SOC leaderboard gains traction.** N2's upside changes from "differentiated
  bet" to "table stakes", because unverified vendor claims would stop being the norm.
- **`internal/codeagent` merges into this tree.** Drop the `codeagent` build tag, delete
  `defensexbow_disabled.go`, and re-run the defense-xbow lane — and reassess N1(a) since
  the `Action.Patch` work may already be done there.
