# The AI Security Engineer: job → measurable tasks → benchmarks

The product claim is "an AI security engineer." A claim like that is only
meaningful if it decomposes into the tasks a human security engineer actually
performs, and each task is measured against a **neutral, third-party**
benchmark. This document is that decomposition, the SOTA number for each task,
where we stand, and how we keep standing there.

**Rule of the road (§10 discipline applied to ourselves):** a task is "done"
only when a real benchmark run produced the number. An architectural argument
is not a score. Where we have no number, this document says so.

---

## 0. Self-assessment: how are we doing, and are we SOTA?

The 2025–26 finding is that agents **patch ~90% of localized bugs but discover
only ~13–34% end-to-end** — the bottleneck is *finding* the bug, not fixing it.
Our answer is architectural: **discovery is deterministic OSS + evidence-grounded
targeting (not an LLM search), so we don't inherit the 13%**, and the LLM is
spent on the tasks where agents already measure strong (triage, correlate,
remediate, verify), always grounded + HITL-gated.

**Did we fix discovery, and test it?** Yes — and the tests are what make it
credible, including a live one that caught a silent failure:

| Discovery improvement (this line of work) | Built | Tested | How |
|---|---|---|---|
| Threat-intel now DRIVES targeting (was annotation-only) | ✅ | ✅ | `internal/threatinformed`, 11 unit + 2 handler-wiring tests (ip + web) |
| KEV catalog product retained (was discarded) | ✅ | ✅ | parser test asserts vendor/product survive |
| Iterative escalation (observe→re-plan, was single-pass) | ✅ | ✅ | 3 tests: chains depth-2, round-cap, shared budget |
| Escalation grows surface from depth discovery | ✅ | ✅ | ffuf/kiterunner `DiscoveredURLs` fed to next round |
| api SQLi escalation (schemathesis 500 → sqlmap) | ✅ | ✅✅ | 8 unit tests **+ LIVE on VAmPI**: caught that it *silently never fired*, fixed 2 bugs, re-verified the chain fires |
| KEV → remediation clock (BOD 22-01) | ✅ | ✅ | 4 SLA tests + API round-trip test + UI |

**Are we SOTA per task?** Honest reading:

| Task | Our status | SOTA gap |
|---|---|---|
| Detect (L1 OSS) | ✅ live on all 5 assets | at/above per-tool baselines by construction |
| Triage / FP-reduction | ✅ **100% decoy-downgrade, 0 invented** | at the frontier (this is where 2026 DAST rankings compete) |
| Correlate attack paths | ✅ **100% path recall, 0 false** | internal metric (no neutral leaderboard) |
| Remediate / patch | 🔒 **unmeasured** | needs a funded LLM; SOTA is ~90% (BountyBench) |
| Verify fix (retest) | ✅ mechanism proven | live rate LLM-gated |
| Backport | ✅ core+wiring+scorer (22 tests: 9+6+7) | dataset run pending (BackportBench) |
| Discover (autonomous, end-to-end) | 🔒 **unmeasured** | needs a funded LLM / proxy run; SOTA is only 13–34% |

**The one honest blocker to a SOTA *claim*:** every remaining ❓ is an
LLM-dependent number (patch-rate, autonomous discovery). The harnesses exist;
they need a funded frontier key (or a bounded file-relay proxy run). Until those
numbers exist, the agent claims are *unverified* — and this doc + the launch gate
say so.

**How to improve further (ranked, deterministic-first):**
1. Run the LLM-gated benchmarks (BountyBench-Patch, CVE-Bench, XBOW) — the only
   thing between us and measured SOTA on tasks 1/6.
2. Deploy OWASP BenchmarkJava → a fresh SAST Youden (0.387 is stale/mid-pack;
   this is the biggest *detection*-accuracy lever).
3. Extend threat-informed targeting as the corpus gains affected-version ranges
   (would let container join the targeting loop — see §5.1).
4. Wrap an OSS API-authz specialist (Akto) or ADR the in-house `apiauthz` path —
   the one web-vuln class with no grounding OSS today.

---

## 0.5 Is our DEFENSE benchmark neutral? (Partly — and it's an improvement loop)

**Honest status (corrected).** The offense side has a **neutral** third-party
benchmark (XBOW — their suite, ungameable flag capture; proxy-tested, XBEN-019
solved). On the defense side, `tsbench cloud-engine` (the synthetic) is
**ours-vs-ours** — rigorous but self-authored — and must NOT be presented as a
neutral score. BUT for cloud **attack-path discovery** specifically we DO have
neutral ground truth, wired and offline (zero disk):

- **CloudGoat** (Rhino Security Labs) — `tsbench cloud-engine --cloudgoat`, 8
  scenarios transcribed from CloudGoat's public Terraform, scored against its
  **published pentest solutions** (cloudiam is under test, not the referee).
- **IAM-Vulnerable** (Bishop Fox / Rhino) — `internal/cloudquery/
  iamvulnerable_test.go`, ~20 scenarios: **16 privesc primitives** (the full
  Rhino/PMapper method set) + boundary/SCP
  precision (must-NOT-fire) + a multi-hop assume→privesc chain + a data-exfil
  assume→read-PII chain + GCP/Azure impersonate/assume→privesc chains
  (`internal/cloudgraph/multicloud_chain_test.go`). Offline-transcribed, so
  zero disk / zero AWS.

**Used as an improvement LOOP, not a scorecard (this is the point).** Running
the IAM-Vulnerable suite surfaced a real gap and drove a fix:

> **Gap found + fixed:** the graph built `role→role` assume edges but never
> `user→role` ones, so a compromised IAM user that could `sts:AssumeRole` a
> privileged role was *disconnected* from it — the very common "leaked user key
> → assume an admin/deploy role" path was invisible. Fixed in
> `internal/cloudquery/ingest.go` (SCP/boundary-aware user-assume resolution).
> The multi-hop, data-exfil, and GCP/Azure chains now all pass and are permanent
> regression guards. Precision cases (boundary/SCP-blocked) correctly report NO
> path. Cross-account role ASSUMPTION (the multi-account pivot) works and is guarded —
> the trust is evaluated independently of the same-account union rule. The
> `SameAccount:true` simplification only affects cross-account DATA-access
> PRECISION (S3 bucket ARNs carry no owner account), a lower-frequency edge
> needing a schema field — scoped, not a recall gap.

So the neutral cloud-attack-path benchmark isn't missing — it's CloudGoat +
IAM-Vulnerable, and it earns its keep by finding gaps. The larger-N and live
halves (Bishop Fox's full multi-STEP lab scenarios via real Terraform; CloudGoat live mode)
stay AWS-credential-gated.

**For the OTHER engineer tasks** (respond/IR, remediate), the neutral
*defensive-agent* benchmarks target adjacent surfaces:

| Neutral benchmark | Task it scores | Domain | SOTA | Fit to our engineer |
|---|---|---|---|---|
| **SecRespond** (arXiv 2607.26791, 2026) | detection **+ remediation planning**, scored separately | post-compromise **host** IR (Linux/Win, forensic disk snapshots, 10 cyber ranges, 21 ATT&CK techs) | **Claude Opus 4.7 = 72.4%** | Best-aligned neutral *defender* bench; but host-forensics, not cloud IAM — and heavy Dockerized dataset |
| **BountyBench** (Detect/Patch) | detect + patch | real repos | Patch ~90% (Claude Code) | Maps to our remediate/verify tasks |
| **SEC-bench / CVE-Bench** | patch a real CVE | code repos | 34% / 21% | Maps to task 6 (remediate); we already built the scorers (`internal/bench/backport.go` shape) |
| **CTI→detection-rule** (Gao 2026) | turn threat intel into detection rules | cloud+endpoint | — | Adjacent to our threat-intel work (§7.1) |
| Blue-team threat-hunting (arXiv 2509.23571) | threat hunting | logs | — | Future |
| AI-SOC "top platforms" lists (Prophet, UnderDefense, Palo Alto) | — | vendor marketing | — | **NOT benchmarks** — no reproducible ground truth; do not cite as a score |

**Recommendation (do NOT rewrite our own benchmark for the headline):**
1. **Adopt SecRespond as the neutral defender benchmark to target** — it's public,
   reproducible, separately scores detect + remediate (our engineer's core tasks),
   and has a published Claude SOTA (72.4%) to compare against. Caveat: it's
   host-IR, so it exercises the *incident-response* half of our engineer (the
   `detect`/A-RSP path), not the cloud-IAM path.
2. **For the remediate task specifically, run a neutral PATCH benchmark**
   (SEC-bench / CVE-Bench) via the proxy — it maps cleanly to `remediate` +
   `backport`, and we already have execution-oracle scorers.
3. **Keep `cloud-engine` as our *internal* metric only**, labelled honestly as
   self-authored — never presented as a neutral score.

**Blocker for a larger-N neutral defense run:** every option above needs its
dataset deployed (SecRespond's 10 Dockerized ranges + disk snapshots; SEC-bench/
CVE-Bench's Docker task images) — the honest gated half, same posture as WAVSEP/
OWASP-Benchmark. Fabricating a dataset would produce a fake number (§10). The
proxy-drive mechanism is proven and ready the moment a dataset is present.

Sources: [SecRespond](https://arxiv.org/abs/2607.26791v1) · [BountyBench](https://crfm.stanford.edu/2025/05/21/bountybench.html) · [SEC-bench](https://github.com/SEC-bench/SEC-bench) · [blue-team threat-hunting](https://arxiv.org/html/2509.23571v3).

---

## 1. Why autonomous *discovery* is the weak link (the industry-wide fact)

The 2025–26 literature is consistent, and it splits sharply by task:

| Capability | Frontier-agent SOTA | Source |
|---|---|---|
| **Patch**, once the vuln is localized | **~90%** (Claude Code), 87.5% (Codex) | BountyBench |
| Patch, real CVE repos | 21% (SWE-agent) · 34% (best on SEC-bench) | CVE-Bench · SEC-bench |
| **Exploit / discover**, end-to-end | **13%** (zero-day) – 25% (one-day) | CVE-Bench (web CVEs) |
| PoC generation | 18% | SEC-bench |

The gap is not "writing the fix." It is **finding the thing worth fixing**.
Discovery demands open-ended hypothesis generation over an enormous space, a
sense of what is normal versus anomalous in *this* system, and long-horizon
state — precisely where LLM agents degrade.

### 1.1 Why *we* are (and are not) exposed to this

tsengine's architecture already refuses the losing bet. **Discovery is
deterministic OSS tooling (L1), not an LLM search** — so we inherit the
scanners' recall rather than the agent's 13%. The LLM is concentrated on the
tasks where agents measure *strong*: triage, correlation, remediation,
verification — and it is always grounded (propose/dispose) and HITL-gated.

That is the right shape. But it left three **real** discovery weaknesses of our
own, which are about *targeting*, not about model IQ:

1. **Untargeted probe selection (FIXED — §3).** Template/tag selection was
   static and hardcoded (`"api,graphql,jwt,oauth"`, a port→tags map). The
   engine could *know* a CVE was being exploited in the wild against Apache
   httpd, *detect* Apache httpd on the target, and still never probe for it,
   because probe selection and threat intel never met.
2. **Single-pass discovery.** The deterministic escalation stage (§5.3) is a
   good "signal → depth tool" loop, but its triggers are a fixed table. It does
   not iterate ("found X ⇒ therefore look for Y ⇒ therefore Z").
3. **Business-logic / unknown-unknowns.** BOLA, privesc chains, and novel
   logic flaws are genuinely agent-territory. We ground them with FP-free
   deterministic predicates (`bola_probe`, `privesc_probe`), so we cannot
   produce a false positive — but *finding* the candidate still needs the LLM,
   and that half is LLM-gated.

---

## 2. The nine tasks, their benchmarks, and our status

| # | Task | How tsengine does it | Neutral benchmark | SOTA | Our status |
|---|---|---|---|---|---|
| 1 | **Discover / detect** | L1 anchor OSS per asset + recon fan-out | CyberGym-E2E (discover) · SEC-bench · OWASP Benchmark (SAST) · WAVSEP (web) | 13–34% e2e for agents | ✅ live: container 84 CVEs, api 11, web SQLi captured, ip 9, repo 9 tools. ⏳ SAST Youden 0.387 (needs re-run) |
| 2 | **Triage / FP-filter** | L1.5 FP-filter, corroborator, confidence; grounding | **SASTBENCH** (agentic SAST triage) · "Sifting the Noise" | — (new field) | ✅ **100% decoy downgrade, 0 invented** (cloud-engine) |
| 3 | **Localize** (find the sink) | `internal/codelocalize` (heuristic + LLM tiers) | CyberGym (localization sub-task) | agents strong once reachable | ✅ recall@k/MRR harness exists; not wired to L1.5 |
| 4 | **Prioritize** by real risk | KEV/EPSS/ExploitDB + reachability + data-tier | no neutral leaderboard | — | ✅ deterministic; now also drives targeting (§3) |
| 5 | **Correlate** cross-surface attack paths | `crossdetect` + `cloudgraph` reachability | none neutral (we define it) | — | ✅ **100% path recall, 0 false paths** |
| 6 | **Remediate / patch** | `remediate` + code/cloud agents, HITL-gated | **BountyBench Patch** · **CVE-Bench** (509 CVEs) · SEC-bench · CyberGym-E2E | **90%** / 21% / 34% | 🔒 **LLM-gated — no number yet** |
| 7 | **Verify the fix** (retest) | `retest.Verify` — same predicate the product ships | built into BountyBench / CVE-Bench (exploit + functional test) | — | ✅ mechanism test-proven; live rate LLM-gated |
| 8 | **Backport** across branches | `internal/backport` relocation + `remediate.PlanBackports` gated actions | **BackportBench** (202 tasks, PyPI/Maven/npm, **test-driven** oracle) | agentic > traditional porting; varies by language | ✅ core + product wiring + scorer (22 tests); dataset run pending |
| 9 | **Detect & respond** (SOC/ITDR) | `detect` + `identitythreat` + A-RSP runbooks | **AgentCyberRange** · **ZeroDayBench** | — | 🟡 deterministic rules; agentic triage is future |

### 2.1 Web-specific benchmarks (the richest neutral set)

- **Detection:** WAVSEP (leaderboard: Acunetix 87 / Burp 78 / ZAP 56); OWASP Benchmark (Veracode 51 / Checkmarx 47).
- **Web vuln *repair*:** CVE-Bench (UIUC) is explicitly *AI agents on real-world **web** application vulnerabilities* (40 high-severity web CVEs).
- **The 2026 web-DAST differentiator is validation / FP-triage, not raw coverage.** Every commercial ranking now scores AI-DAST on "does the AI validate findings and cut false positives." That maps exactly onto our propose/dispose grounding — a task we should benchmark loudly, because it is where our architecture is genuinely differentiated.

---

## 2.2 Per-SPECIALIST neutral benchmark coverage (the taxonomy in CLAUDE.md §2.2.1)

§2 maps the nine *tasks*. This maps the six *specialists*, because that is the unit
we ship and the unit a "best in breed" claim is made about. A specialist with no
neutral benchmark cannot be claimed best-in-breed at all — only described.

| Specialist | Neutral benchmark | Status | What it takes to RUN the benchmark |
|---|---|---|---|
| **AI Cloud Security Engineer** | **CloudGoat** (Rhino) · **IAM-Vulnerable** (Bishop Fox) | ✅ **running, offline-transcribed** — 16/16 AWS privesc primitives, blocked-privesc precision, multi-hop, cross-account, GCP/Azure chains; a proxy-driven agent run reached admin over third-party ground truth | Offline: **nothing** (scenarios transcribed from the public Terraform into `cloudquery` tables — zero creds, zero disk). Live 31-scenario deploy: an AWS account + Terraform |
| **AI AppSec Engineer** | **OWASP Benchmark** (SAST) · **WAVSEP** (DAST) · **CVE-Bench** · **BountyBench-Patch** · **BackportBench** · **SEC-bench** | 🟡 harnesses built; SAST Youden **0.387** measured; the patch/exploit lanes are **LLM-gated (no number)** | GitHub connection (repo assets) · the Docker sandbox image · a deployed WAVSEP target · **a funded LLM key** for every patch lane |
| **AI Identity/SaaS Engineer** | **CISA SCuBA** — `cisagov/ScubaGear` (M365) + `cisagov/ScubaGoggles` (Google Workspace) | ✅ **built + improved this session** (`internal/bench/scuba.go`): 169 published policies, 146 scanner-detectable, **recall 0.322** (from 0.178), **SHALL recall 0.426** (from 0.218) — 89-policy worklist remaining | Offline: **nothing** (catalog transcribed; CC0). The gaps are mostly *fetch-surface* gaps, so closing them needs **Graph scopes** (`Policy.Read.All`, `SharePointTenantSettings.Read.All`, Teams/Exchange admin reads) and **Admin SDK** reads for Gmail/Drive/session settings |
| **AI SOC Analyst** | **ExCyTIn-Bench** (ICML 2026, `microsoft/SecRL`, MIT — 7.5k questions over 57 Sentinel log tables) · SecRespond · SIR-Bench | 🔴 **scores 0 by construction** — capability verified absent, see §2.2.2 | ExCyTIn needs **10–33 GB** of MySQL log volumes (measured from its own setup script) — infeasible under the disk constraint; SIR-Bench's dataset is **announced but unreleased**. The real blocker is not disk: it is a **SIEM/log-store connector + a `query_logs` agent tool**, which the codebase has nowhere |
| **AI Compliance Engineer** | **OpenCRE** (OWASP, CWE↔standard) · **SCF** + **CSA CCM** control cross-mapping | ✅ **MEASURED LIVE: 96%** — 48 of our 50 mapped CWEs are corroborated by OpenCRE (only CWE-1395 and CWE-693 are in-house-only). The lane was silently dead until this session; see §2.2.3 | OpenCRE is a **keyless live API** — no credential, no disk, runs today via `tsengine corpus compliance-provenance`. The SCF/CCM axis still needs an operator-supplied matrix export (SCF is CC BY-ND — parseable, not redistributable) |
| **AI EASM/OSINT Engineer** | **none exists** | 🔴 **honest gap** — the public material is vendor/analyst comparison (Expert Insights, buyer guides), not a reproducible dataset with ground truth | Nothing to run. The two honest options are (a) **subfinder/amass discovery-rate parity** on a domain we own, or (b) define one publicly, as we did for the defense bench |

**Two things this table changes.**

1. **The Identity/SaaS "no neutral bench" claim was wrong.** CISA publishes
   machine-checkable secure-configuration baselines for the two most common SaaS
   estates, with open assessment tools (OPA/Rego) and a CC0 licence. That is
   third-party ground truth for exactly the surface `operate` + `sspm` assess —
   the identity/SaaS analogue of IAM-Vulnerable. It is now transcribed and scored.
2. **Two specialists still cannot be claimed best-in-breed**: the SOC Analyst
   (benchmark exists, not built) and EASM/OSINT (no benchmark exists). Saying so
   is the point — §4's rule is that a SKIP is not a pass.

### 2.2.1 The SCuBA benchmark: 0.178 → 0.322, and why the denominator matters

`internal/bench/scuba.go` transcribes all 169 policies from eight baselines
(Entra ID, Exchange, SharePoint/OneDrive, Teams, GWS common controls, Drive,
Gmail, Calendar) and maps each to the tsengine rule ids that detect its violation.
Three properties keep the number from being self-graded:

- **Every mapping is EXECUTED.** `scuba_test.go` builds deliberately
  misconfigured tenants, runs the real `operate`/`sspm` assessors, and requires
  that each of the 25 claimed rule ids is genuinely emitted. A typo or a mapping
  to a check that does not exist **fails the build** rather than inflating recall.
- **The denominator is stated honestly**, in the `grc.Coverage` "no false
  compliant" tradition: 169 published → **146 scanner-detectable** (17 procedural,
  6 FCEB-specific such as the `reports@dmarc.cyber.dhs.gov` contact). Recall is
  quoted over the detectable subset, and separately over the mandatory (SHALL)
  half, so a claim always names which denominator it rests on.
- **Partial coverage is never counted as coverage.** A rule mapped with a `~`
  prefix (e.g. we detect "admin has no MFA" where the baseline demands
  *phishing-resistant* MFA for admins) is reported in its own column, not folded in.

**What the low number actually means.** The uncovered 111 are overwhelmingly
*fetch-surface* gaps, not detection-logic gaps: the baselines legislate password
length, session lifetime, Gmail attachment/link protections, Teams meeting
options, and Drive link defaults — settings our snapshot schema simply does not
carry yet. So the fix is mostly schema + Graph/Admin-SDK scope, which is why the
integration column above is the operative one for this specialist.

**And it already found a real detection bug.** `operate::dmarc-not-enforced`
accepted **p=quarantine** as enforced, while SCuBA makes **p=reject** mandatory
(`MS.EXO.4.2v1` / `GWS.GMAIL.4.2v1`). A tenant sitting at quarantine — the usual
"we started a DMARC rollout and stopped" resting state, where spoofed mail is
still *delivered* to junk and BEC can land — produced **no finding at all**. Fixed
by a new `operate::dmarc-not-rejecting` (medium), FP-safe (fires only on an
explicitly parsed quarantine, so an absent DMARC still yields the high-severity
finding and a p=reject domain stays clean). The labeled email-auth corpus was
re-labelled accordingly: a quarantine domain is no longer in the hardened
FP-control set, on the same rationale the pre-existing partial-enforcement check
already uses. **Same species of find as the cloud specialist's user→role assume
edge — which is the whole argument for running neutral benchmarks as a loop.**

---

**The loop then ran, which is the point of building it.** 21 checks were added across
`sspm.AssessM365` and `sspm.AssessGoogleWorkspace`, chosen by security value rather than
by ease — one theme, the three things an SMB actually gets breached through:

- **Bypassable authentication**: phishable MFA methods permitted (SMS/voice/email-OTP on
  both platforms), high-risk users and high-risk sign-ins detected-but-not-blocked,
  super-admin and user account self-recovery enabled, sub-12-character passwords,
  strength enforcement off.
- **Standing privilege**: privileged roles held as permanent ACTIVE assignments instead
  of PIM-eligible — privilege an attacker inherits at takeover with no activation step
  to detect — and self-service application registration by any user.
- **Exfil and impersonation paths**: external mail auto-forwarding (which we detected for
  Google but **not** for Microsoft — the asymmetry the benchmark exposed), never-expiring
  anonymous share links, share links defaulting to "Anyone"/edit, spam-filter bypass
  lists, missing external-sender tagging, inbound spoofing of the org's own domain, and
  unauthenticated mail delivered normally.

| Measure | Before | After |
|---|---|---|
| recall (of 146 detectable) | 0.178 | **0.322** |
| mandatory (SHALL) recall | 0.218 (22/101) | **0.426** (43/101) |
| rules proven live | 25 | **46** |
| m365/exchange · m365/sharepoint | 0.600 · 0.375 | **0.800 · 0.750** |

Two properties were held while doing it, because a recall number bought by loosening
either would be worthless. **The executed guard held throughout** — it caught the new
mappings twice before the snapshots exercised them, which is exactly the failure mode
(claiming a rule that never fires) it exists to prevent. And **every new field is
FP-safe by construction**: each is optional and named so that *true* (or a supplied
number) is the violation, so a snapshot written before the field existed produces
precisely its old finding set. `TestSCuBAGapFieldsAreFPSafeOnLegacySnapshots` asserts
that by rule name rather than by count, plus the two numeric boundaries where 0 must
mean "unknown" rather than "zero-length password" / "links expire immediately".

What remains is the honest part: 89 detectable policies are still uncovered, and they
need *fetch surface* more than logic — Graph and Admin-SDK reads for Gmail attachment
and link protections, Teams meeting options, session lifetime, and Drive defaults. That
is integration work, which is why the integration column is the operative one here.

**The fetch half now exists too, so this runs on a real tenant.** The checks were only
reachable by hand-posting JSON; `sspm.FetchM365Posture` reads the posture live from
Microsoft Graph, reusing the already-onboarded M365 token (no new credential), and
`POST /v1/saas/m365/sync` wires it end to end — the exact pattern `FetchGitHubOrg` /
`/v1/saas/github_org/sync` established. Graph covers `/admin/sharepoint/settings`
(sharing level, domain allow-listing, default link scope/permission, anonymous-link
expiry), `/policies/authenticationMethodsPolicy` (phishable factors),
`/policies/authorizationPolicy` (self-service app registration), and
`/identity/conditionalAccess/policies` (whether high risk is actually *blocked*).

The scope boundary is a property of Microsoft's APIs, not a TODO: Teams meeting policies
and Exchange transport posture are **PowerShell-only**, and PIM assignment types need
**Entra ID P2** — so those stay on the posted-snapshot path, gated honestly.

That boundary immediately exposed a **live-path false positive** that had been latent in
the snapshot model. `MailboxAuditingEnabled` was the one "true = good" field, checked
unconditionally as `!enabled` — so its zero value asserted a violation, and since mailbox
auditing is Exchange-PowerShell-only, **every live Graph sync would have reported "mailbox
auditing disabled" regardless of the tenant's real setting**. It is now tri-state
(`*bool`: nil = not supplied, `&false` = really off), which keeps the JSON key stable so a
posted snapshot sending an explicit `false` behaves exactly as before — only *omission*
changes, and omission asserting a violation was the bug. Tests pin both halves.

The fetcher's own tests assert the property that matters for a partial read: when Graph
refuses an endpoint (missing scope, unlicensed feature), the corresponding fields stay
zero and **no finding is invented** — in particular an unreadable Conditional Access list
must never be read as "high risk is unblocked". Reading *nothing* is a hard error rather
than a silently clean snapshot, so a misconfigured app registration cannot masquerade as a
healthy tenant.

**Google Workspace is deliberately not built the same way.** Workspace admin *settings*
are not exposed by the Directory API; ScubaGoggles reconstructs them from Admin **Reports**
API change events, inferring current state from the absence of a change. That is a
materially different and more FP-prone design than reading a settings endpoint, so it is a
scoped decision rather than a mechanical port — flagged here instead of half-built.

### 2.2.2 The SOC Analyst scores 0 — and the reason is architectural, not model quality

**ExCyTIn-Bench** (ICML 2026, Microsoft, `microsoft/SecRL`, MIT) is the neutral SOC
benchmark: 7,542 questions built from *investigation graphs* over a controlled Azure
tenant (57 Microsoft Sentinel log tables). Ground truth is automatic and explainable —
each question is generated from a pair of nodes on the alert graph, so the answer is a
specific real entity. A representative task, from its own test set:

> *Context:* a 'Suspicious process injection observed' alert where `powershell.exe`
> ran with an execution-policy bypass and a long base64 command.
> *Question:* in the related alert, what remote IP address was involved?
> *Answer:* a specific IP, reachable only by querying the logs and pivoting between
> two alerts through a shared entity.

**Two blockers, and only one is disk.**

- **Disk (hard, immediate):** the benchmark's own setup script provisions **10 GB** of
  MySQL volumes for 8 separate incident databases, or **33 GB** for the combined one.
  Free space on this machine is **12 GiB**. Not runnable here — stated, not skipped.
- **Capability (the real one):** tsengine's SOC specialist **cannot express this task
  at all**. Verified against the exported API, not assumed:
  - `internal/detect` exposes only `Reconcile`, `OpenFor`, `EscalateOverdue`, `Key` —
    every one of them over `[]types.Finding`. It diffs *findings*; it has no telemetry.
  - `internal/identitythreat` exposes only `Detect(events, cfg)` over a fixed `Event`
    shape returning fixed rule verdicts (impossible_travel, password_spray, …). It
    cannot answer a free-form entity question.
  - A repo-wide search for any log-query capability (`QueryLogs`/`kql`/`sentinel`/
    `splunk`) returns **nothing**.
  - There is no alert-graph or entity-pivot concept anywhere — no "related alert", no
    entity node, no traversal.

So the honest score is **0, by construction** — and it would be 0 with a frontier
model behind the proxy, because the gap is a missing tool surface, not missing
reasoning. **The integration that would close it is specific**: a SIEM/log-store
connector (Sentinel, Splunk, or Elastic) feeding an alert+entity graph, plus a
`query_logs` tool in the L2 catalogue so the agent can pivot. That is a genuine
capability increment, and it is the honest prerequisite before any "AI SOC" claim.

Note also that `identitythreat` *is* measured (`accuracy.go`'s `ScoreCorpus` over a
labeled `Corpus`) — but against **our own** corpus. That is a regression guard, not a
neutral benchmark, and it must not be quoted as one.

### 2.2.3 The compliance lane was silently dead — now 96% OSS-corroborated

`internal/corpus/opencre` cross-checks our in-house CWE→control crosswalk against
**OpenCRE** (OWASP's Open Common Requirement Enumeration) over a keyless public API —
no credential, no disk, runnable on any laptop. It was built, wired to
`tsengine corpus compliance-provenance`, and **returning nothing**.

Cause: OpenCRE changed its response shape. The `page` field now arrives as the JSON
**string** `"1"` while `total_pages` stayed a number. The decode struct required both
to be ints, so page 1 failed to unmarshal — and because a page-1 failure is treated as
a hard error, `Fetch` aborted the entire walk. The CLI logged one line to stderr and
printed `"opencre": null` **while still exiting 0**, so nothing about the failure was
load-bearing. A lane that reports nothing and exits clean is worse than one that is
absent, because it reads as "we have this covered".

Fixed with a `flexInt` that accepts a number **or** a string on both paging fields,
plus a regression test pinning all three shapes (live: string page + numeric total;
the reverse flip; the original all-numeric) and one asserting `total_pages` still
drives the multi-page walk — otherwise `Fetch` would read 1 page of 48 and quietly
under-report.

**First live number: 96%** — 48 of our 50 mapped CWEs are corroborated by an OpenCRE
CRE node. The 2 in-house-only mappings are **CWE-1395** (dependency on a vulnerable
third-party component) and **CWE-693** (protection mechanism failure); per §8 that is
honest, not a defect — OpenCRE simply has no node for them, which is exactly why the
report separates *corroborated* from *in-house-only* instead of blending them.

---

## 2.3 The uncomfortable synthesis: benchmark coverage ≠ AGENT coverage

Auditing which specialists have a neutral benchmark surfaced a more important fact.
For five of the six specialists the **LLM agent does not exist**. Verified by
enumerating every agent loop and every `LLM` consumer in the tree, not by reading the
architecture doc:

| Specialist | Has an LLM agent here? | Package | Neutral benchmark | Number |
|---|---|---|---|---|
| **Cloud Security** | ✅ **yes** | `internal/cloudagent` (`Investigate`) | IAM-Vulnerable / CloudGoat | ✅ reached admin on third-party ground truth via proxy; substrate 16/16 |
| **AppSec** | ❌ **no** — `remediate`/`backport` are deterministic proposers; there is no code-patch agent in this tree | — | OWASP-Bench (SAST) · BountyBench-Patch · CVE-Bench · SEC-bench | SAST **0.387** (deterministic). Patch lanes have **no agent to run** |
| **Identity/SaaS** | ❌ no — **correct by design** | `operate` + `sspm` (deterministic assessors) | CISA SCuBA | **0.178** recall / **0.218** SHALL |
| **SOC Analyst** | ❌ **no** — the genuine gap | `detect` (finding-diff only) | ExCyTIn-Bench | **0 by construction** (§2.2.2) |
| **Compliance** | ❌ no — **correct by design** | `grc` (annotation) | OpenCRE / SCF / CCM | **96%** OSS-corroborated |
| **EASM/OSINT** | ❌ no — deterministic assess | `osint` | **none exists** | — |

For comparison, the OFFENSIVE side of the product is where the agents actually live:
`internal/webagent` (the XBOW driver, with `internal/webrange` as an independent
procedural answer key), `internal/pentest/llmspec.go` (the ModeDeep D-agent),
`internal/llmredteam` (multi-turn attacker vs a customer LLM endpoint), and
`internal/apiauthz/discover.go` (LLM-assisted authz discovery).

**What this means, stated plainly.** The "AI Security Engineer" umbrella (CLAUDE.md
§2.2.1) is today **one specialist deep on defence** — Cloud — while the offensive
agent is several. Two of the five agent-less specialists are agent-less *correctly*:
identity/SaaS posture and compliance annotation are deterministic problems where an
LLM would only add non-determinism to something a rule already decides exactly
(§10's whole argument). But **two are real gaps**:

1. **AppSec patch agent.** The neutral benchmarks are the strongest in the whole map
   (BountyBench-Patch at 90% SOTA, CVE-Bench, SEC-bench, BackportBench) and we have
   *no agent to point at them*. The blocker is deeper than a missing agent — it is the
   **data model**, verified three ways: (a) `remediate` exports only `Propose`,
   `ProposeBulk`, `PlanBackports`, `ProposeIncidentResponse`, all of which emit fix
   *directives*; (b) `platform.Action` has **no patch or diff field at all**; (c) no
   `FetchFile`/`CommitFiles`/`CreateCommit`/`PutContents` exists anywhere in
   `internal/connector`. The sharpest illustration: `PlanBackports` already computes a
   relocated hunk and decides clean/offset/needs_adaptation — and then emits a
   `*platform.Action` that **cannot carry the patched content it just computed**.
   So the increment is: a patch field on `Action`, a GitHub read+commit path in the
   connector (behind the existing HITL gate), and only then an agent to fill it.
2. **SOC investigation agent.** Integration needed: a **SIEM/log-store connector**
   plus a `query_logs` tool and an alert/entity graph (§2.2.2).

Both are genuine capability increments, not benchmark plumbing — and both are
**product decisions about scope**, which is why this section states them rather than
quietly starting one. The benchmark work is what made the gap legible: three ticks of
"do we have a neutral benchmark per specialist" ended up answering "do we have a
specialist per specialist", which is the more useful question.

**A note on what the proxy can and cannot buy.** The file-relay proxy (a frontier
model standing in for the tenant's LLM) is how the cloud specialist and the pentester
were validated, and it is the right tool for any lane with an agent behind it. It
cannot manufacture a number for a lane with **no agent**: pointing a frontier model at
BountyBench through a proxy would measure *the model*, not tsengine. That distinction
is the difference between a benchmark and a demo.

---

## 3. Do we use threat intelligence well? (Answer: we now use it at 3 of 4 points)

We ship a strong corpus — **CISA KEV** (exploited in the wild), **FIRST.org
EPSS** (~336k CVEs), **Exploit-DB** (public PoC exists), and opt-in **NVD CVSS
vectors** — refreshed out of band and *pinned per scan* for the evidence pack.
The data was good. The **usage was narrow**: it fired at exactly one point.

| Where intel *can* act | Before | Now |
|---|---|---|
| **Annotate** a finding (CVSS/KEV/EPSS/advisories) | ✅ `threat_intel.enrich` (L1.5 hook) | ✅ unchanged |
| **Escalate severity** (KEV ⇒ high, BOD 22-01) | ✅ opt-in `TSENGINE_KEV_ESCALATE` | ✅ unchanged |
| **Target discovery** — decide *what to look for* | ❌ **nothing** — intel never touched the discovery path | ✅ **`internal/threatinformed`** |
| **Drive remediation SLA / order of work** | 🟡 indirect (severity → SLA policy) | ✅ **`SLAPolicy.KEVResolveHours`** — the BOD 22-01 clock |

### 3.1 What was built: `internal/threatinformed`

The missing loop — **intel decides what to probe** — is how a human engineer
works: read the KEV catalog, ask "do we run any of this?", then go look.

- `Plan(corpus, observed, opts) []Probe` takes the pinned corpus plus the
  technology recon **actually observed** (nmap/httpx product+version — the same
  grounded signal `service_eol` consumes) and returns ranked, bounded CVE
  probes with an audit trail.
- **Ranking by real exploitation evidence:** KEV listing (observed in the wild)
  dominates, then EPSS probability, then a public exploit, and a product match
  outranks the same evidence without one.
- **Grounded (§10):** a probe is emitted only for a CVE that really appears in
  the corpus with a real exploitation signal, and a product match must come
  from the corpus's own KEV vendor/product strings. **No exploitation signal ⇒
  no probe** (absence of evidence is not a reason to spend budget). Empty
  corpus or no observed tech ⇒ nothing planned. No CVE id is ever synthesized.
- **Bounded:** `MaxProbes` (default 50 — the cost twin of
  `TSENGINE_FANOUT_MAX_URLS`/`TSENGINE_ESCALATION_MAX`), with a separate
  sub-cap for speculative "intel-only" breadth, which is **off by default** so
  the default plan is purely evidence-targeted.
- **Deterministic:** identical inputs ⇒ identical ordered plan (map iteration
  order cannot leak). Needs **no LLM** — so it works today, free, reproducibly.

**Enabling data fix:** the KEV ingest was discarding `vendorProject` and
`product` (`KEVStatus{Listed: true}`) — exactly the fields needed to answer
"is the tech we just found the tech being exploited?" They are now retained
(optional/`omitempty`, so the dashboard contract and the embedded corpus
snapshot stay byte-compatible), and a test asserts the retention.

**Status: built + wired into the ip and web escalation stages; 12 tests passing
(grounding, ranking, bounding, determinism, banner↔catalog matching, the web
httpx path). Container is intentionally excluded — see §5.1.**

### 3.2 The 4th touchpoint: KEV drives the remediation CLOCK (BOD 22-01)

Intel now also sets *when the fix is due*, not just how the finding is labelled.
`SLAPolicy.KEVResolveHours` applies the CISA **BOD 22-01** deadline to any
incident whose opening finding carries a real KEV listing — **regardless of its
CVSS severity tier**, because being exploited in the wild is itself the deadline.

- The flag is carried on `Incident.KEV`, stamped in `detect.Reconcile` from the
  finding's `ThreatIntel.KEV.Listed` (the L1.5 hook's corpus-backed annotation) —
  the same pattern as `Verification`/`Confidence`/`Attacked`.
- It can only **tighten**: the stricter of (severity target, KEV window) wins, so
  a looser KEV window never relaxes a tight critical clock.
- It applies even when the severity has **no** target at all.
- `SLABreach.KEVAccelerated` records *why* the clock is short, so the UI can say
  "exploited in the wild" rather than showing an unexplained short deadline.
- Grounded (§10): a disabled policy, or an incident without the real KEV flag,
  gets no override; a resolved incident never breaches.

4 tests cover compress / never-relax / no-severity-target / grounded+resolved.

---

## 4. How we stay SOTA (the automation)

SOTA is a moving target, so the check must be mechanical, not a memory:

- **`make launch-check`** (`scripts/launch-readiness.sh`) is the per-launch
  gate: build + tests + **govulncheck-clean** always run and must pass; live
  per-asset scans run when a sandbox + deployed target exist; the **agent
  benchmarks are LLM-gated and SKIP loudly as UNVERIFIED** — with a real
  `generateContent` probe so a depleted key can never masquerade as a pass.
- **A SKIP is not a pass.** If the XBOW/defense lanes skip, the
  "best-in-breed AI pentester / security engineer" claim is *unverified for
  that launch*, and the gate says so in its verdict.
- **Per-task reporting.** The engineer should be reported per task
  ("triage ✓ / correlate ✓ / remediate 🔒 unverified"), never as one blurred
  score — that is what this table is for.

---

## 5. Ranked backlog to close the remaining gaps

1. ~~**Wire `threatinformed` into the escalation stage**~~ — **DONE** for the two
   assets where it is coherent:
   - **ip** — nmap `product`+`version` ⇒ targeted KEV/EPSS nuclei templates.
   - **web** — httpx `webserver` + `-tech-detect` ⇒ same. (httpx now emits both
     *structured* in `ToolArgs`; previously they were only concatenated into the
     finding title, so the signal existed but was unusable.)
   - **container — deliberately NOT wired, and this is the right call.**
     grype/trivy already emit CVE-keyed findings (`grype::CVE-…`) and the
     `threat_intel.enrich` hook extracts the CVE from `rule_id`, so KEV/EPSS
     already annotates every container finding — the intel loop is *already
     closed* there. A nuclei probe has no live target inside an image. The one
     residual gap (packages whose CVEs grype's DB missed but KEV lists) would
     need affected-**version-range** data the corpus does not carry; matching on
     product name alone would be FP-prone, so it is not done (§10).
2. **Run the LLM-gated benchmarks** (needs a funded frontier key): BountyBench
   Patch + CVE-Bench for task 6, XBOW for the pentester. The harnesses exist.
3. ~~**Iterative discovery**~~ — **DONE**: `finalizeWithEscalation` is now a
   bounded observe→re-plan loop. Each round re-plans over the accumulated
   findings, so a depth tool's own findings trigger the next depth tool
   (service→CMS→plugin-CVE→targeted probe). Converges via a per-scan
   dispatch-dedup set; the total shares the one `TSENGINE_ESCALATION_MAX`
   budget; `TSENGINE_ESCALATION_ROUNDS` (default 3) caps depth. This is the
   single biggest deterministic *discovery* lever — a single pass could only
   find what the first-order signals pointed at. 3 tests (chains / round-cap /
   shared-budget).
4. ~~**Explicit KEV → SLA clock**~~ — **DONE** (§3.2): `SLAPolicy.KEVResolveHours`,
   configurable via `PUT /v1/settings/sla` + the Settings panel, driving
   `SLABreach.KEVAccelerated`. Wiring is guarded by handler-level tests for both
   the ip and web escalation paths (the unit tests alone would not have caught a
   handler that forgot to call the planner — the failure mode that made the api
   asset silently return zero findings).
5. ~~**BackportBench** (task 8)~~ — **core DONE**: `internal/backport` relocates a
   fix hunk into a diverged version and classifies it honestly:
   `clean` / `offset` / `already_applied` / `needs_adaptation` / `not_applicable`.
   Design notes:
   - **Every** candidate site is considered and the patch's context is what
     disambiguates; a site is applied only when exactly ONE candidate is
     identified. Anything ambiguous escalates rather than coin-flipping a
     security patch into one of several plausible places.
   - **`already_applied` is checked first** — double-applying a security patch is
     a real, damaging failure mode, and `Apply` refuses that verdict.
   - **`Apply` only accepts `clean`/`offset`**, so an unadapted or ambiguous
     patch can never be forced in — the propose/dispose split (§10): an LLM may
     propose an adapted patch, but only this deterministic layer (plus the
     caller's build/test gates) decides it applies.
   - Formatting-drift recognition strips all whitespace, which is safe precisely
     because that path yields `needs_adaptation` and never auto-applies.
   **Wired into the product**: `remediate.PlanBackports(action, hunk, branches)`
   turns one merged fix into per-branch, HITL-gated remediation —
   clean/offset → a reviewable `ActOpenPR` carrying the patched content (tier 1,
   reversible); `needs_adaptation` → an `ActFileTicket` naming the branch and why
   it doesn't apply (**never a PR with a patch we couldn't place**);
   `already_applied` / `not_applicable` → **no action at all**. 6 tests including
   a mixed fleet (1 PR / 1 ticket / 2 no-action). The branch list + per-branch
   file fetch is the connector's (credential-gated) half — the planner is pure.
   **Scorer built** (`internal/bench/backport.go`), with an important correction
   to how this must be measured: **BackportBench's oracle is EXECUTION, not
   classification.** It is 202 real tasks from 12 repos across PyPI/Maven/npm,
   each with a Dockerized env, the upstream fix, the historical target version,
   the maintainer's own backport, and the relevant tests — a task is resolved
   only when **the repo's tests pass**. So our `backport` verdicts
   (clean/offset/…) are a *safety* layer and are **never evidence of
   correctness**; the scorer takes an execution Runner and refuses to let the
   system under test grade itself (7 tests, incl. "a confident solver whose tests
   fail scores 0", per-ecosystem split, decline-vs-error separation, partial-run
   honesty). No dataset ⇒ the renderer says so instead of printing a fake 0%.
   Remaining: the concrete loader for the released task schema + the Docker
   runner (the dataset is large and Dockerized — an out-of-band fetch, like the
   WAVSEP/OWASP corpora). A schema was deliberately NOT invented.
6. **Re-run SAST Youden** against a deployed OWASP Benchmark tree (0.387 is
   stale and mid-pack; the FP/FN tuning work lives here).

---

## 6. Honest summary

- The architecture is **correctly shaped for where the field actually is**:
  deterministic discovery (dodging the 13% agent-discovery trap), LLM applied
  to the ~90% tasks, everything grounded and HITL-gated.
- **Measured today:** triage/FP-reduction 100%, attack-path correlation 100%,
  0 invented findings, and live detection on all five tech assets.
- **Unmeasured today:** every LLM-dependent task number (patch-rate,
  solve-rate). Those require a funded key; until they exist, the agent claims
  are *unverified*, and both this document and the launch gate say so.
- **Newly closed:** threat intel now informs *what we look for*, not just how
  we label what we already found.
