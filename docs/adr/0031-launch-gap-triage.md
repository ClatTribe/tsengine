# ADR 0031 — Launch-gap triage: the remaining gaps are ranked by the customer confidence they put at risk, not by the effort they cost

**Status:** **ACCEPTED — D1, D2b, D2c IMPLEMENTED + the D5 hygiene batch landed** (branch
`adr-0031/launch-gap-ga-blockers`). **Open:** D2a (Azure, M), D2d (dispatcher+image publish, M),
D4.1–D4.5 (parity sequence), and the three DECISIONS D3a–c, which no code can make.

**Post-merge amendments (2026-08-25, after ADR 0030's fleet landed on main):**

- **D3a run configuration is now pinned by available machinery:** the published offense number
  must state its tier — single-agent vs `TSENGINE_FLEET_WORKERS=N --assurance fast|verified` —
  because both are now first-class and a number without its configuration is not reproducible.
  `$`/finding rides along (usage accounting shipped in the same merge); a brain that reports no
  usage renders "unknown", never "$0". A keyless local-model smoke of the full XBOW harness
  (qwen3:8b, ~4 min/turn, 2 turns in 9 minutes) confirmed D3a's framing empirically: harness
  works end-to-end; capability waits on the funded key.
- **The framework-count rot reaches CLAUDE.md itself**: §8 said both "25" and a
  "full 14-framework set" in the same file. Fixed here to 25 (`grc.Frameworks` is canonical);
  the customer-facing sheets (competitive-proof-sheet, pitch deck) carried 14 and were corrected.
  Historical ADRs (0005/0007/0017) keep their at-the-time counts — they are records, not claims.
- **D2b acceptance caught a real defect while being implemented**: `writeJSON`'s
  `emptyIfNilSlice/fillEmpty` pass was altering the pack AFTER signing — every downstream verifier
  would have seen "hash mismatch". The signed route now serves exactly what it signs (plain
  encoder, bypassing the response massager), with the reason stated in place. The corpus-version
  pin guard (`TestComplianceCorpusVersionPinsTheData`) hashes the embedded crosswalk against the
  version string.
- **D2c enforcement point is `RoE.Check` itself** (the one choke every proposed action passes),
  with the environment stamped from the asset's recorded classification on the asset-scoped path
  and accepted in the RoE body on the generic path. Existing test fixtures assumed unclassified
  targets were attackable; they now declare environments, and the denial text tells the operator
  what to do about it.
- `main.go:642`'s mislabeled comment could not be located at the cited line (the region moved);
  re-locate before striking it from D5.

**What is NOT proposed here:** any new detection engine (§13 holds), any change to the L1/L2 split,
any new asset type, any entry into the alert-triage/SIEM lane, and any softening of a refusal to make
a launch date. Several items below are *decisions* rather than engineering work, and this ADR names
them as such instead of disguising them as tickets.

**Date:** 2026-08-25
**Depends on / reconciles:** CLAUDE.md §0 (customer-value-first ranking — this ADR operationalizes
it for the launch backlog), §10 (grounding), §12.3 (exit contracts and the swallowing ratchet),
§14.2 rule 6 (a guard that cannot see its subject must fail), §16 (build status),
[docs/specialist-roadmap.md](../../docs/specialist-roadmap.md) §2.4 (the frontier-key blocker —
adopted here as a launch gate, not re-derived), ADR 0024 (the verification ladder), ADR 0028 (the
CTEM bookend phases), ADR 0029 (its surface-vs-capability axis distinction is the template for the
audit this ADR records). **Supersedes:** nothing.

---

## Context

Two audits were run against `origin/main` and reconciled:

1. **A code audit**, in five passes, verifying the six surfaces, the threat-intel stack, the
   verification-loop packages, the two L2 products, and the compliance machinery *against the tree*
   rather than against CLAUDE.md or arch.md.
2. **A market audit** of the category the product sells into — Gartner's Adversarial Exposure
   Validation / CTEM framing (Market Guide, March 2026; first Exposure Assessment Platforms MQ,
   November 2025) and the vendors buyers actually shortlist: XBOW, Horizon3 NodeZero, Aikido,
   Pentera/XM Cyber/Cymulate on the validation side, Vanta/Drata/Sprinto on the compliance side,
   Torq/Dropzone/Prophet on the AI-SOC side.

The market conclusion first, because it is what makes the ranking below meaningful rather than
academic:

| Competitor | What they monetize | The gap beside them |
|---|---|---|
| **XBOW** (~$237M raised; #1 HackerOne US; ~$6k pentests) | Exploit-validated findings via a deterministic non-LLM validator layer — the same design as §10 | Web/API only. No cloud, code, identity, or compliance evidence |
| **NodeZero** (262k production pentests) | Hack → Fix → Verify loop with 1-click fix verification — the same shape as `internal/retest` | No code security at all; launched WebApp pentesting July 2026, still no compliance evidence output |
| **Aikido Infinite** (Feb 2026) | Pentest-on-every-release + autofix PRs + Drata/Vanta sync; "no High/Critical = don't pay" pricing — i.e. the market already pays for exactly a `verified_rate` claim | Shallower offense; no exploitation-proven bar |
| **Pentera / XM Cyber / Cymulate** | The AEV validate stage, enterprise-priced ($100K+/yr) | No code surface; no agentic reasoning; not SMB-reachable |
| **Vanta / Drata** | Integration count (400+/200+) and auditor networks | Zero offense/validation. Their evidence is configuration evidence, not attack evidence |

**The intersection — exploitation-proven offense + fix-verification + audit-grade compliance
evidence across all six surfaces — is unoccupied.** Nothing in the code audit changes that thesis;
everything in the gap list below is about making the intersection *true under a customer's audit*
rather than merely claimed.

The code audit's headline finding is the same shape ADR 0029 recorded on a narrower question:
**the hard parts are done, and what remains is concentrated in three failure modes**, not spread
thinly across missing features —

- **S1 — silent-clean false confidence**: the system reports success where it did not look;
- **S2 — built-but-unwired**: capabilities finished and tested with no production caller (the shape
  that caught `ghoidc`, `codesweep`, `cweattrib`, `NVDURL`);
- **S3 — claims ahead of measurement**: sentences the tree cannot currently prove, including one
  marketed feature that does not exist.

Per §0, the ranking below orders by *(a)* the customer confidence a gap puts at risk if we ship as-is,
and *(b)* the headline claim fixing it unblocks. Effort appears only as a tiebreak. That is why a
two-line fix outranks a multi-week feature: the fix removes a way to tell a customer something false;
the feature widens coverage.

### C1 — S1: the cloud asset can read clean when the credentials never worked

`internal/tool/prowler/prowler.go:81-85` and `internal/tool/scoutsuite/scoutsuite.go:62-66` return
`err=nil, findings=0` when the scanner produces no output file — which is what bad, expired, or
missing credentials produce. stderr sits in `Result.Output`, which normalization never lifts. Neither
wrapper uses `tool.Failed` or `tool.DidNotRun`, so the §12.3 exit-contract ratchet
(`internal/tool/exitcontract_test.go`) does not classify them — a blind spot in the ratchet itself.

The cascade is the one §12.3 was written to prevent, on the asset whose gate doc
([docs/per-asset-gates.md](../../docs/per-asset-gates.md)) names credentials as *the* boundary:

- the pass reads complete, `Scan.ToolsFailed` stays empty, no degradation fires;
- `detect.Reconcile` sees a clean estate; `retest.VerifyWithPolicy` confirms fixes;
- `grc.Reconcile` flips control gaps toward MET.

**A SOC 2 customer handing the report to an auditor can be told their cloud estate is clean when
nobody ever looked at it.** This is the single highest confidence-at-risk item on the list and among
the cheapest to fix — which is exactly the §0 inversion the ranking exists to catch.

### C2 — S2: five finished capabilities with no production caller

| Piece | Where it sits | What wiring it would make true | Risk if left unwired |
|---|---|---|---|
| **Azure privesc + Entra ownership edges** | `azureiam.Techniques`, `EntraTechniques`, `cloudgraph.AddAzurePrivescEdges` / `AddAzureEntraPrivescEdges` / `AddEntraOwnershipEdges` (`iam_bridge.go:210/255/295`) — zero non-test callers; `azinventory.Build` calls it "the honest gated half"; Azure ingest returns an empty `InventoryCoverage` (`platformapi/cloudinventory.go:55-57`) | AWS and GCP estates enumerate privilege-escalation attack paths; Azure estates silently return none, and zero reads as "nobody can become admin here" | Asymmetric cloud offense — a sales conversation killer on one of the big three clouds |
| **Signed GRC evidence pack** | `grc.Sign` / `SignedReport` / `EvidencePack()` implemented + tested; **zero production callers**; `/v1/compliance/{framework}/report` serves unsigned Markdown | The auditor-facing artifact the whole compliance pillar points at — tamper-evident, servable — exists and is withheld | The compliance pillar's flagship deliverable is weaker than its own code |
| **Production-environment RoE gate** | `pentest/environment.go` (`CheckEnvironment`, `ProductionAuthorized`, `AllowProduction` — unknown-counts-as-production, two-consent-acts) fully built + tested; zero production callers. `datatier.go`'s comment meanwhile *claims* the environment gates pentesting — an overclaim in the opposite direction | Blast-radius consent for active testing: staging vs production decided by classification, not by the operator remembering | For an offense product, the safety story has a hole exactly where a prospect asks "what stops it touching prod?" |
| **`dispatch_oss` inside platform-run pentests** | `webagent.SandboxDispatcher` wired via CLI `--oss-sandbox` and tsbench; `pentest_discover.go`'s `defaultWebDiscoverer` builds `webagent.Options` without `Dispatcher`; `docker/pentest-sandbox/` exists locally but `.github/workflows/images.yml` never publishes it | sqlmap/wpscan/nuclei/ffuf/hydra/padbuster reachable from the *productized* pentest, not just the CLI | Platform engagements quietly lose the deep OSS specialists; honest degradation, but a capability gap the UI does not explain |
| **`post_emit_verifier` (L2.5)** | Chain slot present, Finalize pass-through even with `TSENGINE_L15_POST_EMIT_VERIFY=1`; documented as deferred | `pattern_match → verified` upgrades without a live re-fire elsewhere | Deliberately excluded from the wiring batch — see the refusal below |

### C3 — S3: claims ahead of measurement

1. **No public cloud/offense autonomous numbers.** [docs/specialist-roadmap.md](../../docs/specialist-roadmap.md)
   §2.4 already names the cause precisely — *"a funded frontier model key and one clean autonomous
   run each … a purchasing decision, not an engineering project … the highest-leverage item on this
   page."* Proxy suites exist (cloud 7/7, offense 4/4, XBEN 89/97 flags captured, defense twin 6/6
   patch-verified) but the published-aggregate trigger has not fired. XBOW and NodeZero publish
   numbers; until we run ours, the headline claim rests on fixtures we authored.
2. **SSO is marketed and absent.** `frontend/app/(marketing)/pricing/page.tsx` sells
   "SSO / SAML + role-based access" on Enterprise; `internal/authn` has password auth only — no
   OIDC/SAML login exists anywhere in the tree (the only SAML/OIDC code assesses *customers'*
   AWS trust policies). A trust product cannot ship a marketed authentication feature it does not have.
3. **Unmeasured or thin measurements** that a security buyer probes early:
   - web DAST: WAVSEP SQLi **57.58% Youden at 0 FP** (good), but XSS **−15.20%** with script-context
     XSS 0-for-N across runs, path traversal **~0.49%** (nuclei ships no working LFI template —
     recorded as a capability statement, `SCOREBOARD.md:96-154`);
   - repository SAST **46.54% Youden** — third on the published cohort, carried honestly, with
     specificity (12–27%) the known weakness and the CodeQL escalation — the mitigation — **amd64-only**
     (arm64 images ship a 127 stub);
   - domain/ip: **zero measured numbers** (fixture stubs); their registry tiers are comment-only;
   - cloud offline bench: recall 1.00 against ground truth seeded at **19 of CIS's ~60 controls**;
   - api: VAmPI recall 1.000 but **one vuln class**, and — see C4 — unauthenticated by construction.
4. **Stale documentation asserting superseded numbers**: `benchmark.md` carries 47.86% SAST and a
   +0.17 cloud lift superseded by `SCOREBOARD.md`'s reproduced 46.54%/+0.05;
   `docs/neutral-benchmarks.md` and `bench/scoreboard.results.json` still carry 0.387; root
   `roadmap.md` describes the pre-platform engine (multi-tenancy 🔴, HITL 🔴 — all built);
   `docs/pricing-model.md` disagrees with the live pricing page and `plan.go`. Each is small; summed,
   they mean anyone auditing us reads two contradictory trees.

### C4 — Parity gaps that are genuine engineering (ranked by buyer-feel)

1. **The `api` asset scans unauthenticated.** The web handler seeds sessions (`seed_auth` wave 0 +
   cookie threading, `asset/web/handler.go:142-152`); the api handler has no equivalent, so
   schemathesis, nuclei, sqlmap and the response sampler all run anonymous. Every real API is
   authenticated; the authed-surface finding classes are structurally out of reach, disclosed only as
   the API1/API5 authz gap (which itself needs operator-configured identities). Highest-value
   engineering item: it mirrors a pattern the codebase already proved on web.
2. **Container depth.** Anchors are solid (trivy/grype/dockle/syft/cosign, must-find recall 1.000,
   FP-control passing) but the registry tier is empty (`container/handler.go:84-86` is a comment),
   there is no escalation, and no `CoverageReporter` — the thinnest disclosure surface of the six.
3. **Web DAST class coverage** (XSS script-context, path traversal) — a recall hole competitors'
   scores make visible; bounded by the WAVSEP delta so it cannot regress silently.
4. **domain/ip benches** — recon breadth vs subfinder/amass published rates; cheap harnesses, needed
   before those surfaces carry a claim.

---

## Decision

### D0 — The ranking rule, made explicit for the launch backlog

Every open item is assigned exactly one tier, by §0:

- **GA-BLOCKER** — shipping with the item unfixed risks telling a customer something false, or
  marketing a capability that does not exist. Launch waits.
- **SHIP-WITH-DISCLOSURE** — real gaps the existing disclosure machinery renders honestly
  (`coverage::` findings, `ChecksNotRun`, the evidence-rung ladder, `certifiable:false`). Launch
  proceeds; the disclosure is the commitment.
- **DEFER** — out of the launch claim entirely.

Effort never promotes an item into a higher tier and never demotes one out of GA-BLOCKER. It only
orders work *within* a tier.

### D1 — Kill S1 first (GA-BLOCKER, one PR)

Convert `prowler` and `scoutsuite` to the §12.3 exit contract: declare their finding-exits (none —
both exit non-zero only on error), route everything else through `tool.Failed`, and add both wrappers
to the ratchet ledger so they can never silently regress to swallowing. Acceptance is written at the
consumer level, not the wrapper level: a bad-credential scan produces `ToolsFailed` entries carrying
the stderr cause, marks the pass degraded, and **all three absence-consumers refuse** —
`detect.OpenFor` (never resolves), `retest.Verify` skipped, `grc.RefreshEvidence` (never clears) —
asserted by one test through the runner, in the spirit of `grc_false_compliant_test.go`.

While there: sweep the remaining unconverted wrappers in `internal/tool.swallowing` for *other*
members of the exact class "exit non-zero means error and we parsed anyway" — trivy and grype were
converted because they were measured; the ratchet exists so the rest convert when measured, and the
cloud pair proves the ledger alone is not enough if the ratchet never sees a wrapper.

### D2 — Wire the built cluster (GA-BLOCKER or near; one PR each, no new engines)

- **D2a — Azure parity.** Call the three existing bridges from `azinventory.Build` (AWS and GCP show
  the seam), and give Azure ingest a `CoverAzure` coverage analyzer mirroring `CoverAWS`/`CoverGCP`,
  naming principals whose policies failed to parse and roles that could not be resolved — the
  firm-allow rule's disclosures, not new inference. Until this lands, the product page and attack-path
  copy must not imply uniform multi-cloud privesc coverage.
- **D2b — serve the signed evidence pack.** One route (`GET /v1/compliance/{framework}/evidence-pack`)
  over the tested `Sign`/`Verify`, plus the guard that makes the pinning honest:
  `ComplianceCorpusVersion` (`internal/tracer/hooks/version.go:14`) must change whenever the embedded
  crosswalk changes — a pinned corpus whose version string never moves makes two different corpora
  indistinguishable in an evidence block, defeating the pin. Guarded like `claimcheck`: the version
  string is data, and a test fails when the data file changes without it.
- **D2c — wire the production-environment gate.** `RoE.Check` consults `CheckEnvironment`
  (unknown = production, two consent acts to allow it — the built design), and the `datatier.go`
  comment is corrected to match whichever way this lands. Fail-closed is already the built semantics;
  wiring it changes no defaults, it makes the built safety real in the productized path.
- **D2d — platform pentests reach the sandbox specialists.** `defaultWebDiscoverer` accepts a
  `Dispatcher` (nil-safe, as the CLI path already is), `cmd/platform` supplies it behind the existing
  sandbox env, and `images.yml` publishes `pentest-sandbox` with the same verify-tools discipline as
  the other sandboxes. Note for RELEASE.md: this grows the twelve-artifact release matrix — the
  partial-release risk it already warns about grows with it, so the same-tag verification check
  covers the new image.

**Deliberately NOT in D2: `post_emit_verifier`/L2.5.** It is inert-and-documented today, which §0's
shallow-version clause prefers over a half-right verifier that upgrades findings on weak evidence.
It gets a design pass (what a benign-control re-fire grounds, per class) before it gets a flag flip.
Ticking the box is explicitly refused.

### D3 — Three decisions, named as decisions (not tickets)

- **D3a — the frontier-model run (GA-BLOCKER for headline claims).** Adopt specialist-roadmap §2.4
  verbatim as a launch gate: one funded key, one clean autonomous run each for cloud and offense,
  aggregate published. Nothing else on the critical path is blocked on engineering while this waits —
  which is precisely why it must be decided now rather than discovered late.
- **D3b — the monetization motion.** Either (i) **contact-sales at GA** — then billing is *not* a
  blocker, the plan-tier enforcement stands, and all self-serve implications come out of the copy; or
  (ii) **self-serve checkout** — then a payment/tax/invoicing integration is a GA-BLOCKER with real
  scope. The current state (self-serve signup works, paid fulfilment is a human) is a halfway position
  that neither copy nor pricing page acknowledges cleanly.
- **D3c — the SSO claim.** Build OIDC/OAuth SSO login for Enterprise, or cut the pricing-page line
  until built. There is no third option: a marketed-but-absent authentication feature on a *security*
  product is the exact claim/code mismatch this codebase's own guards exist to prevent.

### D4 — Parity sequence within SHIP-WITH-DISCLOSURE (value order, effort only breaks ties)

1. **API authenticated scanning** — port the proven web pattern: a `seed_auth` dispatch in wave 0,
   session threading into schemathesis/nuclei/sqlmap args, graceful unauthenticated fallback, and a
   `coverage::` disclosure when no credentials are configured (so an anon-only scan never reads as
   full-surface).
2. **Web DAST class depth** — XSS script-context and path traversal via escalation additions
   (template packs / registry promotions), gated on the WAVSEP per-class delta so improvement is
   measured and regression impossible.
3. **Container disclosure floor** — a `CoverageReporter` modeled on `common.ThreatInformedGaps`
   (registry tier and escalation remain arch.md backlog; the *disclosure* should not wait on them).
4. **domain/ip benches** — recon-breadth harnesses against published subfinder/amass rates.
5. **arm64 posture** — either declare amd64 the supported sandbox config for taint escalation, or
   ship the arm64 loss as a visible declared gap; today it fails loudly into `ToolsFailed`, which is
   correct behaviour rendered nowhere a customer looks.

### D5 — Hygiene batch (Tier C; scheduled, never allowed to gate Tier A)

Doc truth sweep (`benchmark.md`, `neutral-benchmarks.md`, `scoreboard.results.json`, root
`roadmap.md` rewrite-or-delete, `pricing-model.md`, the "22"/"14 framework" strings,
`testing-l2-agents.md`'s provider list, `main.go:642`'s mislabeled comment); a cross-language
TS↔Go framework-mirror guard in the `icpcheck` style, replacing the comment that currently claims a
gate that does not exist; pin scoutsuite via the pip constraints file (the mechanism that fixed the
semgrep pin). None of these wait on anything, and none of them justify delaying D1–D3.

### Refusals

- **No alert-triage lane.** The AI-SOC competitors (Torq/Dropzone/Prophet) own SIEM-fed triage; we
  have no SIEM ingestion and the focus decision (CLAUDE.md §2.2.1, 2026-08-17) already scoped the SOC
  analyst as capability-not-claim. `detectionvalidation` stays what it is — grading *defenses*
  against our proofs — and is not repositioned as an AI SOC.
- **No connector-count race.** Vanta/Drata win on integration breadth; we win on evidence quality
  (finding-grounded, OSCAL, signed). Racing them on connector count is catch-up confused with moat
  (§0). A Drata/Vanta *sync* (Aikido ships one) is distribution, evaluated separately, not part of
  this ADR.
- **No revival of mobile/garak** to widen the surface list for launch copy. Six surfaces, stated as six.
- **No invented precision in this ADR.** Items are sized S/M/XL in the sequencing table, matching
  specialist-roadmap's convention; day-counts here would be fiction.

---

## Consequences

**What gets better.** The three ways the tree can currently tell a customer something false
(cloud-clean-on-no-creds; unsigned flagship evidence; a marketed auth feature that does not exist)
are closed before the first external audit. Five finished capabilities become live claims with no
new engines — the cheapest truth-per-line-of-code available anywhere in the backlog. And the two
headline numbers (cloud + offense `verified_rate`) become publishable instead of proxied.

**What gets harder.** D1's ratchet additions and D2b's corpus-version guard will fail future PRs —
that is their function. D2c makes production targets require one more deliberate consent act, which
will occasionally annoy an operator and is the point. D2d grows the release matrix and with it the
partial-release risk RELEASE.md already flags. Honest disclosures (api-unauthed, container depth,
XSS/LFI) may cost deals that vaguer copy would have kept, for a while — the same trade ADR 0029
accepted for the evidence ladder.

**What this deliberately does not do.** It does not close the API BOLA/BFLA general-authz problem,
the identity-mutation scope gaps, or the scale-out infra list (Postgres/KMS/HA) — all documented
elsewhere and none launch-blocking under single-box deployment. It does not make exploit-proof
even across six surfaces; ADR 0029 owns that boundary and its ladder remains the vocabulary.

**Sequencing** (sizes are relative, not calendar promises):

| Order | Item | Size | Tier |
|---|---|---|---|
| 1 | D1 cloud exit-contract + consumer-level acceptance test | S | GA-BLOCKER |
| 2 | D3b/D3c decisions (billing motion, SSO build-or-cut) | — | GA-BLOCKER (decisions) |
| 3 | D2b signed evidence pack + corpus-version guard | S | GA-BLOCKER |
| 4 | D2a Azure wiring + coverage analyzer | M | GA-BLOCKER (asymmetry) |
| 5 | D2c RoE environment gate + comment fix | S | GA-BLOCKER (trust) |
| 6 | D2d pentest dispatcher + image publish | M | near-blocker |
| 7 | D4.1 API authenticated scanning | M | SHIP-WITH-DISCLOSURE |
| 8 | D3a frontier runs + published aggregates | decision + run | GA-BLOCKER (claims) |
| 9 | D4.2–D4.5 DAST depth, container disclosure, ip/domain benches, arm64 posture | M each | SHIP-WITH-DISCLOSURE |
| 10 | D5 hygiene batch | S each | Tier C |

**The honest sentence until this lands:**

> We find exposures across code, cloud, identity, web, API and containers; on web and API we prove
> them by exploiting them, on AWS we confirm authorization with the provider's evaluator, and every
> finding states the rung it stands on. Our cloud scanner currently reports a clean account if its
> credentials are wrong — being fixed first, because that is the one defect in this list that can
> make a compliance report lie. Our strongest artifacts (signed evidence packs, multi-cloud privesc
> paths, production-scoped consent) are already built and are being wired, not redesigned. We have
> not yet published an autonomous-run number for cloud or offense; when we do, it will sit beside
> the external answer keys we already score against.
