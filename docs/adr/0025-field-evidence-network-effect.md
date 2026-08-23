# ADR 0025 — Field evidence: the network effect that calibrates VERIFICATION, not just ranking

**Status:** Proposed — **design only, no code.** Nothing in this ADR is built. It names the two
network effects available to this product, argues that only one of them is defensible, and fixes the
invariants any implementation must satisfy — because the dangerous version of this feature is easy to
build by accident and hard to withdraw once customers depend on it.

**Date:** 2026-08-23
**Depends on / reconciles:** CLAUDE.md §7 (the global threat-intel corpus is world-state, and a
cross-tenant feed is *"deliberately gated on isolation + consent — never default"*), §10 (evidence
grounding — the model proposes, the framework disposes), §18.2 inv. 2 (tenant isolation is the
security boundary), §2.5 (an L1.5 dismissal must be logged and recoverable), ADR 0006 (predicate
disposal), ADR 0017 (the untrusted-input trust boundary), ADR 0019 (reference material fed to the
proposer without widening what can be marked true), ADR 0024 (the coverage matrix).
**Supersedes:** nothing.

---

## Context

The question this answers is *"what can we build so that every new customer benefits from what we
learned from existing ones, and vice versa?"* — and the architecture already anticipated it. §7 splits
**global world-state** (the KEV/EPSS/SSVC corpus: the same for everyone, stored once, refreshed by
`scheduler.CorpusRefresher`) from **tenant-private data** (findings, incidents, OSINT), and joins them
at finding emission. §7 then states plainly that a cross-tenant feed is gated on isolation and
consent, never default.

So the shape is not new. A network effect is **a second global corpus whose source is aggregated,
consented tenant experience rather than CISA**. Everything downstream already works: per-scan version
pinning, the L1.5 hook join, the evidence pack.

What is new is the choice of *what to aggregate* — and that choice decides whether this is a feature
or a moat.

### Two network effects are available, and they are not equal

**The customer-facing one — better RANKING.** Aggregate the human dispositions the product already
collects (`tenanteval`'s `reinstated` / `ignored` / `accepted_risk` / `human_verdict`) into a per-rule
prior, and a new customer's first scan — the noisiest moment they will ever have, and the one where
they decide whether we are credible — arrives ranked by what security teams actually kept. Real value,
available on day one, and it retires `tenanteval.StarterCases`.

It is also **copyable by anyone with scan volume and a feedback button.** Every scanner vendor has
findings and a dismiss control. Nothing about this requires the rest of our architecture.

**The harness-facing one — better-calibrated VERIFICATION.** Aggregate what happened *after* a fix
shipped: `FixVerification.Status`, and above all `RescanSaidFixed` + `Disagreement`
(`rescan_missed_live_exploit` / `scanner_sees_variant`). The comment on `platform.FixVerification`
already argues this case, written before anyone was thinking about network effects:

> *"the two disagreeing is the single most valuable thing this system can learn: it is a labelled
> example that absence-evidence was not enough, and it is the only way to answer 'what evidence is
> sufficient' from real data rather than from opinion."*

Per tenant that is a handful of examples a year. Across tenants it is a dataset — and it is the only
dataset that answers the question the product's honesty rests on.

### Why VERIFICATION is the defensible half

Two reasons, and the second is the load-bearing one.

**It cannot be collected by scanning.** Producing one `rescan_missed_live_exploit` record requires the
whole loop: detect it, propose a class-correct fix, gate it through HITL, apply it, re-scan, *and then
re-attack to check whether the clean scan was telling the truth*. A vendor with ten times our scan
volume and no remediation loop generates exactly zero of these records. Scan volume is not a
substitute; it is a different quantity.

**It calibrates the only component that creates truth.** §10 is that the LLM proposes and the
framework disposes — a finding is `verified` because a predicate RAN, not because a model was
confident. So improving the proposer widens what the agent *tries*; improving the disposer changes
what the product can honestly *claim*. Ranking makes a list nicer to read. Verification calibration
changes what we are entitled to say, which is the entire product.

The sharpest statement of the thesis:

> The customer-facing network effect makes findings better ranked. The harness-facing one makes
> verification better calibrated — and verification is the only thing here that creates truth. That is
> the half competitors cannot copy by collecting more scan volume, because it requires shipping fixes
> and re-proving them.

### The counter-argument, stated fairly

Ranking is worth more *sooner*. It is felt in the first ten minutes of a trial; verification
calibration is felt the first time we correctly refuse to say something. A reasonable reading is that
ranking should therefore ship first.

This ADR takes the opposite order, for a specific reason rather than a purist one: **ranking is the
feed with the suppression temptation.** A disposition prior is one product decision away from
auto-hiding findings, and that decision is very easy to make when the demo is noisy. Building the
consent, k-anonymity and annotate-only plumbing on the verification feed first — where there is
nothing to suppress — means the guardrails exist *before* the feed that will test them.

---

## Decision

Build **`fieldevidence`**: a GLOBAL corpus, refreshed by the existing `scheduler.CorpusRefresher`
machinery, populated from consented per-tenant outcomes, keyed exclusively on world-state identifiers,
consumed on two paths.

**Path A — harness (verification calibration).** Per rule class: how often a clean re-scan was
contradicted by a live re-attack; which remediation types actually closed the finding versus got
reopened; the marginal value of attempt N per vulnerability class. Consumed by `retest` (require
re-attack rather than rescan for classes where absence-evidence has measurably failed), by the
remediation catalogs (`cloudFixCatalog` / `appsecFixCatalog` — rank a runbook by whether it worked),
and by the effort budgets (`MaxIters`, `TSENGINE_DEEP_MAX_ATTEMPTS`, `ProbeBudget`).

**Path B — customer (ranking).** Per rule id: a disposition prior with variance, annotating
confidence and ordering. Last, and only after Path A has proven the plumbing.

### The invariants — the part that must not be traded away

1. **World-state keys only.** What crosses the boundary must be a fact about *the world*, never about
   *a customer*. `nuclei::CVE-2024-1234` is a public OSS rule id; `package_upgrade` is a remediation
   type from a closed set; `s3://acme-payroll` is a customer. Rule ids, remediation types, CWEs,
   technique classes, outcome counts — nothing else. No endpoint, no ARN, no host, no response body.

2. **Annotate, never suppress.** A global prior may reorder, badge and inform confidence. It must
   never hide a finding. This is not caution for its own sake: it is the rule the codebase already
   enforces everywhere (the Detection Skill triage annotates only; `internal/consensus` is the single
   place permitted to DROP, and only because a sweep candidate is one model's opinion, so a panel is a
   second opinion on an opinion). A cross-tenant prior is *weaker* evidence than that, not stronger —
   it is other people's estates. And its failure mode is worse than a scanner's: if it could suppress,
   one popular misconfiguration goes invisible to every customer at once. N independent blind spots is
   a bad day; one correlated blind spot is the product failing silently, everywhere, together.

3. **Structurally constrained, never prose.** The moment a cross-tenant corpus reaches an agent's
   prompt it becomes **an untrusted-input channel between tenants** — a hostile customer planting text
   to manipulate another tenant's agent is prompt injection with a data structure around it. ADR 0017
   already has the pattern (untrusted `SKILL.md`, structural capability refusal, propose-only). Apply
   it: an entry must PARSE into a typed structure the disposer already validates — a `DemoSpec`
   skeleton, a rule id matching a known OSS rule, a remediation type from a closed set. Never free
   text concatenated into a system prompt. A poisoned entry must degrade to a WASTED ATTEMPT, never to
   a false claim.

4. **k-anonymity and a per-tenant weight cap.** A statistic computed from two tenants *is* those two
   tenants' data. A minimum-contributor threshold gates publication, and one tenant's dispositions
   cannot move a global number past a bounded share — otherwise a customer who mass-ignores everything
   silently retrains the product for everyone else.

5. **Opt-in, never default (§7 restated).** Contribution is a consent decision, and the consent page
   must be able to state exactly what leaves. Invariant 1 is what keeps that page short enough to be
   believed.

6. **Absence declares itself.** A rule with no field data reads as *"no prior"* — never as clean, safe
   or low. This is §10's own distinction ("we could not look" ≠ "we looked and it was fine") applied to
   the corpus, and it is the difference between a young corpus being honest and a young corpus quietly
   deprioritising everything nobody has seen yet.

7. **Pinned per scan, like threat intel.** The corpus version is recorded in `vulnerabilities.json`'s
   `corpus` block so an auditor can see which field evidence a decision was made against, and re-run
   it. A moving global prior that is not pinned makes past evidence unreproducible.

### Sequencing

```
F1  rescan trustworthiness      — smallest; the fields already exist and are machine-readable;
                                  proves consent + k-anonymity + pinning where nothing can be
                                  suppressed because there is nothing to suppress
F2  remediation efficacy        — ranks the runbooks in both fix catalogs by measured closure
F3  disposition prior (ranking) — most value, most hazard; only after F1/F2 plumbing is proven
```

F1 is deliberately the feed whose network effect makes the product **more honest rather than more
confident**. In a §10 codebase that is the version that cannot backfire, and it is a claim no
competitor can make: we can tell a new customer where *not* to trust us, with numbers.

---

## What this ADR explicitly does NOT decide

- **Fine-tuning is refused, not deferred.** §18.5 is "bring your own brain" — per-tenant model config
  across Anthropic/OpenAI/Gemini/local Ollama. A fine-tune breaks model-agnosticism, depreciates on
  every frontier release, and buys less here than elsewhere because §10 means the model is never the
  oracle. Harness learning transfers instantly to a model we have never seen; weight learning does
  not. Frontier churn depreciates a fine-tune and *upgrades* a harness.
- **Cross-tenant IOC sharing** (§7's original example) is a different feature with a different risk
  profile and stays gated.
- **Segmentation** (a fintech's true positives differ from a seed-stage SaaS's). Either segment the
  prior or publish variance beside it; a single blended number quietly averages a bank and a startup.
  Open question below.
- **Suppression, in any form, on any feed.** Not a sequencing decision — a standing invariant.

## Consequences

- **Positive:** the moat is on the half that requires the whole loop, so it widens with every fix we
  ship and re-prove rather than with scan volume. F1 makes the product measurably more honest, which
  is the claim this codebase is architected to be able to make. The existing corpus machinery,
  pinning and hook join are reused rather than rebuilt.
- **Negative:** the felt value arrives later than the ranking feed would deliver it, and the consent
  and k-anonymity work is real cost paid before any customer sees a benefit. Contribution being
  opt-in means the corpus grows slower than the customer base.
- **Neutral:** none of the six existing external feeds change. `fieldevidence` is a seventh corpus
  with a different provenance, and its entries must be distinguishable from world-state facts at every
  consumer, because "CISA says" and "our customers' outcomes suggest" are different grades of evidence
  and rendering them alike would be this ADR's own §10 failure.

## Open questions

1. **Segment or publish variance?** Decide before F3; F1/F2 outcomes are less segment-sensitive than
   dispositions, which is another reason they go first.
2. **Does F1 change `retest` behaviour automatically, or propose it?** Automatically tightening
   verification is safe in the honest direction, but it is still the corpus changing engine behaviour.
   Leaning toward automatic, since it can only ever *demand more evidence*, never less — but the
   inverse (relaxing to rescan-only where re-attack always agreed) must NOT be automatic.
3. **How is contribution priced?** A contributing tenant funds the corpus every tenant reads. If
   contribution is free and consumption is paid, the incentive is backwards.

## Status

| Item | Effort | Risk | Status |
|---|---|---|---|
| **F1** rescan trustworthiness | S–M | low (annotate-only; nothing to suppress) | Proposed — **start here** |
| **F2** remediation efficacy | M | low | Proposed |
| **F3** disposition prior | M | **medium** — the suppression temptation lives here | Proposed — after F1/F2 |
| consent + k-anonymity plumbing | M | — | Proposed — prerequisite to F1 shipping |
| fine-tuning | — | — | **Refused** (see above) |
