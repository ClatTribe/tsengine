# ADR 0017 — Adopt Detection Skills as a consumer (not a competitor)

**Status:** Accepted
**Date:** 2026-08-03

## Context

[Detection Skills](https://detectionskills.io/) is an open format stewarded by Vega that packages a
detection rule together with the investigation reasoning a detection engineer would apply. It is a
folder with a `SKILL.md` — the same Agent Skills format Anthropic defined — with three phases:
**triage** (does this deserve attention?), **investigation** (gather evidence, reach a verdict), and
**tuning** (propose rule refinements for human review). Vega shipped ~35 skills; Elastic publishes an
Agent Skills repo for its detection rules.

Two facts about our own tree decided this:

1. **Our defensive triage is the thinnest part of the product.** `detect.Detector.Reconcile` opens an
   incident on a *severity threshold*. `platformapi.runInvestigate` is generic over any Issue. There is
   no per-rule investigation logic anywhere on the defensive side.
2. **We already own a lot of per-rule reasoning, trapped in Go.** Eight authored runbooks in
   `remediate/identity.go` (`operate::admin-without-mfa`, `dmarc-not-enforced`, `oauth-admin-scope`,
   `stale-account`, …), four `PlanEscalation` trigger tables (web/repository/api/ip) that map a signal
   to a depth tool, and a 50-entry CWE→control crosswalk. None of it is portable, versioned, or
   editable by a customer without a code change.

## Decision

**Adopt the format as a consumer. Do not compete on the standard.**

Formats commoditize. The scarce asset is not the runbook library — it is the substrate that can
*ground* a skill (real tools, sandbox, pinned corpus, evidence pack) and *stand behind* its verdict (a
named human, a signed ledger). Vega is competing for the runbook layer; we are indifferent to who wins
it and sell the layer underneath and above.

The framing that follows from this:

> **Skills are the input. Evidence is the output.**

Every other consumer of this format stops at a verdict — malicious/benign, analyst moves on. We are
the only ones who can turn that verdict into signed, pinned, auditor-ready compliance evidence with a
named human behind it, because `internal/grc` + `pkg/ledger` + the HITL desk already exist.

### The leverage stack (build order)

1. **Consume** ✅ — a `SKILL.md` loader, so community skills run on our substrate. Fills our weakest
   link with someone else's labour. Wired at the composition root: `TSENGINE_SKILLS_DIR`, or the
   bundled `./skills`, attached to `detect.Detector.Triager`.
2. **Certify** ✅ — a skill verdict becomes compliance evidence across the 22 frameworks, with a named
   human. `Certify` inherits controls from the cited findings and never invents one.
3. **Convert** ✅ — the 8 identity runbooks are now 5 portable skills, authored around investigations
   rather than 1:1 with rules. The 4 escalation trigger tables remain.
4. **Compose** ✅ — skills are per-detection and single-surface; `ComposeChain` runs verdicts along a
   `correlate.Chain` to produce **cross-surface corroboration**: two skills, different authors,
   different systems, independently flagging two hops of one attack path. No single-detection skill
   can observe that. Composition AGGREGATES but never ESCALATES beyond what its steps support.
5. **Distribute** — publish our FP-free primitives (`bola_probe`, `privesc_probe`, `cloudiam.Authorize`,
   reachability) so *other people's* skills call them. Load-bearing inside the standard. *(Open.)*

## The trust boundary (the part to get right)

A community `SKILL.md` is **untrusted instructions that an agent will follow** — prompt injection as a
supply chain. This is the OpenAI×HuggingFace lesson in a new wrapper, and there is already research on
malicious agent skills (SkillSieve, arXiv 2604.06550). The following are invariants, enforced in code
and tested:

| Invariant | Mechanism |
|---|---|
| **A skill is DATA, never capability.** It cannot grant a tool, widen scope/budget/egress, or change the gate tier. | `Skill` carries no capability fields; `RenderContext` emits the body inside explicit untrusted-content delimiters. Capability-claiming frontmatter keys are rejected at load. |
| **A skill PROPOSES; the framework DISPOSES.** | `ProposedVerdict` is validated against a closed enum, and every cited finding id must exist in the incident under triage. An ungrounded verdict is refused, not downgraded. |
| **Tuning never auto-applies.** | A tuning proposal is emitted as a HITL action, never a mutation — same gate as every other consequential change (§18.2 inv. 3). |
| **Provenance is pinned.** | Every skill records a SHA-256 content digest and its source path. A verdict records the digest, so an evidence pack states exactly which skill version produced it. |
| **Injection markers are neutralised.** | Delimiter-escape sequences in skill bodies are defanged so a skill cannot break out of its untrusted-content frame. |

This reuses the model the engine already runs on (§10, "agent proposes, framework disposes") rather
than inventing a second safety story.

## Consequences

* **Gained:** an extensibility seam customers have no other way to get today; per-rule triage depth we
  do not have; an ecosystem of externally-authored content; a credible answer to "can we encode our own
  detection logic?".
* **Cost:** a new untrusted-input surface. Mitigated by the invariants above, which are the point of
  this ADR rather than an afterthought.
* **Explicitly not doing:** authoring a competing standard, or claiming the format as ours. We publish
  skills *in* the format.
* **Not a SIEM.** The format assumes an alert stream from SIEM/EDR telemetry; our findings come from OSS
  scanners and posture snapshots. `rule_id`/CWE/tool is the join key instead. Skills written against raw
  telemetry fields will not match — that is an honest limit, surfaced as "no skill matched", never
  papered over.
