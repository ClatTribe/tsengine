# ADR 0028 — Scoping and Mobilization: the two CTEM phases this campaign under-built

**Status:** Proposed — G1 implemented in the same PR; G2 and G3 scoped, not built.

**Date:** 2026-08-23
**Depends on / reconciles:** CLAUDE.md §0 (rank by customer value), §10 (grounding), §18.2 inv. 2
(tenant isolation), ADR 0024 (coverage matrix), ADR 0025 (field evidence), ADR 0027 (the control
plane — where the Prioritization gap lives). **Supersedes:** nothing.

---

## Context

A per-capability audit against CTEM's five phases, run after shipping six gap-closures, found the
remaining holes are **not evenly distributed**. They cluster at the two ends:

| Phase | Capabilities checked | State |
|---|---|---|
| **Scoping** | boundary · crown jewels · business-service map · success metric | **2 of 4** |
| Discovery | known + shadow assets · vulns · misconfig · identity · creds · permissions · third-party | 8 of 8 (identity wraps no OSS — depth, not absence) |
| Prioritization | threat intel · criticality · attack path · exploit proof · compensating controls | 4 of 5 (the fifth is ADR 0027) |
| Validation | exploit · detection · prevention · retest · continuous | 5 of 5 |
| **Mobilization** | ticketing · ownership · SLA · guidance · interim mitigation · progress | **5 of 6** |

That shape is a fact about how this campaign was run, and worth stating rather than presenting the
result as a plan. Validation is the phase that is fun to build and the one competitors compete on, so
it got six PRs; Scoping is a data-model question and Mobilization is plumbing, so they got none. The
under-built phases are the ones nobody demos.

**Why it matters commercially rather than tidily:** the audit's own competitor research kept
returning the same line — a platform that cannot route a finding to the team that owns it wastes the
prioritization it just did. Getting Validation right and Mobilization wrong produces an excellent
list nobody acts on.

## Decision

Close the three decision-free gaps. The Prioritization gap (compensating controls) stays in ADR 0027
because it genuinely needs the control-plane choice; these three need only building.

### G1 — Asset ownership (Mobilization) — **implemented in this PR**

`platform.Asset` carries `ID`, `TenantID`, `ConnectionID`, `Type`, `Target`, `Meta`, `DiscoveredAt`.
There is no owner. `Owner` exists on `Risk` and `Policy` — the vCISO artifacts — so the product can
say who accepted a risk and cannot say who should fix the finding underneath it.

`Asset.Owner` and `Asset.Team`, surfaced on the proposed action and carried into the filed ticket.

**The invariant: an unowned asset says so.** The tempting default is to fall back to the tenant owner
so every ticket has an assignee. That manufactures accountability — someone is named who never agreed
to it, and the real answer ("nobody owns this") is exactly what a scoping exercise needs to surface.
Unowned is reported as unowned.

### G2 — Business-service grouping (Scoping) — scoped, not built

CTEM scoping means mapping critical business SERVICES to the assets that carry them. We have
`DataTier` per asset, which is a decent proxy for crown-jewel identification and is not the same
thing: "this repository is tier 1" does not say *checkout* depends on it, and it is the service that
has an owner, an SLA and a board-level consequence.

Deliberately not built here. It is a data-model change with real product surface (who defines a
service, how assets join one, what happens when they overlap), and doing it badly — a free-text tag
nobody maintains — is worse than the honest absence, because a stale service map reads as scope.

### G3 — Program-level exposure objective (Scoping) — scoped, not built

Scoping asks how success is measured. We have per-severity SLA targets and, since the exposure-trend
work, a real series. What is missing is a stated objective to read that series against: without one,
a trend is a chart, and "is this good?" has no answer on the page.

Not built for a specific reason: an objective the product invents is a number the customer never
agreed to, and one they set is a commitment they must be able to change without it looking like
moving the goalposts. That needs a product decision about whether the objective is per-severity, per
service (so it depends on G2), or estate-wide.

## Invariants

1. **Unowned is a first-class answer** (G1). Never fall back to the tenant owner.
2. **Ownership annotates; it never gates.** A finding on an unowned asset is still a finding, still
   ranked, still ticketed. Ownership decides where it goes, never whether it counts.
3. **Owner is not a credential.** It is contact metadata like `platform.Contact`, stored plain, not
   sealed — and it must not become an authorization input, or an unowned asset becomes an
   unprotectable one.

## Consequences

- **Positive:** the prioritization the product already does reaches a named human; the audit's own
  finding — that this campaign built one phase and neglected two — is recorded rather than quietly
  corrected.
- **Negative:** G1 alone does not give routing to a *team* in the ticketing sense (assignee mapping
  per tracker); it puts the owner in the ticket body and on the desk, which is where it is useful
  without a per-tracker identity mapping.
- **Neutral:** no detection logic changes (§13 holds).

## Status

| Item | Effort | Status |
|---|---|---|
| **G1** asset ownership | S | **Implemented here** |
| **G2** business-service grouping | M | Proposed — needs a product decision on service definition |
| **G3** program exposure objective | S–M | Proposed — depends on G2 if per-service |
| compensating controls | M | **ADR 0027**, blocked on the control-plane choice |
