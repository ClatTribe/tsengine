# ADR 0027 — The control plane: did their defences catch us, would they have stopped this, and can we use them today

**Status:** Proposed — **design only, no code.** Scopes the one integration that unlocks the three
remaining CTEM gaps at once. Written because the temptation here is to build the flattering half
(read a WAF policy, declare the exposure mitigated) and skip the half that makes it true.

**Date:** 2026-08-23
**Depends on / reconciles:** CLAUDE.md §10 (evidence grounding), §13 (wrap OSS, don't build detectors),
§18.2 inv. 2/3/6 (tenant isolation, the single gated write path, secret sealing), ADR 0006 (RoE +
predicate disposal), ADR 0024 (the verification ladder), ADR 0025 (field evidence — calibration from
outcomes). **Supersedes:** nothing.

---

## Context

Gartner's 2026 Adversarial Exposure Validation guidance defines the category by one test: does the
technology deliver evidence of whether an attacker **can circumvent the preventive and detective
controls you already run**. tsengine proves exploitability and proves closure. It never asks whether
the customer's EDR, SIEM, WAF or NGFW noticed.

An audit of all five CTEM phases found three gaps, and they are not three projects:

| Gap | Phase | The question |
|---|---|---|
| Control / detection validation | Validation | *Did it catch us?* |
| Compensating-control awareness | Prioritization | *Would it stop this?* |
| Mitigate-now targeting | Mobilization | *Can we use it right now?* |

All three need the same thing — knowing which controls this customer actually runs — and they
compound: a control we have validated is a control we can trust in a prioritization decision, which
is a control we can point a mitigation at.

### What already exists, and how close it is

Closer than it looks, which is the reason to scope this deliberately rather than start coding.

- **`platform.RuntimeEvent` carries `Blocked bool`** — *"did the sensor block it (vs monitor-only)"*.
  Populated, ingested at `POST /v1/runtime/events`, and read in exactly one place
  (`crossdetect.go:235`) to produce a raw count. It reaches no screen and no decision. **The one
  signal we hold that says a control WORKED is currently inert.**
- **Probes already carry a correlatable canary.** `pentest.ActiveDriver` takes a `canaryFn`, and the
  platform supplies `engID + "-" + i` — unique per probe and traceable to the engagement. That is the
  join key detection validation needs, and it exists today.
- **`internal/connector`** already defines the OAuth → Discover → Watch → Apply shape, with sealed
  secrets and per-connection quarantine.
- **`interim_mitigation`** (eight classes) is written conditionally *because* we cannot see the
  customer's controls. It is the surface that gets to filter once we can.

**A prerequisite this surfaced:** the RE-ATTACK canary is `tsrt<shortTenant><index>`, which is
tenant-scoped but **not run-unique** — two runs reuse index 0. Detection correlation needs a probe
identifier unique across runs, so that must be stamped before C1 can use the re-attack path.

---

## Decision

Add a **read-only control-plane integration** and three capabilities over it.

**Read-only is structural, not a default.** The existing `Connector` interface carries `Apply`, the
platform's single gated write path. A control-plane connector must not have one: we read what
controls exist and what they observed. We do not write firewall rules into a customer's estate, and
an interface without the method cannot be talked into it later.

### C1 — Detection validation: *did it catch us?*

When a validated probe fires, ask whether the customer's controls produced a matching alert, joining
on the probe's canary within a bounded window.

**The invariant that matters, and the one most likely to be traded away: absence of an alert is NOT
absence of detection.** Silence has at least four causes — telemetry latency, a wrong correlation
window, a connector without the permission to see the alert, or a genuine miss. Reporting silence as
*"your EDR missed this"* is a false accusation about someone else's product, made from our own blind
spot. So a miss is only ever claimed when the pipeline is demonstrably working (a control-of-the-
control: something we know SHOULD alert did), and otherwise the answer is `undetermined`, which is
this ADR's rung equivalent of §10's *"we could not look"*.

### C2 — Compensating controls: *would it stop this?*

Read control configuration and report whether an existing control plausibly mitigates an exposure,
as a prioritization input.

**This maps onto ADR 0024's ladder and must not skip a rung.** Reading a WAF policy yields
`config_possible`: the policy as configured would match. Only firing a probe through it yields
`confirmed_blocked`. Competitors sell the first as the answer; our differentiator is that we can
reach the second, and collapsing them would discard exactly the advantage.

**A compensating control never suppresses a finding.** It annotates and reprioritizes. A control can
be misconfigured, bypassed, in monitor-only mode, or removed tomorrow — and the failure mode of
suppression is correlated: one popular control silently hides the same class for every customer.

### C3 — Mitigate-now targeting

Filter `interim_mitigation` to controls the customer actually runs, and stop phrasing them
conditionally where we now know. Smallest of the three; falls out of C2's inventory.

### Invariants

1. **Read-only. No `Apply`.** Not a policy — an interface without the method.
2. **Undetermined is a first-class answer.** Applies to every capability; a negative needs positive
   evidence the pipeline worked.
3. **Config-read is `config_possible`, never `confirmed`.** The ladder holds (ADR 0024).
4. **Never suppress, only annotate.** As everywhere else in this codebase.
5. **Ingest the minimum.** Ask "did an alert matching this canary fire in this window", not "stream
   us your SIEM". A security product that vacuums a customer's detection telemetry has made itself a
   more attractive target than the thing it protects, and §18.2 inv. 2 makes the blast radius of a
   mistake tenant-wide.
6. **Sealed like any credential** (§18.2 inv. 6), and quarantinable per connection.
7. **Validated results feed ADR 0025.** Whether a control caught us is a field outcome, so control
   efficacy gets calibrated from evidence over time rather than asserted from a policy read — which
   is the pairing no competitor currently has.

### Sequencing — and the first step needs no connector at all

```
S0  make the re-attack canary run-unique                        (prerequisite, XS)
S1  correlate canaries against the EXISTING RuntimeEvent push   (C1, no connector — S)
    ...customers already running a sensor get detection validation with zero new integration
S2  read-only inventory connector: what controls exist          (C2 foundation, M)
S3  compensating-control annotation at config_possible          (C2, M)
S4  probe-through-control to reach confirmed_blocked            (C2 upper rung, M)
S5  filter interim_mitigation to controls in inventory          (C3, S)
```

S1 is the disproportionate one: the ingest, the canary and the finding join all exist, so the
cheapest version of the category-defining capability is a correlation, not an integration.

---

## What this ADR does NOT decide

- **Which control planes first.** EDR, SIEM, WAF and NGFW are four different integration surfaces
  with different data models. A product call, not an engineering one.
- **Whether to ship C2 on config-read alone.** It is what competitors sell and it is genuinely useful,
  but it is the rung below what we can reach. Shipping it first risks the stronger claim never being
  built because the weaker one already demos well.
- **Pull vs push beyond S1.** S1 is push (their sensor posts to us). S2+ implies pull, which implies
  credentials.

## Consequences

- **Positive:** closes the category-defining gap; the three capabilities compound; S1 delivers value
  with no new credential surface; ADR 0025 makes our control-efficacy claims verifiable over time,
  where the incumbents' rest on a policy read.
- **Negative:** a real credential surface from S2 onward, on systems whose telemetry is more sensitive
  than most of what we already hold. Invariant 5 exists because that risk is asymmetric.
- **Neutral:** no detection logic is added (§13 holds) — this reads controls and correlates, and the
  detectors remain the OSS tools.

## Open questions

1. **The correlation window.** Too short reports false misses; too long correlates unrelated alerts.
   It is likely per-control-plane and should be measured rather than guessed.
2. **What proves the pipeline is working** for invariant 2 — a periodic known-benign probe that
   SHOULD alert is the obvious candidate, and it is itself an active action needing RoE treatment.
3. **Does a validated compensating control change severity, or only rank?** Rank is safer; severity
   feeds SLA clocks and compliance, and a control failing silently would then relax a deadline.

## Status

| Item | Effort | Risk | Status |
|---|---|---|---|
| **S0** run-unique re-attack canary | XS | none | Proposed — prerequisite |
| **S1** canary ↔ RuntimeEvent correlation | S | low (no new credential) | Proposed — **start here** |
| **S2** read-only control inventory | M | credential surface | Proposed — needs the plane decision |
| **S3** compensating annotation (config_possible) | M | **medium** — the rung-skipping temptation | Proposed |
| **S4** probe-through-control (confirmed_blocked) | M | active testing, RoE-gated | Proposed |
| **S5** mitigate-now filtering | S | none | Proposed — falls out of S2 |
