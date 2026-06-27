# ADR 0013 — /Protect: managed runtime protection by wrapping OSS Zen

## Status

Accepted (Phase 0 built). This is the productization of ADR-0007's runtime track into the fourth Aikido
pillar — /Protect — without violating §13 (wrap OSS, never build an in-house RASP).

## Context

The Aikido four-pillar comparison (Code · Cloud · Attack · Protect) found tsengine at or beyond parity on
the first three but with **no /Protect pillar**: we *consume* runtime attack events (the Zen-style RASP
sensor streams its block events in via `POST /v1/runtime/events`, correlated by `crossdetect.AnnotateRuntime`
to flag issues attacked-in-the-wild) but we never *blocked*, and we never surfaced runtime protection as a
first-class product surface. The State-of-AI-in-Pentesting report's KF#1 (76% intervened on AI/runtime
behavior) and the buyer's "block attacks in production" expectation make this a real gap.

The tension is §13: a blocking in-app firewall / RASP is a detection-and-enforcement engine, exactly the
kind of thing we do NOT build in-house. So the question is how to claim /Protect honestly.

## Decision

**Wrap, don't build.** Aikido's own runtime firewall — **Zen** (`@aikido/firewall`, MIT-licensed, OSS) — is
an embeddable in-app sensor the customer installs in their own app; it does the blocking, in-process. We are
the **management + telemetry layer** around it, the same posture as every other wrapped OSS tool:

1. **The sensor blocks; we never do.** Zen runs in the customer's app and blocks SQLi/SSRF/path-traversal/
   etc. at the dangerous sink. tsengine ingests its events (already wired) — it does not sit in the request
   path and does not enforce. (§13 holds: consume the OSS signal, never build the RASP.)
2. **A first-class /Protect surface** (`internal/protect`, built): `Compute(events, since, topN)` rolls the
   ingested `platform.RuntimeEvent`s into a runtime-protection posture — which apps are reporting, attacks
   blocked vs monitor-only, block-rate, top attack kinds + most-targeted endpoints. `GET /v1/protect`.
   Grounded (§10): every number is a real ingested event; no events → `active:false` ("no runtime signal
   yet", never "protected"); a monitor-only deployment reports honestly as active with block-rate 0.
3. **Folds into the one platform.** Runtime blocks already become the strongest exploitability signal
   (`AnnotateRuntime` → `Attacked`/`under active attack` incidents). /Protect adds the posture view on top;
   nothing new in the issue/incident pipeline.

The marketing pillar is added under **Security** (per the two-outcome IA, ADR/decision recorded in
`[[product-ia-two-outcomes]]`) once the managed deploy is live — not as a co-equal top pillar.

## Honesty / grounding (§10)

The honest line is explicit: **tsengine does not block in production; the OSS sensor does, and we manage it
and surface what it stopped.** We never advertise blocking we don't perform. A clean app (no events) is "no
runtime signal yet," not "protected."

## Phases

- **Phase 0 (built)** — `internal/protect` posture core + `GET /v1/protect` + the existing
  `POST /v1/runtime/events` ingest + `AnnotateRuntime` correlation. Works today over posted events.
- **Phase 1 (gated)** — the *managed* side: a per-tenant Zen config (which app, block-vs-monitor mode,
  endpoint allowlist) distributed to the customer's sensor, and a connector to pull Zen's event stream
  directly (vs the posted path). The live config-distribution + the `/protect` UX page + the Security-nav
  entry are the follow-on. Bot-protection (Aikido's third /Protect item) rides the same Zen wrap.
- **Phase 2** — device protection is already covered detection-side by `internal/deviceposture` (MDM-lite);
  active device enforcement stays a connector follow-on.

Until Phase 1 ships the managed deploy, the honest status is: tsengine **ingests + surfaces** runtime
protection (the OSS-sensor signal) today; the **managed Zen rollout** is the documented next step.
