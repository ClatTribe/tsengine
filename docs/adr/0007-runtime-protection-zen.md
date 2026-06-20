# ADR 0007 — Runtime Protection (in-app firewall / RASP), "Zen" parity

- **Status:** **Phase 0 + 0b Accepted + built (2026-06-20)** — the un-gated slices
  shipped: Phase 0 (ingestion + correlation — `internal/crossdetect/runtime.go`,
  `platform.RuntimeEvent`, `POST/GET /v1/runtime/events`, the `attacked` issue
  annotation) and Phase 0b (an observed-under-attack finding escalates into a
  `platform.Incident` regardless of severity floor — `crossdetect.AttackedKeys` →
  `Detector.Reconcile` → `Incident.Attacked`, so detect→respond fires for live attacks).
  **Phase 1 (the managed in-app sensor) remains Proposed — decision required**; do not
  ship the runtime agent until accepted.
- **Date:** 2026-06-20
- **Affects:** §1 (repository identity — "orchestrator over OSS scanners"), §13 (no in-house detection engines), §3 (asset types), the platform (`internal/runner`, `internal/detect`, `internal/crossdetect`), a potential NEW artifact (a runtime sensor that lives inside the customer's app)

## Context

A capability re-survey against **aikido.dev** (2026-06-20) confirms tsengine now
has parity across Aikido's scan-time + posture + remediation surface: SAST, SCA
(+reachability), secrets, malware, IaC, EOL, CSPM, container/K8s, DAST, dedup /
unified issues, **custom exclusion rules** (#255), AutoFix-to-PR + **Bulk Fix**
(#254), SBOM, 14-framework compliance, audit-grade VAPT reports, and **productized
AI pentesting with active exploitation** (ADR-0006). The cross-detection /
unified-platform pillar is saturated.

**One genuinely-differentiated capability remains unbuilt: Runtime Protection** —
Aikido's **"Zen"** (an open-source in-app firewall / RASP, `AikidoSec/firewall`) plus
**bot/abuse protection**. Zen is a library the developer embeds **inside their running
application** (Node, Python, PHP, Java, .NET, Ruby); it instruments dangerous sinks and
**blocks attacks in real time** — SQL/command injection, SSRF, path traversal — and
adds rate-limiting + IP/bot blocking. Aikido advertises it as "in-app firewall blocking
critical injection attacks."

This is **not a scanner**. It is **inline enforcement in the customer's production
request path**. That is a different product muscle from everything tsengine does today,
and it crosses two of our load-bearing invariants:

- **§1 / §13**: tsengine is "an orchestrator over community-maintained OSS security
  tools" — it runs scanners in a sandbox and a platform that consumes their output. It
  has **never shipped code that runs inside the customer's app**. A RASP is exactly
  that.
- **Blast radius**: a bug in a scanner produces a wrong finding. A bug in a RASP **breaks
  or slows the customer's production app** (false-positive blocks a legitimate request,
  or adds latency to every request). The safety bar is categorically higher.

Hence this ADR: shipping a runtime agent is an architecture + safety decision, not a
silent build — the same reasoning that gated the active-exploitation engine (ADR-0006).

## What already exists (so the ADR is scoped honestly)

- **`internal/detect`** — the deterministic detect-&-respond backbone (incidents from
  change between passes, signed into the ledger).
- **`internal/crossdetect`** — correlation glue: it already turns "many signals about
  one issue" into a confirmed, prioritized issue, and bridges findings across surfaces.
- **`internal/runner` + webhooks** — an event-driven ingestion path (provider webhooks →
  re-scan) already exists.

So tsengine already has the **control-plane** machinery (ingest a signal → correlate →
incident → respond → ledger). What it lacks is a **runtime data-plane** sensor.

## Decision required

**Do we enter the runtime-protection category, and if so, how?** Default per §1/§13 is
**no in-house RASP**. The options below are what we would do *if* accepted.

## Options

1. **Decline (stay scan-time + posture + pentest).** Position runtime protection as
   out-of-scope; compete on detect-&-respond breadth, autonomous pentest, and the
   governance spine. Honest and focused; cedes the "block it in prod" story.

2. **Wrap the OSS Zen as the sensor; tsengine is the control plane (recommended if we
   pursue this).** Consistent with §13 ("wrap OSS, never build in-house detectors"): we
   do **not** write a RASP. The customer installs the existing OSS firewall in their
   app; tsengine **ingests its runtime block/attack events** and makes them a
   first-class platform signal. The tsengine value-add is **cross-detection**, not the
   blocking: correlate a runtime-blocked exploit attempt with the scan-time finding for
   the same sink → upgrade that finding's exploitability to *observed-in-the-wild* (a
   far stronger signal than static reachability), open an incident, and prioritize the
   fix. This is pure orchestration glue — adds no detection, keeps §13 intact.

3. **Build an in-house RASP.** Rejected: violates §13, is per-language, and carries
   production blast-radius we have no mandate for. Not best-in-class by construction.

4. **Partner / embed a commercial RASP.** A business-development path, not an
   engineering one; out of scope for this ADR.

## Proposed design (only if Option 2 is accepted)

A **two-phase** plan that front-loads the safe, in-wheelhouse value and gates the
data-plane:

**Phase 0 — runtime-event ingestion + correlation (no new in-app artifact; buildable
without crossing §13).** A normalized runtime-protection event
(`{source_ip, attack_kind, endpoint, sink, blocked, occurred_at, app}`) is accepted at a
new ingestion endpoint and stored as a new signal class. `crossdetect` correlates it
with scan findings on the same endpoint/sink; a confirmed live-attack event bumps the
finding's exploitability and can open an incident via `internal/detect`. A
`runtime_application` (or a meta on an existing app asset) carries the posture. This is
the highest-leverage slice and is **just another event source** — the same shape as
provider webhooks. *It does not make us a RASP vendor; it makes us consume one.*

**Phase 1 — managed runtime sensor (the gated part).** Ship/guide the OSS Zen install
per language and stream its events into Phase 0. This is where production blast-radius
enters (the sensor runs in the customer's app). Requires: a design partner who will run
it in a non-critical service first, an explicit "monitor-only before block" default
(observe + report before any inline blocking), and a kill-switch that disables blocking
remotely (reusing `Tenant.AgentsHalted`-style governance).

## Risks and mitigations

| Risk | Mitigation |
|---|---|
| A false block breaks the customer's prod app | Default **monitor-only** (report, don't block) until the customer opts into enforcement per-route; remote kill-switch for blocking |
| Latency added to every request | Out of our hands for the OSS sensor (it's their benchmark); Phase 0 (ingestion) adds zero in-path latency |
| Scope creep — becomes a RASP vendor | Option 2 keeps us the control plane; the detector stays OSS (§13 intact) |
| Half-built RASP that isn't best-in-class | Don't build one (Option 3 rejected); wrap the OSS firewall |
| New asset type churn | Phase 0 can ride on a meta of the existing app asset; a full `runtime_application` asset only if Phase 1 lands |

## Recommendation

**Defer the runtime sensor (Phase 1); if there is appetite, build Phase 0 now (it's
un-gated).** Phase 0 — ingesting and *correlating* runtime-protection events — is pure
tsengine orchestration, respects §13, adds zero production blast-radius, and delivers the
single most valuable thing tsengine specifically can add to runtime protection:
**closing the loop between what we flagged at scan time and what actually got attacked in
production.** The in-app sensor itself (Phase 1) is a genuine architecture + safety
departure and should wait for a design partner and an explicit greenlight — exactly as
active exploitation did.

Net: tsengine's thesis is the **AI security engineer that detects, proves, and
remediates**. Runtime *blocking* is adjacent; runtime *evidence feeding the brain* is
squarely on-thesis. Recommend pursuing the latter first.

## Consequences

- **Proposing** this ADR implies no code change; §1/§13 are unchanged.
- If **Phase 0** is greenlit: a runtime-event ingestion endpoint + a `crossdetect`
  correlation + an exploitability bump + an optional incident — all additive, all
  grounded, no detector built in-house. CLAUDE.md §18 + §8 (exploitability signal) would
  be updated.
- If **Phase 1** is greenlit (separately): a managed/guided OSS Zen install streaming
  into Phase 0, monitor-only by default, with a blocking kill-switch.
- This ADR is the reference for the runtime-protection boundary, as ADR-0006 is for
  active exploitation.
