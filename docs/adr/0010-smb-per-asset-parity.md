# ADR 0010 — Be THE SMB product, per asset: coverage, depth, accuracy

**Status:** accepted (2026-06-22) · phased implementation in progress
**Goal:** for each asset an SMB buys, reach parity with the SMB-category leader on (a) coverage +
depth and (b) detection accuracy (FP/FN), wrapped in a modern, agentic, sleek UX.

Bounds (unchanged): wrap OSS where it exists (§13); the **one exception** is where no standalone
OSS exists — API authz logic (§5.2 names this explicitly) — which warrants an in-house specialist
*with this ADR*. Everything is grounded (§10), platform-additive (§18.2 inv 1), and ships with a
deterministic, offline-testable core + an honest credential/sandbox gate for live execution.

## Per-asset gap → design → phase

| Asset | SMB leader | The gap (coverage/depth/accuracy) | Design (backend + UX) | Phase |
|---|---|---|---|---|
| **api** | Akto, APIsec | **BOLA/BFLA authz-logic** (the §5.2 no-OSS gap) — our thinnest asset | `internal/apiauthz`: differential authz tester (two identities, attacker-hits-victim-object predicate); gated live prober; `/assets` API-authz config (2 identities) + findings | **1 (this)** |
| **repository** | Aikido, Snyk | **PR-inline review bot** + IDE — detection→developer-loop | diff→findings mapper + `connector.GitHub` inline-comment + check-run; webhook-driven; `/settings` PR-checks toggle + activity | 2 |
| **web_application** | Probely, Detectify | **Authenticated-scan depth** (SPA/OAuth recorded login) | recorded-login capture → session seed into the fan-out; `/assets` "add login flow" UX | 3 |
| **container_image** | Aikido, Snyk Container | **Registry auto-watch** (scan on push) + base-image upgrade advice | registry connector (ECR/GHCR) → image inventory → scan-on-new-digest; `/assets` "connect registry" | 4 |
| **cloud_account** | Wiz, Aikido Cloud | (largely done — ADR 0009) full-DSPM classification, Phase-4b authz eval | follow-ons in ADR 0009 | (0009) |
| **identity** | Nudge, Push, Vanta | Real-time identity-threat + SCIM deprovisioning | `operate` event stream + a deprovision `Apply`; identity timeline UX | 5 |
| **SaaS posture** | Nudge, Wing | **Breadth** (Atlassian/Zoom/Salesforce/M365-SaaS) + shadow-IT OAuth discovery | extend `internal/sspm` connectors; SaaS inventory + app-grant graph UX | 6 |

Cross-cutting (every asset): **accuracy** — keep extending the FP-control bench (§14.1.1) +
corroboration to drive measured FP/FN down; **agentic UX** — every new finding class flows into the
unified-issues / auto-triage / consensus machinery already built.

## Phase 1 (this PR) — API BOLA/BFLA authz specialist

**Why in-house (the §13 exception):** object- and function-level authorization is *business logic*
— "can user B read user A's invoice?" — with no standalone OSS detector (nuclei/schemathesis fuzz
inputs, not authz). §5.2 already records this as the one place an in-house specialist is warranted.
`classifyOp` (internal/asset/api) already routes operations to `idor`/`bfla`/`mass_assignment`; this
builds the specialist those routes were waiting for.

**Design — a differential authz test (benign, predicate-checked, low-FP):**
- Two authenticated **identities**: a *victim* (owns an object / is privileged) and an *attacker*
  (a different, lower-privilege principal).
- **BOLA/IDOR**: replay the victim's object request *as the attacker*. Bypass ⟺ the attacker gets
  `2xx` **and** the victim's data comes back (a marker from the victim's object appears, or the body
  matches the victim baseline). A `401/403/404` for the attacker = correctly denied → **no finding**.
- **BFLA**: the low-privilege attacker invokes a privileged function. Bypass ⟺ `2xx` (not denied).
- **Accuracy:** the predicate only fires on a *proven* bypass (status + victim-data correlation),
  never a maybe — so a confirmed finding is `verification: verified` (the XBOW no-FP bar). It reads
  the victim's *own* object only (benign; no exfil beyond proving access), never writes.

**Backend:** `internal/apiauthz` — `Plan(ops, victim, attacker)` builds the test set from the
classified operations; `Evaluate(test, baseline, attacker)` is the offline-testable differential
predicate; `Run(ctx, plan, prober)` executes via an injected `Prober` (live HTTP, gated like the
active-exploit driver — off unless the operator enables it + consent) and emits findings. Fully
offline-tested with a fake prober; the live prober + asset-escalation wiring + the two-identity UX
are the api Phase 1b/1c slices.

**Honest gate:** sending requests to a customer's API is *active* testing — the live prober stays
behind the same explicit-consent + `TSENGINE_ACTIVE_EXPLOIT` gate as ADR 0006/0008. Without it, the
plan is reported as un-run leads (never a falsely-confident result).
