# ADR 0026 — Best-in-breed on the OWASP API Security Top 10: what is covered, what is gated, and what is absent

**Status:** Proposed · decision 4 IMPLEMENTED (this change); decisions 1–3 are the build order.
The coverage map is measured from the handlers, not read off the docs.
**Date:** 2026-08-23

## Context

The goal is to be best-in-breed on the **OWASP API Security Top 10 (2023)** for the `api` asset.
Reaching it starts with an honest map of what runs today, and the first attempt at that map was
wrong in a way worth recording.

### The api asset is not thin, and the anchor list says otherwise

Read the anchor tier alone and `api` looks like the weakest asset in the product: two tools,
`nuclei` and `httpx`, against eight for `repository` and five for `container_image`. That reading is
wrong, and it is the reading anyone comparing assets will reach for first.

`anchorNames` is the **no-spec fallback**. The real pipeline is recon → fan-out → escalation
(CLAUDE.md §5.1), and almost everything the asset does lives past the anchor list:

| stage | what actually runs |
|---|---|
| recon | `openapi_spec_ingest` — probes `/openapi.json`, `/swagger.json`, `/v3/api-docs`, `/swagger/v1/swagger.json`, `/api-docs`, `/openapi.yaml` on **every** scan |
| fan-out | `schemathesis` against the resolved schema · `nuclei` list-mode over the declared operations **plus the host root** · `sqlmap` per param-bearing endpoint, with an injection marker |
| escalation | spec → `kiterunner` (undocumented routes) · `/graphql` → `inql` · empty surface → `kiterunner` |
| on demand | `internal/apiauthz` differential BOLA/BFLA prober |

The `sqlmap` wiring in particular is not a tag change: it rewrites `/users/v1/{username}` to
`/users/v1/name1*` because sqlmap judges a brace token non-dynamic and never injects it. That was
found by running it against VAmPI, and the handler records the measurement — tags alone took raw
findings from 1 to 12 while recall stayed at **0.000**.

So the gap is not "the api asset does little". It is narrower and more specific.

### The measured coverage map

| # | OWASP API Top 10 (2023) | Covered by | Status |
|---|---|---|---|
| API1 | Broken Object Level Authorization | `apiauthz` differential prober; `webagent.bola_probe` | **gated** |
| API2 | Broken Authentication | `nuclei` `jwt,oauth` tags | signature-only |
| API3 | Broken Object Property Level Authorization | `webagent.privesc_probe` (self-privesc only) | **partial + gated** |
| API4 | Unrestricted Resource Consumption | — | **absent** |
| API5 | Broken Function Level Authorization | `apiauthz` | **gated** |
| API6 | Unrestricted Access to Sensitive Business Flows | — | out of reach (needs business semantics) |
| API7 | Server Side Request Forgery | `nuclei` `ssrf` tag | covered |
| API8 | Security Misconfiguration | `nuclei` `misconfig,config,exposure,files`; `schemathesis` | covered |
| API9 | Improper Inventory Management | `kiterunner::undocumented-route` | covered |
| API10 | Unsafe Consumption of APIs | — | absent |

**"Gated" is the finding, not "absent".** API1 and API5 sit at the top of the list, the product has
a real differential prober for both, and it never fires in a normal scan — `apiauthz` needs an owner
to configure two identities and consent first. The flagship capability is the one a prospect is
least likely to ever see.

### What "best-in-breed" would have to mean here

CLAUDE.md §14.2 rule 5 is unambiguous: an in-house answer key measures whether the fixtures and the
code agree, not whether the product works.

**A first draft of this section said the API ground truth "contains two entries" and was wrong.**
It read `bench/pentest_e2e/vampi.groundtruth.txt` (which does hold two, for a different harness) and
missed `fixtures/api/vampi/fixture.json` — which is careful work: it records **all nine** defects
VAmPI documents, each with its CWE and the component that detects it or a plain "NOT COVERED", and
carries a note explaining that `must_find` is deliberately narrower because *"a fixture that can
never pass is a permanently-red gate rather than a measurement"*.

The real defect is one level up, and it is this repo's most familiar shape. **Nothing read it.**
`bench.Fixture` had no field for `documented_vulnerabilities` or `ground_truth_note`, so
`json.Unmarshal` dropped both silently. The note says the denominator exists *"so the gap stays
visible instead of being quietly defined away"* — and it was visible only to someone who opened the
JSON. No report has ever mentioned it.

The consequence is precise: a fixture whose `must_find` holds one token scores
`detection_recall: 1.000`, which reads as *we find everything*, when the honest statement is *we find
one of the nine defects this target deliberately contains*.

## Decision

### 1. Close API3 by reusing `internal/dataclass`, not by writing a detector

Excessive data exposure is the classic API3 finding: an endpoint returns fields the caller should
never see. The product already has a built, tested classifier for exactly this question —
`internal/dataclass` — which finds `pii`/`phi`/`pci`/`secret`/`auth` in a set of named columns with
sampled values, Luhn- and range-checks structure rather than shape, ranks a value signal above a
name signal, and emits evidence that never echoes a raw value.

An API response is that same shape: the endpoint is the object, the JSON fields are the columns.
`apiauthz.HTTPProber` **already captures response bodies** (capped at 64 KiB), so the plumbing
exists and the work is the glue.

This matters for §13: it is **reuse, not a new in-house detection engine**, so it needs no §13
exception. Writing a second field classifier when a mutation-tested one exists would be the actual
violation.

**The grounding line, which is what makes it shippable:** returning personal data is not by itself a
defect — a user's own profile endpoint returns their own email, correctly. So the finding is
conditional on something we can observe rather than guess:

- `secret` / `auth` classes in a response → a finding **regardless of authentication**. An API
  should not return a password hash, a private key or a session token in any body.
- `pii` / `phi` / `pci` → a finding only when the response came back on a request we sent **with no
  credentials**, which the prober knows because it controls what it sent.

Anything else is reported as an observation, not a vulnerability.

### 2. API4 needs the RoE gate before it needs code

Unrestricted Resource Consumption is genuinely absent and looks like the easiest gap to close: send
N requests, look for a 429 or a rate-limit header. It is not, and the reason should be written down
before someone implements the easy version.

A burst probe is **load generation against a customer's production API**. CLAUDE.md §18.1 puts an
absolute destructive ban in the RoE Guard, and "we sent a few hundred requests to find out whether
you throttle" is the shape that ban exists for. It also cannot prove what it wants to: no 429 within
N requests means no limit **below N**, never no limit.

So API4 is deliberately **not** proposed as a scanner check. If it is built it belongs in
`internal/pentest` behind `RoE.ActiveAuthorized()` — explicit consent, a named authoriser, a bounded
request budget — and its finding must be phrased as the observation it is ("no throttling observed
at N requests in T seconds"), never as "no rate limiting".

### 3. API1/API5: make the prober discoverable, do not try to automate the credentials

The gate on `apiauthz` is not an oversight; a differential authz test needs two real identities and
nothing can invent them. The gap is that nothing ever **asks**.

`apiauthz.ProposeOperations` already exists and proposes candidate operations from an ingested spec.
The change is a prompt after the first API scan that finds a spec — "we can test these 6 operations
for BOLA/BFLA; add two test identities" — turning a setup task nobody discovers into one someone
declines on purpose.

No detection changes. This is the highest-value item on the list and it is a UX change.

### 4. Make the denominator readable, and key it to the Top 10 — IMPLEMENTED

Not "extend the ground truth": the ground truth was already right. The work is to stop discarding it.

- `bench.Fixture` gains `DocumentedVulnerabilities` and `GroundTruthNote`, so the fields the fixture
  has always carried are parsed instead of dropped.
- `DocumentedVuln.OWASPAPI` maps each class to its 2023 item. **SQL injection is deliberately left
  unmapped** — Injection was API8:2019 and was folded away in the revision, so giving VAmPI's
  headline defect a 2023 number would invent coverage of an item it does not exercise. A test pins
  that, because it is the kind of blank someone tidies up.
- `Score.Scope` reports `documented / detectable / measured`, names the uncovered classes rather than
  counting them, and partitions the mapped items into covered and uncovered — so a recall figure
  never travels without the denominator that qualifies it.
- `DocumentedVuln.Covered()` reads the **prose** in `covered_by` rather than a parallel boolean, so
  a field reading "NOT COVERED" cannot sit beside `covered: true`.

**An item with one covered class and one uncovered class counts as UNCOVERED.** That is the rule the
implementation turns on and the one a careless version gets backwards, because the covered class is
encountered first. It is mutation-verified: crediting the partial makes VAmPI report API2 as covered,
and the test fails naming it.

Measured on VAmPI with the mapping applied — the first per-item number this product has had:

```
mapped by VAmPI : API1 API2 API3 API4 API5     (five of ten; it exercises no others)
covered         : API1 API5
uncovered       : API2 API3 API4
```

crAPI remains the second corpus (CLAUDE.md §14 names both) and reaches items VAmPI does not. API6
and API10 are exercised by neither, which is consistent with decision 5 below: they are not proposed,
so nothing claims them.

This baseline is recorded **before** decisions 1–3 land, so their effect is falsifiable. Fixing a
benchmark and the thing it measures in one commit makes the result unfalsifiable — §14.2 rule 5.

## Invariants

1. **The anchor list is not the coverage story for a recon→fan-out asset.** Any comparison of assets
   by anchor count is wrong for `api`, `web`, `ip` and `domain`.
2. **An absence of observation is never reported as an absence of the thing.** No 429 in N requests
   is not "no rate limiting"; no classified field in a sampled body is not "no sensitive data".
3. **A new detection capability reuses a tested component or wraps OSS.** A second implementation of
   a question the tree already answers is the §13 violation, whoever writes it.
4. **Active load generation lives behind the RoE Guard**, never in a scanner's default path.
5. **A Top 10 claim requires a per-item score against a corpus we did not write.** Recall on a
   two-item ground truth is not evidence about ten items.

## Consequences

**The headline is smaller than "we are not best-in-breed on APIs".** Four of the ten are covered,
three are gated behind a real capability, two are out of reach without business context, and one is
genuinely absent. The work is closing one gap, un-gating one capability, and building a scoreboard —
not building an API scanner.

**Decision 3 is the highest value and the least code.** The differential prober is the thing
competitors do not have; it is invisible because nothing offers it. That is a product gap wearing an
engineering costume.

**API6 and API10 are not proposed at all.** API6 needs to know which business flows matter, and
API10 needs to know which upstream APIs the target consumes — neither is observable from outside,
and a plausible-looking check for either would manufacture exactly the false confidence §10 forbids.
They stay uncovered and are stated as uncovered.

**What this ADR does not do.** It does not claim the api asset is weak — the measured map above
says otherwise, and the first draft of this document said the opposite because it read the anchor
list and stopped. It also does not touch the offensive path: ADR 0024 assesses web/api **offense**
via `internal/pentest` and `internal/webagent`, which is a different axis from the `api` asset's
detection coverage measured here.
