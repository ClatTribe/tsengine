# Series A scope — what stays on, what gets switched off

Proposal for review. **Nothing is disabled by this document.** Turning a feature off is visible to
anyone already using it and is not cheaply undone, so the list needs a decision before the flags go in.

## The test

The tempting test is "does this sound like an enterprise feature?" That test is wrong here, and
checking it against the compliance crosswalk is what showed why.

**The actual test: does a Series A customer's SOC 2 evidence, or their attack surface, depend on it?**

Two things only survive under the real test and would have been cut by the lazy one:

| Module | Looks like | Actually |
|---|---|---|
| **TPRM** (vendor risk) | enterprise procurement | **The only source of SOC 2 `CC9.2` evidence.** That control appears nowhere in the CWE crosswalk — no scanner produces it. Cutting TPRM removes vendor-management evidence from every SOC 2 report we generate. |
| **Device posture** (MDM-lite) | you already have Kandji | Contributes `CC6.1/6.6/6.7/6.8/7.1`. It is the only endpoint-encryption evidence (`CC6.7`) we have. |

The CWE crosswalk — everything code, cloud and web scanning produces — covers just **9 SOC 2
controls**: `A1.1, A1.2, CC6.1, CC6.3, CC6.6, CC6.7, CC6.8, CC7.1, CC8.1`. The modules that look
peripheral are carrying the controls scanners cannot reach. SOC 2 readiness is the Series A
deal-blocker, so anything feeding it stays.

---

## Keep on (serves the wedge or the audit)

| Area | Why |
|---|---|
| Code security — SAST, SCA, secrets | The core of what they run |
| Cloud posture — AWS/GCP/Azure, CIS | Second half of the wedge |
| Web / API scanning | Their product's actual attack surface |
| Identity — Google Workspace, M365, Okta | They have exactly one of these |
| Cross-surface attack paths | The differentiating claim |
| Compliance — SOC 2 + whatever they scope | The deal-blocker |
| **TPRM** | Sole source of `CC9.2` (see above) |
| **Device posture** | Endpoint-encryption evidence `CC6.7` |
| OSINT external exposure | Cheap, credential-free, attacker's-eye |
| SSPM — GitHub org | Live sync already reuses their existing connection |

## Propose switching off (serves a different buyer, contributes no evidence)

| Area | Who it is for | Evidence contribution |
|---|---|---|
| **Practitioner / MSP layer** — operator console, cross-tenant desk, act-on-behalf | Channel partners running us for their clients | None |
| **vCISO program** — risk register, audit engagements, policy publish/ack | A company with a CISO and a board risk committee | None |
| **MDR service-ops** — escalation matrix, SLA policy, maintenance windows, SOC metrics, on-call roster | A company with a SOC and an on-call rota | None (verified: no compliance mapping in these packages) |
| **`mobile_application` asset** | Already deprecated in CLAUDE.md §3 | None |
| **Runtime event ingest** | Needs an in-app sensor they do not run | None |

Rough surface: five nav destinations and a Settings section, none of which a 30-person engineering
team has a use for, all of which they currently have to read past.

## Not a cut — a default

**The 22 frameworks stay.** `Tenant.TargetFrameworks` already exists and `/compliance/scope` already
lets a customer pick what they are pursuing. The fix is that unscoped frameworks should not be rendered
by default, which is a display default, not a capability change. Deleting 20 frameworks would break the
one customer who genuinely needs HIPAA.

## How to switch off, if approved

A build-tag or dead-code approach loses the compile check and rots. Use the mechanism already in the
codebase: an entitlement/feature predicate, so a disabled area is

1. **absent from the nav and the API surface** — not visible, not callable,
2. **still compiled and still tested** — no rot, no bit-rotted revival,
3. **re-enabled by one flag** when a customer needs it, with no code archaeology.

`pkg/platform.Entitlements` is the natural home: it is already the single source of truth for what a
tenant may reach, already read by both the API and the frontend, and already carries the
plan-limits pattern this would extend.

## Sequence

1. Get a decision on the switch-off list (this document).
2. Add the predicate + the flags; keep every package compiled and tested.
3. Hide the nav destinations; make the endpoints 404 for a tenant without the flag.
4. Re-check the SOC 2 report on a scoped tenant to confirm no control lost its only evidence source.

Step 4 is not optional. The TPRM finding above is exactly the failure it is there to catch.

---

## 6. Found by walking the product: the ingest half never reaches the approval desk

**Evidence.** A workspace seeded through the credential-free ingest paths — Vercel, device posture,
vendor risk — produced 6 findings and **0 proposed actions**. `GET /v1/approvals` returned `[]`.
Nothing ever reached the Inbox.

**Cause.** Remediation is proposed only in `runner.RescanTenant` (the engine scan path). None of the
five ingest handlers (`vercel`, `deviceposture`, `tprm`, `osint`, `saasposture`) call the proposer, and
`platformapi.Deps` carries no desk or proposer to call.

**Why it matters more than it looks.** These are exactly the paths a Series A customer uses *first* —
they need no OAuth app and no cloud credentials. So the surfaces most likely to produce a new
customer's first findings are the ones where the human-in-the-loop approval loop never starts. And the
dashboard tells them, in those words: *"TensorShield is triaging these and will prepare fixes you can
approve."* For these findings it never does.

**It is tractable.** `remediate.Propose` already has a `default` case that returns a generic ticket
action for a finding with no asset, so the proposer handles this shape today. The work is:

1. carry a proposer + desk on `platformapi.Deps` (they exist; the API layer just never got them), and
2. run ingested findings through it after `enrichFindings`, the same way the engine path does.

**Why it is not done in this pass.** It touches §18.2 invariant 3 — the only write path is
`connector.Apply`, reached only after a HITL gate. Wiring a new proposer into that machinery deserves
its own change with its own review, not an addendum at the end of an audit. Flagged for a decision.
