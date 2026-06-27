# tsengine — UI/UX & Productization Proposal

**Question asked:** webappsec/ is the SaaS wrapper built for *strix* — can it be reused
to productize *tsengine*, and what should the UI/UX be?

**Verdict (TL;DR):** **Yes — fork webappsec, don't rebuild.** ~90% of it is
engine-agnostic and already renders a finding schema near-identical to
tsengine's contract. The strix coupling is concentrated in **one worker file**.
The real net-new work is the part tsengine uniquely needs: the **L1 (security)
vs L2 (developer) dual-view**, the **tool-replay "investigate"** surface, and
**signed-evidence/attestation** UI. This doc covers the reuse evaluation, the
multi-tenant architecture (Goal 1), the two-layer UI/UX (Goal 2), landing
(Goal 3), and a phased plan.

---

## 1. What webappsec already is (the asset)

A 3-tier multi-tenant SaaS, branded "TensorShield — AI security & compliance engineer":

| Tier | Tech | Role |
|---|---|---|
| Frontend | **Next.js 14 App Router** (Vercel), Tailwind, custom components, `lucide`, `react-markdown`, Supabase realtime | UI + ~90 API routes |
| Data plane | **Supabase**: Postgres + **RLS**, Auth (MFA/OAuth), **pgsodium Vault**, Storage, **Realtime** | multi-tenant data + secrets |
| Compute | **Python worker** (Fly.io) + **`pg_notify`** queue → spawns **one container per scan** | runs the engine |
| Billing | **Stripe + Razorpay** (dual-currency, GST/VAT) | metering by scan cost/tokens |

Its founding principle (webappsec `CLAUDE.md`) is exactly tsengine's seam:

> *"Strix is the source of truth, webappsec is a wrapper… The one exception:
> multi-tenant isolation (RLS, org_id keying, vault, real-time filtered by org)
> is the wrapper's exclusive responsibility. Strix is single-tenant by design."*

tsengine is **also** single-tenant (a CLI + per-scan sandbox). The wrapper's job —
make it safe + scalable across hundreds of orgs — is identical. **And the
integration contract webappsec standardized on is literally `vulnerabilities.json`**
— which tsengine already emits as a frozen, signed schema.

---

## 2. Reuse evaluation — fit & gap

### 2.1 The engine seam is one file
The strix coupling lives almost entirely in `webapp/worker/src/strix_worker/runner.py`
(~2,600 lines): how the subprocess is invoked (`_build_cmd`/`_build_env`, `STRIX_*`
env, exit-code convention) and the `vulnerabilities.json` field mapping + satellite
artifacts (kg.json, patches.jsonl, run_meta.json). Everything else — RLS, Vault,
queue, realtime, storage, billing, auth, **and the frontend** — never references
strix.

**tsengine is a *cleaner* fit than strix was.** webappsec had to fall back to
parsing strix's markdown/events; tsengine emits a **frozen, versioned,
signed** `vulnerabilities.json` (`findings_raw` + `findings_enriched` +
`l15_audit_log` + `attestation` + `corpus` + `anchors_fired`). The worker's
"happy path" is already "engine produces findings JSON" — we replace strix's
field names with tsengine's and delete the artifact zoo.

### 2.2 Reuse matrix

| Component | Reusability | Action |
|---|---|---|
| Supabase RLS (`org_id` JWT claim), `custom_access_token_hook`, role model | **as-is** | keep |
| pgsodium Vault + security-definer worker RPCs (creds never plaintext) | **as-is** | keep |
| `pg_notify` queue, listener, claim/heartbeat/sweep scaffolding (~80% of worker) | **as-is** | keep |
| Supabase Realtime (per-scan / per-org channels) | **as-is** | keep |
| Auth (MFA/OAuth), billing (Stripe+Razorpay), Storage | **as-is** | keep |
| `finding-card.tsx` (renders severity, KEV/EPSS, CWE/CVSS, verification_status, confidence, kill-chain, reasoning, patch preview, triage) | **~95%** | reuse; re-map fields |
| `scan-live-view` (realtime agent/tool timeline, phase progress, coverage) | **as-is** | keep |
| `chat-panel` / `agent-message` (AI-engineer chat with citations) | **as-is** | becomes the L2 surface |
| compliance/readiness/evidence/`trust/[slug]`/`audit/[token]` portals | **as-is** | keep |
| marketing landing, pricing, legal, blog | **structure as-is** | re-message |
| **`worker/runner.py`** (strix CLI + field map) | **rewrite** | re-point to tsengine |
| `credentials.py` env contract (`STRIX_*` → tsengine flags) | **adapt** | re-map |
| DB `findings` schema | **extend** | add raw/enriched split, attestation, partial, asset_type, anchors_fired/corpus |
| **L1 raw↔enriched toggle + L1.5 audit-log override** | **net-new** | tsengine §2.5 |
| **Tool-replay "Investigate" UI + `/replay` API proxy** | **net-new** | tsengine §9 |
| **Attestation verify UI** (ed25519 signed evidence) | **net-new** | tsengine §10 |
| **L2 agent telemetry** (OODA phase, budget/cost/tokens/compactions) | **net-new (small)** | tsengine §2.6 |

**Gaps webappsec has that tsengine specifically needs:** (1) no `findings_raw`
vs `findings_enriched` toggle — it only shows the enriched/triaged view; (2) no
structured `l15_audit_log` override surface for the security engineer; (3) no
`/replay` UI; (4) no attestation-verify; (5) branding is strix-derived. All are
additive, not rewrites.

---

## 3. Goal 1 — Multi-tenant architecture (isolation, safety, scale)

**Adopt webappsec's spine wholesale** (it's the part that's hard and already
done), then harden the documented gaps for tsengine's safety bar.

### 3.1 Inherited as-is
- **Tenant isolation:** every row keyed `org_id`; RLS gates on
  `org_id = current_org_id()` from the JWT (injected by an access-token hook);
  the worker uses the service role but only through **security-definer RPCs**
  that re-derive `org_id` from `scan_id` — a scan can only write into its own org.
- **Secrets:** pgsodium Vault; cloud creds decrypted *at scan time* into a
  `CredentialBundle` (env vars / mode-0600 temp files, wiped on exit). This
  matches tsengine's standing rule — *credentials forwarded as short-lived env,
  never on disk, die with the `--rm` container.*
- **Scan = one ephemeral sandbox container** (fresh bearer token, ports, workdir;
  force-removed on teardown). tsengine's own `internal/sandbox` model maps 1:1.

### 3.2 Hardening tsengine should add (close webappsec's known gaps)
| Risk (webappsec roadmap) | tsengine fix |
|---|---|
| Shared worker host → sandbox escape in scan A reaches scan B | **K8s-Job-per-scan or Firecracker microVM per scan** — strict run↔run isolation |
| Unrestricted egress (SSRF/exfil) | **egress allow-list firewall**; tsengine already rewrites loopback→`host.docker.internal` and enforces scope (C2) — extend to L4 |
| No per-org concurrency / cost quotas | tsengine's **Budget caps** (L2 cost/token/iteration/wall-clock) + **scan `--timeout`** map directly → enforce per-org quotas + plan tiers |
| No data residency | region-pin Supabase project + worker per region (billing already region-aware) |

### 3.3 Reproducibility & evidence (tsengine's compliance edge)
tsengine signs `vulnerabilities.json` (ed25519) and pins `corpus.*` per scan.
Store the `attestation` block; expose a **"Verify evidence"** action (re-hash +
signature check) in both the security view and the `audit/[token]` portal — a
concrete compliance differentiator strix/webappsec didn't have.

---

## 4. Goal 2 — The two-layer UI/UX (the core)

tsengine's L1/L2 split *is* an audience split, and webappsec already articulates
the same two personas in `docs/tier-layer-mapping.md` (security-engineer
"deterministic stack" vs developer "AI co-pilot"). Make it a **first-class view
switch**, not a filter.

### 4.1 L1 view — "Security Engineer / Compliance Auditor"
**Audience:** the security team + auditors (peers, not subordinate). They read
the *pre-L1.5 raw* truth.

- **Raw ↔ Enriched toggle** (the key missing piece). `findings_raw` = per-tool
  verbatim output (the recall contract); `findings_enriched` = + L1.5
  annotations. Default to raw for this persona; one click to enriched.
- **Per-finding signal row** (reuse the finding-card chips): tool, rule_id,
  severity, CWE, MITRE, **threat-intel (KEV badge + EPSS + CVSS)**, **compliance
  control mapping** (SOC2/PCI/HIPAA/CIS/NIST/ISO), **`verification_status`
  (pattern_match→corroborated→verified) + `confidence`** (the signal we just
  added), `corroborated_by`.
- **L1.5 audit-log panel** (`l15_audit_log`): every demote/dismiss/merge, *with
  an override control* — tsengine §2.5 requires these be recoverable + auditable.
  webappsec shows AI-dismiss banners but not a structured, reversible log.
- **Reproducibility strip:** `anchors_fired`, pinned `corpus.*` versions,
  `sandbox_image_digest`, **Verify-attestation** button.
- **Partial-scan banner:** surface `Scan.Partial` + `StopReason` (the
  no-zero-on-timeout fix) — "timed out, N findings, partial coverage", never a
  silent clean bill of health.
- **"Investigate" (tool-replay):** per-finding "dig deeper" → `/replay` a
  registry tool (e.g. sqlmap `--tamper`, a custom nuclei template) without
  restarting the scan (§9). **Net-new UI.**

### 4.2 L2 view — "AI Security & Compliance Engineer"
**Audience:** developers / PMs / non-security. They can't triage raw scanner
output; they get the translation.

- **Prioritized inbox** (reuse the urgency-tiered `findings` view): L2-authored
  reports ranked, plain-English titles.
- **AI-engineer chat** (reuse `chat-panel`): ask "what's the worst thing here?",
  "how do I fix #3?" — backed by the L2 catalog (get_finding, query_threat_intel,
  dispatch_l2_probe, send_request).
- **Per-report developer card** rendering the `L2Report` reasoning-as-parameters
  (maps onto existing blocks): **kill-chain narrative**, **plain-English**
  explanation, **remediation patch** (unified diff + apply-PR), `evidence_finding_ids`
  (links back to the L1 findings it rests on — never invented), verification ladder.
- **Agent transparency panel** (reuse scan-live-view's timeline; small net-new):
  OODA **phase**, **budget** (cost/tokens/iterations/wall-clock vs caps),
  **compactions**, **tool calls**, **hypotheses** (`record_hypothesis`). This is
  the trust surface — show the model's reasoning *commits*, per §2.7.
- **Compliance evidence packs** (reuse the compliance/readiness/trust portals):
  the auditor-facing artifact.

### 4.3 Shared: scan creation across the 7 asset types
web / api / repository / container_image / ip_address / domain / cloud_account.
webappsec already has asset routes + `cloud_account` in its type union — map
tsengine's asset types onto the existing "new scan" flows (CSV/GitHub/Terraform
import already present).

---

## 5. Goal 3 — Landing / marketing

The landing scaffold exists (hero + chat mockup + personas + compliance-as-product
+ comparison table + pricing + legal). **Keep the structure, re-message** around
tsengine's actual differentiators:

1. **Two products, one engine:** "best-in-class OSS detection your security team
   trusts (L1) **+** an AI security engineer your developers can talk to (L2)."
2. **Benchmarked recall** (the honesty hook strix never had): per-asset numbers
   vs neutral leaderboards — WAVSEP (Acunetix/Burp/ZAP), OWASP Benchmark.
3. **Signed, reproducible compliance evidence** (ed25519 attestation, pinned
   corpus) — the GRC/auditor wedge.
4. **7 assets incl. cloud compliance** (SOC2/PCI/HIPAA/CIS/NIST/ISO).

Personas page maps cleanly to the two views above. (Note: the sibling
`marketing/` dir is unrelated — it's a JEE/physics demo, not webappsec's landing.)

---

## 6. Phased rollout

| Phase | Scope | Outcome |
|---|---|---|
| **P1 — Fork + re-point** | Fork webappsec; rewrite `runner.py` to invoke `tsengine scan` + ingest `vulnerabilities.json`; extend `findings` schema (raw/enriched, asset_type, anchors_fired, corpus, attestation, partial). Keep all RLS/Vault/queue/realtime/auth/billing. | An org can run a tsengine scan and see enriched findings, multi-tenant + isolated. |
| **P2 — L1 security view** | Raw↔enriched toggle, L1.5 audit-log override, reproducibility strip + attestation verify, partial-scan banner. | The security-team product. |
| **P3 — L2 dev view** | Prioritized inbox + AI-engineer chat over the L2 catalog + L2Report developer cards + agent telemetry panel. | The non-security product. |
| **P4 — Tool-replay + compliance** | `/replay` "Investigate" UI + API proxy; wire compliance/readiness/trust/audit portals to tsengine's control mapping + evidence packs. | "Dig deeper" + GRC. |
| **P5 — Isolation & scale hardening** | K8s-Job/microVM-per-scan, egress firewall, per-org concurrency+cost quotas (tsengine Budget→plan tiers), region-pinning. | Production multi-tenant safety. |

P1 is the load-bearing slice; everything after is additive on the inherited spine.

---

## 7. Open decisions

1. **Fork vs greenfield** → **fork** (the multi-tenant spine + finding UI are
   ~6 months of work already done and battle-shaped).
2. **Isolation model** → K8s-Job-per-scan (simplest hardening) vs Firecracker
   microVM (strongest). Decide on P5; both fit the worker's "spawn per scan" model.
3. **How much raw to expose** → default the security view to `findings_raw`;
   confirm with a design partner on the security team.
4. **Branding** → new name vs inherit; copy is strix-derived and must be rewritten
   regardless.
5. **Worker concurrency** → strix forced `WORKER_CONCURRENCY=1` (process-global
   state). tsengine's CLI is a clean subprocess with no shared global → we can
   raise per-worker concurrency, improving scan throughput per machine.

---

## 8. Bottom line

webappsec answers Goal 1 (multi-tenant isolation/safety/scale) **today**, with
documented hardening items that tsengine's own primitives (Budget caps, scope,
loopback rewrite, signed corpus) are well-positioned to close. Goal 2 (the L1/L2
audience split) is the design centerpiece and is mostly *assembly* of existing
components plus three net-new surfaces (raw/enriched toggle, tool-replay, agent
telemetry). Goal 3 (landing) is a re-messaging of an existing scaffold. **Reuse,
re-point the one worker file, and build the dual-view — don't rebuild the SaaS.**
