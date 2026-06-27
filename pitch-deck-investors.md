# TensorShield — The Fractional Autonomous Security Team for SMBs

> Investor pitch deck · Seed round · 2026

---

## Slide 1 — Title

# TensorShield
### The autonomous security team every SMB can afford — with a human always on the loop.

A self-hosted AI security & compliance team that runs continuously, fixes what it
finds (with your approval), and produces audit-ready evidence — without your data ever
leaving your environment.

**Seed · 2026**
[Founder names] · [contact]

---

## Slide 2 — The one-liner

**We give a 50-person company the security posture of a 5,000-person company — for
less than the cost of one part-time analyst, and without surrendering their data.**

- **Fractional** — you rent an always-on team instead of hiring a $180K engineer you can't find.
- **Autonomous** — it scans, triages, prioritizes, and drafts fixes by itself.
- **Human-in-the-loop** — it never makes an irreversible change without a person's approval.
- **Sovereign** — it runs in *your* environment. Your findings never leave your perimeter.

> Existing tools find problems and hand SMBs a list. **TensorShield is the team that acts on the list.**

---

## Slide 3 — The problem

**Every SMB is now a target. Almost none can staff for it. The work still has to happen.**

- **The mismatch.** 43% of cyberattacks hit small businesses, yet ~⅔ have **no dedicated
  security staff**. Ransomware against SMBs is projected to rise **40% by end of 2026** vs. 2024.
- **The talent wall.** There are **4.8M unfilled cybersecurity jobs globally** (ISC2 2025) —
  500K+ in the US alone. A full-time security hire is $150–220K; a CISO is **$250–600K**.
  An SMB cannot win that hire, period.
- **The tooling trap.** Snyk, Tenable, Wiz, and the crowd-pentest vendors **find problems
  and hand you a list**. Someone still has to read 800 findings, decide which 12 matter,
  and fix them. SMBs have no one to hand the list to.
- **The compliance squeeze.** SOC 2 / HIPAA / PCI are now *sales blockers* — no badge, no
  enterprise deal. Audit prep is a recurring manual fire drill.
- **The cost of the gap.** Organizations with a security-staff shortage face breach costs
  **$1.76M higher** on average than well-staffed peers.

> The gap isn't *detection*. It's the *team* that acts on detection — and an SMB can't hire one.

---

## Slide 4 — Why now

Four curves crossed in the last 18 months. Miss this window and someone else owns the budget.

1. **Agentic AI crossed the reliability line.** LLM agents can now do the triage,
   prioritization, and remediation-drafting that was the human bottleneck. The market is
   validating this fast — **Omdia is tracking 50+ "agentic SOC" startups**, and investors
   poured **$3.6B+** into agentic security in the last cycle. But that capital is chasing
   *enterprise* SOCs. **The SMB is wide open.**
2. **Best-in-class detection went free.** nuclei, semgrep, trivy, prowler — the detection
   corpus is open-source and community-maintained. The moat moved *up the stack*: from
   "who detects" to "who acts, and who you can trust with the data."
3. **Compliance became the budget unlock.** Vanta ($2.45B valuation, 8,000+ customers) and
   Drata (7,000+) proved SMBs will pay for security *paperwork on autopilot*. They created
   the buying motion — but they stop at evidence collection. **They don't do the security.**
4. **Sovereignty became a buying requirement.** Data-residency law, AI-data-governance rules,
   and post-breach board paranoia make "we'll host your security data in our cloud" a growing
   deal-killer. SaaS incumbents architecturally cannot answer it.

> Agentic AI is good enough, detection is free, the SMB compliance budget is awake, and
> "don't send us your data" is now a feature. **All four, at once, for the first time.**

---

## Slide 5 — Market

**SMBs are now the majority of global security spend — and the worst-served.**

- **$109B** — SMB cybersecurity spend in 2026, up from $76B in 2022 (**~10% CAGR**). SMBs are
  **~60% of global cyber spend** in 2026.
- SMB security as a share of IT budget **more than doubled** — 6% (2019) → 14% (2024) — and
  is still climbing. The money is moving *now*.

**Bottoms-up sizing (we price against the headcount we replace, not the tools we wrap):**

| Layer | Definition | Size | Derivation |
|---|---|---|---|
| **TAM** | Global SMB security + compliance spend | **$109B (2026)**, ~10% CAGR | Analysys Mason |
| **SAM** | Compliance-driven & regulated SMBs needing detect→fix→prove + self-host | **~$6B** | ~250K target SMBs globally × ~$25K blended ACV; cross-checks to the ~$8–10B consolidatable MSSP+vCISO+compliance-automation SMB budget |
| **SOM (3 yr)** | Direct + channel capture | **~$40M ARR** | ~500 direct × $25K + ~50 MSP partners × ~40 tenants × ~$15K ≈ 2,500 tenants — **<1% of SAM** |

*Penetration check: the Vanta/Drata/Secureframe/Sprinto category already serves ~25K+
compliance-driven SMBs at single-digit market penetration — the target universe is real
and barely tapped.*

**Adjacent budgets we consolidate into one line item:**
- Managed security services (MSSP/MDR): **$43B in 2026**, MDR the fastest-growing segment at **17.8% CAGR**.
- vCISO services: growing ~**15% CAGR**; replaces a $250–600K CISO line.
- Compliance automation: the Vanta/Drata category — proven SMB willingness-to-pay.

> We don't need a new budget. **We collapse the analyst + the point tools + the audit prep +
> the MDR retainer into one subscription** — and undercut all of them combined.

---

## Slide 6 — The solution

**An AI security team you deploy like a container.** It performs the full lifecycle a human
team would — continuously, not point-in-time:

| A human security team… | TensorShield… |
|---|---|
| Inventories what to defend | Connects GitHub, cloud, Google Workspace / M365 / Okta → builds the asset map |
| Scans everything, every week | Continuous monitoring across 8 asset types + identity posture |
| Triages 800 alerts to the 12 that matter | AI prioritizes, correlates into attack chains, kills false positives |
| Writes the fix / opens the ticket | Drafts the PR, the config change, the identity runbook — grounded in evidence |
| Gets sign-off before touching prod | **Stops at a human gate** for anything risky or irreversible |
| Produces the audit evidence | Signed, framework-mapped evidence across **14 compliance frameworks** |

> Competitors sell a *dashboard of problems*. We deliver a *security function* — and remove
> security from the SMB's to-do list entirely.

---

## Slide 7 — Two things make "autonomous" actually sellable

*(The only technical slide — these are the trust primitives the buyer cares about.)*

**1. Human-in-the-loop, by design — safe by construction.**
- Tiered autonomy: reversible actions (open a ticket) auto-apply; anything that mutates a
  real system **queues for human approval** first.
- Irreversible actions (breach notices, destructive changes) **require a named human
  signature** — the agent *cannot* execute them on auto. Enforced in code, not policy.
- One global **kill-switch** halts all autonomous action instantly. Every decision is signed
  into a tamper-evident ledger. *"It works while you sleep, but can't do anything you'd regret —
  and you can prove every move it made."*

**2. Sovereign — the wedge incumbents can't copy.**
- Runs in your environment (`docker compose up`, on-prem, your VPC, in-country cloud).
  **Findings, code, cloud config, identity data never leave your perimeter.**
- Detection engine is deterministic and LLM-free; the AI reasons against *your* data inside
  *your* boundary. We can't leak what we never hold.
- Every finding ships with a **signed, independently-verifiable attestation**. Trust without
  trusting us. *Opens the regulated/government/EU doors SaaS security structurally cannot.*

---

## Slide 8 — Competitive landscape

**Everyone owns one quadrant. Nobody owns the SMB full-lifecycle + sovereign square.**

|  | Finds vulns | **Acts / remediates** | Continuous | Compliance evidence | **Self-hosted / sovereign** | SMB-priced |
|---|:--:|:--:|:--:|:--:|:--:|:--:|
| **Scanners** (Snyk, Tenable, Wiz) | ✅ | ❌ hands you a list | ◑ | add-on | ❌ SaaS | ❌ enterprise |
| **Compliance automation** (Vanta, Drata, Secureframe) | ❌ | ❌ paperwork only | ✅ | ✅ | ❌ SaaS | ✅ |
| **MSSP / MDR** | ✅ | ◑ human, slow, $$$ | ✅ | manual | ❌ their cloud | ❌ |
| **Agentic SOC** (Dropzone, Prophet, Exaforce) | ◑ triages *alerts* | ◑ enterprise SOC | ✅ | ❌ | ❌ SaaS | ❌ enterprise |
| **Offensive AI** (XBOW) | ✅ pentest | ❌ | ◑ | ❌ | ❌ | ❌ enterprise |
| **vCISO** | ◑ | ◑ human advice | ❌ point-in-time | manual | n/a | ❌ |
| **TensorShield** | ✅ | ✅ **autonomous + gated** | ✅ | ✅ **14 frameworks** | ✅ **self-hosted** | ✅ |

**The reads:**
- **Vanta/Drata** proved SMBs pay — but they collect evidence, they don't *do* security. We
  start where they stop, and we generate the evidence as a byproduct of the actual work.
- **Dropzone ($57M raised) / XBOW ($120M, $1B+ val)** prove the agentic thesis — but they're
  built for *enterprises that already have a SOC and a security team*. We're built for the
  SMB that has neither.
- **MSSP/MDR** is humans-in-a-room: expensive, monitoring not remediation, your data in their
  cloud. We're the software that lets that whole model scale without linear headcount.

> The competition validates each axis separately. **TensorShield is the only one combining all six.**

---

## Slide 9 — Distribution is the moat (Part 1: the channel)

**The single biggest unlock: MSPs and vCISOs are desperately hunting for exactly this engine.**

- **MSPs are racing into security.** ~**74% of MSPs** not yet offering vCISO planned to add
  it; the rest are targeting 2026. They have the SMB relationships and the trust — what they
  **lack is a scalable engine** to deliver security without hiring analysts they can't find.
- **TensorShield is that engine.** White-labelable, multi-tenant, self-hosted, governed.
  An MSP runs *hundreds* of their SMB clients on one deployment. **One channel partner =
  hundreds of tenants**, near-zero CAC per logo.
- **We don't compete with the channel — we power it.** The MSP keeps the customer
  relationship and the margin; we're the autonomous team behind their badge. The human-on-the-
  loop *is their vCISO*, now leveraged 10×.
- **The vCISO/MSSP markets are already large and growing** (MSSP $43B, fastest segment +17.8%
  CAGR; vCISO ~15% CAGR) — we ride that growth as the underlying platform, not a competitor to it.

> This is the wedge that turns a hard, one-at-a-time SMB sale into a **fan-out distribution
> machine**. Land the MSP, inherit their book.

---

## Slide 10 — Distribution (Part 2: direct PLG + compliance-led)

**Three motions, sequenced — channel for scale, direct for proof and brand.**

1. **PLG top-of-funnel (free, viral).** A public, read-only "how exposed is yourdomain.com?"
   assessment — instant value, no signup, no data handed over. Founder/CTO-led, bottom-up,
   near-zero CAC. Land → connect one system → see real findings in minutes.
2. **Compliance-led conversion (the wedge that closes).** "Get SOC 2 / HIPAA evidence on
   autopilot — and actually fix what blocks the badge." We sell to the person who *owns* the
   deal-blocking audit (founder / head of eng), not a CISO who doesn't exist at an SMB. This
   is the proven Vanta/Drata buying motion — but we deliver the security work, not just the checklist.
3. **Sovereign / regulated land-and-expand (the margin tier).** Government suppliers, defense-
   adjacent, health & fintech — where "self-hosted + signed evidence" wins deals SaaS can't bid on.

**Why time-to-value wins the sale:** minutes, not a quarter. We don't add to the SMB's to-do
list — we *remove* a function from it.

> **Sequence:** free assessment → land one connector → compliance unlock → expand to full
> monitoring → graduate to the channel and the sovereign tier. NRR engine built in.

---

## Slide 11 — Business model

**Priced as a fractional hire, billed as software, expanded through the channel.**

- **Core subscription** — per-tenant, tiered by connected systems / asset count. Anchored to
  *"less than a part-time analyst"* (~$15–30K/yr vs. a ~$80K part-time hire or a $250–600K CISO).
  Replaces the analyst + the point tools + the MDR retainer.
- **Compliance pack** — premium add-on; the signed evidence + auditor report has the highest
  willingness-to-pay because it directly unblocks the customer's *own* revenue.
- **Sovereign / on-prem tier** — higher ACV for regulated & government buyers (KMS, air-gap,
  HA). The margin tier.
- **Channel / white-label** — per-seat or rev-share with MSPs/vCISOs; volume economics, they
  carry the CAC.

> Land cheap (free score), expand fast (compliance + monitoring), monetize depth (sovereign),
> and multiply through partners. **Multiple expansion vectors on one platform.**

---

## Slide 12 — Why we win (and why it compounds)

- **Architectural sovereignty.** Multi-tenant SaaS incumbents can't retrofit "your data never
  leaves." We're built that way from the boundary up — a moat that *can't be feature-flagged*.
- **Channel lock-in.** An MSP that standardizes delivery on us brings their whole book; ripping
  us out means re-training their entire service line.
- **Trust compounds into autonomy.** The signed-ledger + HITL track record means the longer we
  run safely, the more autonomy the customer grants, the deeper we're embedded.
- **System-of-record switching cost.** We become the source of truth for posture, compliance
  evidence, and the decision ledger. Leaving means losing the audit trail.
- **OSS leverage, not dependence.** Community detection improvements flow to us free; our value
  is the governed, sovereign *team* and the compliance graph on top.

---

## Slide 13 — Traction & roadmap

**Already built (the hard, trust-critical core is done):** full autonomous loop wired
end-to-end (connect → scan → detect change → propose fix → human-gate → apply → signed ledger);
8 asset types + 3 identity providers live; 14 compliance frameworks with signed evidence; global
kill-switch; containerized single-box deploy.

**What the round funds (12 months):**
- Design partners → first paying SMBs (compliance-led).
- **Launch the MSP/vCISO channel program** — the distribution flywheel.
- Deepen the agentic SOC (open-ended triage, live containment); broaden connectors.
- Regulated-tier hardening (HA, cloud-KMS) + our own SOC 2 / FedRAMP path.

**Milestones to Series A:** first ~$1M ARR · first cohort of paying tenants · first signed
**MSP/vCISO channel partners** (the fan-out proof) · first 1–2 sovereign/regulated logos ·
a self-serve free-assessment funnel feeding the pipeline.

> *(Attach real numbers once design partners, pilots, and LOIs are in hand.)*

---

## Slide 14 — Team

- **[Founder 1]** — [security / domain depth; why you understand the SMB security gap].
- **[Founder 2]** — [AI/agentic systems + product; why you can build trustworthy autonomy].
- **[Advisors]** — [compliance/audit, MSP channel, security research].

**Why us:** we've already built the hard part — the deterministic detection brain, the
human-gated autonomy, and the signed evidence chain. We know the exact line between
*"autonomous enough to replace a team"* and *"safe enough that an SMB owner sleeps at night."*

---

## Slide 15 — Where the next 18 months go

**The core engine is built. The capital goes to distribution and breadth, not to proving the tech.**

- **Distribution first** — stand up the **MSP/vCISO channel program** (the fan-out flywheel)
  alongside the compliance-led direct motion. This is where the dollars concentrate.
- **Breadth** — deepen the agentic SOC (open-ended triage, live containment), broaden connectors.
- **Regulated-tier hardening** — HA, cloud-KMS, and our own SOC 2 / FedRAMP path to unlock the
  sovereign margin tier.

**What we'll prove:** repeatable compliance-led SMB acquisition, the first channel partners
fanning out to hundreds of tenants, the first sovereign logos, and the autonomy/trust flywheel.

> **The security team every SMB needs and none can hire — autonomous enough to matter, governed
> enough to trust, sovereign enough to own, and distributed through the partners who already
> own the relationship.**

[founder] · [email] · [phone]

---

### Appendix A — objection handling

- **"Won't Vanta/Drata just add this?"** → They're multi-tenant SaaS built around evidence
  collection. They can't do in-environment remediation without rebuilding their architecture,
  and "your data never leaves" is the one promise they can't make. We start where they stop.
- **"Won't Dropzone/XBOW move down-market?"** → They're built for enterprises that already have
  a SOC and a security team to operate them. The SMB has neither — different product, different
  buyer, different price point, and they're SaaS.
- **"Isn't autonomous security dangerous?"** → That's exactly why the gate, signed ledger, and
  kill-switch are *core architecture*. We sell *governed* autonomy — irreversible actions are
  code-prevented from auto-running.
- **"Is the AI inventing vulnerabilities?"** → No. Detection is deterministic OSS; every recorded
  issue must cite real tool evidence. The AI reasons over proven findings, never hallucinates them.
- **"Why will MSPs adopt vs. build?"** → 74% are rushing to add vCISO/security and can't hire the
  analysts to deliver it. We're the engine that lets them scale without headcount — we make them
  money, we don't compete with them.

### Appendix B — sources

- SMB cyber spend $76B→$109B, ~10% CAGR, ~60% of global spend: [Analysys Mason](https://www.analysysmason.com/research/content/articles/smb-cyber-spending-rsmb1-ren04/)
- SMB attack share, ransomware +40%, IT-budget 6%→14%: [StationX](https://app.stationx.net/articles/small-business-cybersecurity-statistics), [Heimdal](https://heimdalsecurity.com/blog/small-business-cybersecurity-statistics/)
- 4.8M unfilled cyber jobs; $1.76M higher breach cost when understaffed: [ISC2 2025 Workforce Study](https://www.isc2.org/Insights/2025/12/2025-ISC2-Cybersecurity-Workforce-Study), [DeepStrike](https://deepstrike.io/blog/cybersecurity-skills-gap)
- Vanta $2.45B / 8,000+ customers; Drata 7,000+; Sprinto +233%: [YipitData](https://www.yipitdata.com/resources/blog/vanta-vs-drata-compliance-software-2026)
- MSSP $43B (2026), MDR +17.8% CAGR: [MarketsandMarkets](https://www.marketsandmarkets.com/Market-Reports/managed-security-services-market-5918403.html), [Mordor Intelligence](https://www.mordorintelligence.com/industry-reports/security-managed-services-market)
- Dropzone $57.4M raised / $37M Series B; XBOW $120M @ $1B+; Omdia 50+ agentic SOC startups; $3.6B funding: [Dropzone AI](https://www.dropzone.ai/press-release/dropzone-ai-37m-series-b-funding-ai-soc-agents), [Software Strategies Blog](https://softwarestrategiesblog.com/2026/03/28/agentic-ai-security-startups-funding-mna-rsac-2026/)
- vCISO ~15% CAGR, full-time CISO $250–600K, 74% MSPs adding vCISO: [MSSP Alert / Cynomi](https://www.msspalert.com/news/cynomi-demand-for-vciso-services-is-up-and-mssps-msps-are-responding), [Business Research Insights](https://www.businessresearchinsights.com/market-reports/virtual-ciso-market-117910)
