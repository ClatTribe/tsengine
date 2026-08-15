# Outbound — finding Series A companies worth emailing

`icp.md` says who to target. This says **where to get the list**, how to qualify it
before spending a send on it, and what is and isn't safe to automate.

## First, the honest bit about LinkedIn

Scraping LinkedIn is the obvious idea and it is the wrong first move:

- It breaches their User Agreement. The practical consequence isn't a lawsuit, it's
  that **the account doing the scraping gets restricted or banned** — often a founder's
  personal profile, which is also the profile the outbound replies land in.
- LinkedIn actively detects it. Scrapers work until they abruptly don't, usually in the
  middle of a campaign.
- **It's the wrong signal anyway.** LinkedIn tells you a company raised. It does not tell
  you the thing that actually predicts a purchase: that an enterprise customer's security
  review is blocking a deal *right now*. The sources below carry that signal directly.

**The compliant LinkedIn play** is Sales Navigator — a paid, sanctioned product with lead
lists and saved searches, plus alerts on funding and headcount growth. Use it to *research
and verify* a company you sourced elsewhere, and to find the right person's name. Don't use
it as the list itself.

## Sources, ranked by trigger density

Trigger density = what fraction of the list is likely to be in a security review *now*.
A small, high-density list beats a big one; the whole point of `signals.md` is that each
send costs a real scan.

| Source | Trigger density | Why |
|---|---|---|
| **Job posts mentioning SOC 2 / compliance / "first security hire"** | **Highest** | They have publicly declared the trigger. Search Ashby / Greenhouse / Lever / Wellfound / LinkedIn Jobs. A seed/Series A company posting a compliance role is nearly always answering a customer demand |
| **Trust-page and security.txt crawlers** | High | Publishing a trust page means they're in vendor-review cycles. Also tells you which frameworks they already claim |
| **Funding announcements, last 90 days** | Medium-high | Budget exists and enterprise motion usually starts right after. Crunchbase, news, the funding newsletters |
| **YC / accelerator batch directories** | Medium | Public, uniform stage, domains listed. Dense but not trigger-specific |
| **G2 / review-site mentions of Vanta, Drata, Sprinto** | Medium | They already bought compliance and are missing the testing half — the exact gap we fill |
| **Marketplace / partner-directory listings** (AWS, Salesforce, HubSpot) | Medium | Listing usually requires passing a vendor security review |

**The single best list:** companies that announced a Series A in the last 90 days **AND**
have a live job post mentioning SOC 2 or compliance. Two independent trigger signals; expect
this list to be small and to convert several times better than anything broader.

## What happened when this was actually run (2026-08-15)

The table above was written from reasoning. The first real attempt found two of its
assumptions wrong, so they are recorded here rather than quietly left in place.

**Searching job posts for the words "SOC 2" selects the wrong companies.** The query
surfaced four: a Series B healthtech, an FDA-cleared medical-imaging company already
holding ISO 27001, and two security/risk vendors. **Zero qualified** under `icp.md` —
two are hard-disqualified (healthcare/PHI), and the other two *sell* security, which
makes "we found gaps on your site" a hostile opener.

The reason is a selection effect worth internalising: a job post containing "SOC 2"
mostly identifies companies for whom compliance is already **routine** — regulated
industries and compliance vendors. Our buyer is the opposite: a company meeting the
requirement for the *first* time, who is more likely to be quietly panicking than
writing "SOC 2" into a job description.

So search the **symptom, not the vocabulary**:

- "first security hire" / "first security engineer" — the company admitting it has none
- a founder or exec publicly asking how to get through a security questionnaire
- a careers page whose *only* compliance-adjacent role is brand new
- an enterprise-logo announcement from a company that had none before

**Generic funding searches are unusable.** "B2B SaaS Series A funding 2026" returns
lead-broker SEO pages selling lists, not announcements. Use named sources — a specific
funding newsletter, an accelerator directory, a press feed — never an open web query.

**One result worth keeping:** of the two marginal domains scanned, `oscilar.com` — an
AI risk-and-compliance company — came back grade C with **no DMARC enforcement**. It is
the first time the DMARC hook fired in any run here (see `signals.md`, where eight
demo domains produced none), and it fired on a compliance vendor. Treat "they sell
security so they must have it" as an assumption to test, not a disqualifier.

Raw output: `tools/sourced-run-2026-08-15.csv`.

## The pipeline

```
source domains  →  qualify (cheap, automatic)  →  assess  →  personalise  →  send
```

**1. Source** — produce a list of `{company, domain, why_sourced}`. Keep `why_sourced`;
it becomes the first line if the assess scan comes back clean.

**2. Qualify before you scan.** Drop anything that fails `icp.md`'s hard disqualifiers —
consumer-only, pre-product, a security team already in place, healthcare/PHI and
card-data fintech (until evidence sanitisation ships). Cheaper to drop a row than to
scan and then not send.

**3. Assess.** Run `GET /v1/assess?domain=` per domain. Public DNS plus one homepage GET —
it does not touch their infrastructure, which is also the honest answer if anyone asks how
you got it. Store the failing checks.

**4. Personalise from the scan, never from a template variable.** `signals.md` maps each
failing check to its opening line and the fix you hand over. A clean scan gets the
clean-scan variant, not a manufactured problem.

**5. Send** per `sequences/02-evidence-led-cold.md`. Stop the sequence on any reply.

## Rate and volume

The bottleneck is the assess endpoint, which is rate-limited per IP by design — it's a
public endpoint and the limit exists to stop abuse, including ours. Budget scans in
batches rather than firing a thousand at once, and never route them through a pool of
IPs to evade the limit: you'd be circumventing your own product's abuse control to sell
a product whose pitch is that it plays fair.

Start at **20–40 sends/day** from a single domain. Deliverability, not list size, is the
constraint that kills cold outbound.

## Sending infrastructure

- Send from a **separate domain** (e.g. `try-tensorshield.com`), never the primary. A
  burned primary domain takes your product email down with it.
- SPF, DKIM and DMARC on the sending domain — `p=none` at minimum, moving to
  `p=quarantine`. **We sell a product that flags exactly this**; sending cold email from
  a domain that fails our own free check is the single most embarrassing thing this
  motion could do. Run `/scan` against the sending domain before the first send.
- Warm the domain over 2–3 weeks before volume.
- Plain text, no tracking pixels, no link shorteners — see `sequences/02`.

## Legal — read this before the first send

Not legal advice; get counsel before scaling. But the shape:

- **India (DPDP Act 2023)** — you're sending from India. Business contact data has more
  latitude than consumer personal data, but keep a lawful basis, honour erasure requests,
  and don't retain what you don't use.
- **EU/UK (GDPR + PECR)** — B2B cold email to a corporate address can rest on legitimate
  interest, but it must be relevant to the recipient's role, include an easy opt-out, and
  identify you clearly. Keep a record of why each contact was sourced (`why_sourced`).
- **US (CAN-SPAM)** — accurate headers and subject, a physical postal address in the
  footer, and an opt-out honoured within 10 days.

Practical rules that satisfy all three: **identify yourself honestly, include a real
address, make opting out one click, suppress permanently on request, and only contact a
business address about something genuinely relevant to that person's job.**

## Suppression

One list, checked before every send: anyone who asked to stop, anyone who replied
negatively, existing customers, current pipeline (they should hear from a human, not a
sequence), competitors, and every disqualified segment. Suppression is permanent — a
re-add after "no" is how a domain gets blocked.

## What to measure

Per source, not just in aggregate — the point is to find which source carries the trigger:

| Metric | Why |
|---|---|
| Reply rate **by source** | Kills a bad list before it burns the domain |
| Share of replies mentioning a real deal or date | The actual trigger rate. Falling → sourcing is drifting |
| Scans run vs sends made | Should be ~1:1. A gap means sends went out unpersonalised |
| Bounce rate | Over 3% → stop and fix the list; deliverability is at risk |

Full targets and kill thresholds in `metrics.md`.
