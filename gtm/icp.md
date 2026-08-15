# ICP — who we target

## The company

| Attribute | Target |
|---|---|
| Stage | Series A (roughly $8–25M raised), sometimes late seed with enterprise customers |
| Headcount | 20–80, of which 5–30 are engineers |
| Security staff | **Zero.** If they have a security hire, we are early — different motion |
| Product | B2B SaaS selling to companies larger than themselves |
| Infra | One cloud (usually AWS), GitHub, deploys via CI, some IaC |
| Data | Holds customer data their customers care about |

The single strongest qualifier is **"sells B2B to enterprises."** That is what
produces the security questionnaire, which is what produces the budget.

## The buyer

The owner of security is whoever least wants the job:

1. **CTO / co-founder** — most common. Owns it by default. Buys to make a blocker go away.
2. **VP Engineering / Head of Platform** — owns it once the CTO delegates.
3. **The "security-minded" senior engineer** — no budget, but is the internal champion and the person who runs the free scan.
4. **Head of Ops / Finance / Chief of Staff** — sometimes owns SOC 2 as a compliance project. Buys the evidence, not the testing.

Write to a competent engineer who has never done security work. No acronyms
without expansion. No FUD.

## Trigger events — ranked by how fast they close

1. **An enterprise deal is blocked by a security review or questionnaire.** *The* trigger. Urgency is supplied by their sales pipeline, not by us. Fastest close.
2. **A customer contract requires an annual pentest.** Named artifact, existing budget line, hard date.
3. **SOC 2 Type II underway or demanded.** Usually downstream of #1. Slower — often already has Vanta/Drata.
4. **Cyber-insurance renewal or a questionnaire from an insurer.**
5. **Just raised a round** (announcement is public). Budget exists; urgency does not. Nurture, don't push.
6. **A near-miss or public incident** in their space. Handle carefully — never exploit an active incident.

## Hard disqualifiers

- **Consumer apps with no enterprise customers.** No questionnaire → no trigger → no budget.
- **Pre-product / pre-revenue.** They should be building, not buying security.
- **Already has a security team of 3+.** They will evaluate us as a tool, on features, against funded competitors. Losing ground.
- **Regulated industries where we have a known gap** until it closes: healthcare (we have no evidence-sanitisation guarantee yet, so PHI could reach an evidence bundle) and card-data fintech. Do not sell in until that ships.
- Anyone who asks us to test an asset they don't own. Ownership verification is a product gate; it's also a sales gate.

## Where to source lists

| Source | Why it works |
|---|---|
| Funding announcements (Crunchbase/news, "Series A", B2B SaaS) | Stage + budget in one signal |
| YC / accelerator batch directories | Dense, uniform stage, publicly listed domains |
| Job boards — companies hiring "first security engineer" / "SOC 2" / "compliance" | They have declared the trigger publicly |
| G2 / Vanta / Drata customer mentions | Already spending on compliance; missing the testing half |
| Public trust pages / security.txt | They care enough to publish, which means they're in the review cycle |
| Conference and marketplace listings requiring vendor review | Guaranteed to face a questionnaire |

**Best single list:** companies that announced a Series A in the last 90 days AND
have a job posting mentioning SOC 2, compliance, or security. Two independent
trigger signals.

## Segmentation for the sequences

| Segment | Sequence |
|---|---|
| Known blocked deal (they said so publicly, or a job post implies it) | `01-questionnaire-blocked.md` |
| No known trigger, but the scan found something real | `02-evidence-led-cold.md` |
| Ran the free scan themselves | `03-free-scan-nurture.md` |
| vCISO / MSP / compliance consultancy | Partner motion — different economics, one account = many logos |
