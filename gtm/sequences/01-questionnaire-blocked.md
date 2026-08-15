# Sequence 01 — The blocked deal

**Use when:** we know or strongly suspect a security review is blocking a deal right now.
**Signals that qualify them in:** they replied "yes" to the pivot question in sequence 02; a job post mentions SOC 2 / compliance / "first security hire"; they publicly announced an enterprise customer; they asked about a pentest in a community.

This is the **fastest-closing** motion we have. The urgency comes from their sales
pipeline, not from us — so the copy stays calm and operational. Never manufacture fear.

Three touches over 7 days. Short, because they are busy and already motivated.

---

## Email 1 — Day 0

**Subject:** `the security review, faster`

```
Hi {{first_name}},

If a customer's security review is holding up a deal, the blocker is usually
the same three things: a pentest report, evidence for the controls they ask
about, and proof you fixed what was found.

That's normally three purchases — a pentest firm, a compliance tool, and then
a re-test nobody books.

We produce all three as one artifact: findings with a working reproduction,
mapped to the controls the questionnaire asks about, re-tested after the fix,
signed by a named person.

Connect GitHub and your cloud read-only; first proven findings same day.

Worth 15 minutes this week?

— {{sender_first}}
```

*Notes: leads with their problem in their words. "Three purchases → one artifact"
is the whole pitch. Named human is stated early because it's the reviewer's test.*

---

## Email 2 — Day 3 · handle the real objection

**Subject:** `re: the security review, faster`

```
{{first_name}} — the question I'd ask in your position:

"Will their reviewer accept a report from an AI tool?"

Fair. Two things make it hold up:

1. Nothing goes in the report unless it was reproduced. A finding without a
   working exploit doesn't get written down — so there's no "possible" or
   "medium confidence" padding for a reviewer to poke at.
2. A named practitioner signs it. The reviewer is checking who stands behind
   it, and there's a person there.

Sample: {{sample_report_link}}

— {{sender_first}}
```

*Notes: this is **the** objection for this segment. Address it head-on, in email 2,
before they raise it. Both claims are literally true of the product — keep them that way.*

---

## Email 3 — Day 7 · the deadline close

**Subject:** `timing`

```
{{first_name}},

Last one. If the review has a date on it, that date is the only thing that
matters — tell me what it is and I'll tell you honestly whether we can make it.

If we can't, I'll say so and point you at a firm who can.

— {{sender_first}}
```

*Notes: the offer to disqualify ourselves is the highest-converting line in the
sequence for this segment, and it must be honoured. If we can't hit the date,
refer them out. The referral comes back later.*

---

## The discovery call — five questions

1. **What's the deal, and what's the date?** (Everything else is downstream.)
2. **What exactly did they send you?** (Questionnaire? SIG Lite? "Do you have a pentest?")
3. **Have you ever had a pentest?** (If yes — when, and did anyone re-test the fixes? Almost always no.)
4. **What are you running on?** (GitHub + one cloud = we can start today.)
5. **Who signs off internally?** (Usually the person on the call. Confirm it.)

## Qualify out fast

- No date and no named deal → they're browsing. Move to nurture.
- They need a physical/on-site test, or an assessor letter for a regulator → not us. Refer out.
- Healthcare with PHI or card-data fintech → **not yet.** Evidence sanitisation isn't shipped; PHI could reach an evidence bundle. Refer out and log it as demand.

## What we're actually competing with

| They're considering | Our line |
|---|---|
| A pentest firm ($15–40k, 2 weeks, PDF) | "You'll get the PDF. You won't get a re-test, and it's stale the next time you deploy." |
| Vanta/Drata alone | "That tells you which controls to have. It doesn't test anything — the reviewer is asking for the test." |
| Doing nothing / self-attesting | "That works until a reviewer asks for the report. Then the deal waits." |

Never disparage Vanta/Drata — most of these buyers already own one and we sit
beside it, not against it.
