# Sequence 02 — Evidence-led cold

**Use when:** no known trigger, but the assess scan found something real on their domain.
**Volume:** the main outbound engine. **Goal of the sequence:** one reply, and the answer to "are you in a security review right now?"

Five touches over 18 days. Stop the whole sequence on any reply.

---

## Email 1 — Day 0 · the finding

**Subject:** `anyone can send email as {{domain}}`
*(clean-scan variant: `{{domain}} passed all eight`)*

```
Hi {{first_name}},

Quick one — I ran our public check on {{domain}} (public DNS + your homepage,
nothing that touches your servers).

Your DMARC is set to p=none, which means anyone can send email as
@{{domain}} and receiving servers won't reject it. Invoice fraud against your
customers is the usual way that gets used.

The fix is one DNS record:

  _dmarc.{{domain}}  TXT  "v=DMARC1; p=quarantine; rua=mailto:security@{{domain}}"

Full check (8 things an enterprise reviewer looks at first) is here, no signup:
{{scan_link}}

— {{sender_first}}
```

*Notes: gives the fix away, no ask, no pitch. Under 110 words. The link is a
`?domain=` permalink that auto-runs so they see their own result immediately.*

---

## Email 2 — Day 3 · the pivot

**Subject:** `re: anyone can send email as {{domain}}`

```
{{first_name}} — one follow-up and I'll leave it.

Those eight checks are the outside view. They're not what stalls deals.

What stalls deals is the next page of the questionnaire: has anyone tested
whether one customer can reach another customer's data, and can you show the
report.

Are you in a security review right now, or is one coming?

— {{sender_first}}
```

*Notes: this is the qualifying email. A "yes" moves them to sequence 01 immediately.*

---

## Email 3 — Day 7 · the artifact

**Subject:** `what the report looks like`

```
{{first_name}},

In case it's useful later — this is the thing enterprise reviewers actually
accept: {{sample_report_link}}

Two parts most automated tools can't produce:

1. Each finding has a reproduction — the exact request, and the re-test after
   the fix showing the hole is closed.
2. It's signed by a named person, which is what the reviewer on the other side
   is checking for.

Happy to run one against a staging environment if it'd help.

— {{sender_first}}
```

---

## Email 4 — Day 12 · the peer proof

**Subject:** `how {{peer_company}} handled this`

```
{{first_name}},

{{peer_company}} was in the same spot — enterprise deal, security review,
no security hire. They connected GitHub and AWS, had proven findings the same
day, and the report went back with the questionnaire that week.

If the timing's wrong, tell me to stop and I will.

— {{sender_first}}
```

*Notes: **do not send until a real reference exists.** Skip to email 5 until then —
a fabricated customer story is the fastest way to lose the proof positioning.*

---

## Email 5 — Day 18 · the close-out

**Subject:** `closing the loop`

```
{{first_name}} — I'll stop here.

If a security questionnaire lands on your desk and you want the fastest path
through it, reply to this and I'll pick it up.

The free check stays available regardless: {{scan_link}}

— {{sender_first}}
```

---

## Rules

- **Stop on reply.** Even "not now" — move to a 90-day nurture, don't continue.
- **Never send email 1 without running the scan.** If the API failed, don't guess.
- **One finding only**, even if the scan returned four.
- Plain text. No tracking pixels, no images, no HTML signature block. We're a
  security company writing to engineers — tracking pixels get noticed and cost trust.
- Suppress the domain permanently on any unsubscribe or negative reply.

## What to measure

Reply rate is the only number that matters early — target **8%+** for the DMARC
opener. Below 4% after 200 sends, the list is wrong, not the copy.
