# Sequence 03 — Free-scan nurture

> ⚠️ **BLOCKED — prerequisite not built.** `/scan` does not capture an email address
> today. It runs the check, shows the grade and the fixes, and the visitor leaves
> without us learning who they were. **This sequence has no input until that changes**,
> so treat everything below as a design that is ready to run, not a sequence you can
> switch on. Sequences 01 and 02 are unaffected.
>
> Closing it is a product decision, because it turns on **what the visitor gets for
> the email**, and the honest options differ in what they'd require:
>
> | Offer | Honest? | Needs building |
> |---|---|---|
> | "Leave your email and we'll help you fix these" | Yes — it's a sales lead | Nothing. Posts to the existing `/v1/lead` |
> | "Email me these fixes" | Only if we actually send them | A fixes email (the assess result already has per-check fixes) |
> | "Watch this domain, tell me if it changes" | Only if we actually monitor it | Scheduled re-scan + change alert for a non-account visitor |
>
> Whatever is chosen, it must come **after** the result is displayed. The page's
> "free, no signup" promise is a real asset — gating the grade behind an email would
> trade the top of the funnel for the middle of it.
>
> One thing that *does* already work: the embeddable grade badge (`/api/assess/badge`),
> referenced in email 4 below.

**Use when:** someone ran the public scan at `/scan` and left an email address.
**They are the warmest lead we get** — they self-identified a security concern and
already saw their own result. The job is not to convince them there's a problem;
it's to move them from *a grade about their outside* to *a connected account that
sees inside*.

The gap to close: the public scan checks **8 external things**. The product finds
what's in their code, cloud and running app. Those are different orders of
magnitude, and the email has to make that concrete without being alarmist.

Four touches over 14 days. Stop on signup.

---

## Email 1 — sent within 5 minutes of the scan

**Subject:** `your {{domain}} results, and the fixes`

```
Hi{{#first_name}} {{first_name}}{{/first_name}},

Here's your result again so it's in your inbox: {{scan_link}}

{{#failed_checks}}
You didn't pass {{failed_count}} of 8. The fixes, in order of what a reviewer
notices first:

{{failed_checks_with_fixes}}
{{/failed_checks}}
{{^failed_checks}}
All 8 passed — genuinely uncommon. Your external posture is in good shape.
{{/failed_checks}}

These are all things anyone can see from outside your company, which is exactly
why reviewers check them first.

— {{sender_first}}
```

*Notes: deliver value first, no ask. Renders correctly for both pass and fail.*

---

## Email 2 — Day 2 · the inside/outside gap

**Subject:** `what the free check can't see`

```
{{first_name}},

The check I ran only sees your DNS and your homepage. It can't see the two
things that actually decide whether you pass an enterprise review:

  - whether one customer's account can reach another customer's data
  - whether anything in your cloud lets an attacker get from a leaked key to
    your database

Those need to look inside. Connect GitHub and read-only cloud access and you'll
have real findings the same day — free tier, no card:
{{signup_link}}

— {{sender_first}}
```

*Notes: the single most important email in the sequence. It names the two things
that are both (a) genuinely what we do well and (b) invisible to any free tool.*

---

## Email 3 — Day 6 · the trigger question

**Subject:** `quick question`

```
{{first_name}} — what made you run the check?

Asking because the answer usually falls into one of three buckets, and each has
a different fastest path:

  - a customer sent a security questionnaire
  - SOC 2 is starting
  - no specific reason, just wanted to know

If it's the first one, there's a much shorter route than the one most people take.

— {{sender_first}}
```

*Notes: a genuine question with a low reply cost. Bucket one routes straight to
sequence 01. This email consistently earns replies because it asks about them.*

---

## Email 4 — Day 14 · the standing offer

**Subject:** `leaving this here`

```
{{first_name}},

Not going to keep emailing. Two things that stay available:

  - The free tier watches your code and cloud continuously and tells you when
    something changes: {{signup_link}}
  - If a security review shows up, reply here and I'll help you get through it.

You can also drop the grade badge on your site — some teams use it on their
trust page: {{badge_link}}

— {{sender_first}}
```

*Notes: the badge is a viral loop — every render is a branded backlink to `/scan`.
Worth pushing even to people who never buy.*

---

## Rules

- **Email 1 within 5 minutes**, while they still have the tab open.
- **Never re-send the grade as a threat.** They already saw it; repeating it as
  pressure reads as a scare tactic and this audience is allergic to it.
- If they signed up between touches, **exit the sequence immediately** and switch
  to product onboarding.
- Segment on result: an all-pass scanner gets emails 2–4 only (email 1's fix list
  is empty and the pass line alone is enough).

## What to measure

- Scan → email capture rate (the `/scan` page's job)
- Email 2 → signup click (the core conversion of this sequence)
- Email 3 reply rate — target **15%+**, it's a real question to a warm contact
- Scan → connected-account rate — **the number that matters**; everything else is a proxy
