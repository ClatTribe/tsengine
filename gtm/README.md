# GTM — lead generation for the AI Security Engineer + AI Pentester

This folder is the **outbound and nurture system** for the Series A motion. It is
copy and process, not code. The one piece of engineering it depends on already
exists: the public, unauthenticated assessment API.

## The thesis in one paragraph

At Series A there is no security team. Nobody wakes up wanting security, so every
deal starts at a **trigger event** — almost always *an enterprise customer's
security review is blocking a deal*. At that moment the buyer needs three things
that are normally three separate purchases: a **pentest report**, **compliance
evidence**, and **proof the holes got closed**. We sell one artifact that is all
three, signed by a named human. Outbound therefore leads with *evidence about
their own domain*, never with a product pitch.

## Why our cold email can be different

Most security cold email is a claim ("we find vulnerabilities"). Ours can be a
**fact about the recipient's own domain**, produced before they ever reply:

```
GET /v1/assess?domain=<their-domain>
```

Public, unauthenticated, SSRF-screened, rate-limited per IP, and it never touches
their servers — it reads public DNS plus one HTTPS GET of their homepage. It
returns a grade and the specific failing checks (DMARC/SPF/DKIM, HTTPS enforcement,
HSTS, CSP, clickjacking, security.txt) **each with a copy-paste fix**.

That gives every cold email a true, verifiable, useful first line and a reason to
reply. Cost per lead: approximately zero.

> Rule: **never send a finding you have not actually run.** The whole differentiator
> is that we prove things. Fabricating a finding in an email destroys the one thing
> we sell. If the scan comes back clean, use the clean-result variant in
> `sequences/02-evidence-led-cold.md`.

## What's in here

| File | What it's for |
|---|---|
| `icp.md` | Who to target, the trigger events, hard disqualifiers, where to source lists |
| `signals.md` | Mapping from an assess finding → the hook, the fix, and the follow-on question |
| `sequences/01-questionnaire-blocked.md` | The primary motion: a deal is blocked right now |
| `sequences/02-evidence-led-cold.md` | Cold outbound led by a real finding on their domain |
| `sequences/03-free-scan-nurture.md` | Someone ran the free scan — convert to connected account. **Blocked: `/scan` captures no email yet — see the note at the top of that file** |
| `metrics.md` | What to measure, target rates, and when to kill a sequence |

## How to run it

1. Build a list per `icp.md`.
2. Run the assess API against each domain; keep the failing checks per domain.
3. Pick the sequence by trigger (blocked deal → 01, no known trigger → 02).
4. Personalise **only** with facts from the scan. No "I loved your blog post."
5. Track per `metrics.md`. Kill any sequence under target after 200 sends.

## Non-negotiables

- **Every claim in an email must be reproducible.** We are a proof company.
- **One ask per email.** Usually: "want the full report?"
- **Under 120 words.** The buyer is a CTO with no security context and no time.
- **No fear-selling.** Trigger events already supply the urgency.
- Honour unsubscribes immediately; suppress the domain permanently.
