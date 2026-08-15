# Signals — turning a real finding into a first line

Every cold email opens with a **fact about the recipient's own domain**, produced
by the public assessment before we ever contact them:

```
GET /v1/assess?domain=<domain>
```

No auth, no signup, rate-limited per IP. It reads **public DNS plus one HTTPS GET
of their homepage** — it never scans their servers and never touches anything
non-public. That is also the honest sentence to use if anyone asks how we got it.

## The eight checks, and how each becomes a hook

Ordered by how well they work as an opener — top ones are concrete, unarguable,
and cheap for them to fix, which is what earns the reply.

| Check | What it means in plain English | Opening line | The fix we hand them |
|---|---|---|---|
| **DMARC enforcement** | `p=none` means anyone can send email as their domain | "Anyone can send email as `{{domain}}` right now — your DMARC is set to monitor-only." | The exact `_dmarc.{{domain}}` TXT record to publish |
| **SPF** | No/!broken sender policy — spoofing and deliverability | "`{{domain}}` doesn't publish a sender policy, so spoofed mail from your domain isn't rejected." | The `v=spf1` record |
| **DKIM** | No signing key — receivers can't verify mail is really theirs | "Mail from `{{domain}}` isn't cryptographically signed, so receivers can't tell a forgery from the real thing." | Where to publish the selector key |
| **HTTPS enforced** | Plain HTTP served or not redirected | "`{{domain}}` still answers on plain HTTP — that's a first-page question on most vendor reviews." | Redirect config |
| **HSTS** | Browsers can be downgraded to HTTP on first visit | "No HSTS on `{{domain}}`, so a first visit can be downgraded." | The `Strict-Transport-Security` header |
| **CSP header present** | No content-security-policy — XSS has no backstop | "No content-security-policy on `{{domain}}`." | A starter CSP |
| **Clickjacking & MIME protections** | Page can be framed / content-type sniffed | "`{{domain}}` can be loaded inside an attacker's iframe." | `X-Frame-Options` / `X-Content-Type-Options` |
| **security.txt** | No documented way to report a vulnerability | "There's no way for a researcher to report a bug to you — reviewers check for this." | A `/.well-known/security.txt` template |

**DMARC is the best opener *when it fires* — but do not plan on it firing.**

This file originally claimed DMARC was "the best opener by a wide margin" and "true
on a large share of Series A domains". The first real run disagreed. Across eight
live B2B SaaS domains (`tools/sample-leads.csv`), **zero** had a DMARC, SPF or DKIM
gap — every one had email auth done. The actual distribution:

| Hook that fired | Domains |
|---|---|
| Content-Security-Policy | 5 |
| HSTS | 1 |
| Clickjacking & MIME | 1 |
| clean (all 8 pass) | 1 |

Caveats, because eight is not a study: they are developer-tools companies, which are
more technically sophisticated than the average Series A, and they were picked to
exercise the tool rather than sourced per `outbound-sourcing.md`. A less technical
segment will likely show more email-auth gaps.

But the direction is clear enough to plan around: **the headers, not email auth, are
where the findings are** — and that is the inconvenient result, because the header
hooks are the weaker ones. "Anyone can email your customers as you" lands on a
founder; "no content-security-policy" does not. So the header lines above are written
to connect the finding to the **security review** — the thing the reader already cares
about — rather than to the vulnerability class, which they don't.

Re-measure this on your own list before trusting either version. The tool prints the
distribution; if your segment really is DMARC-heavy, reorder `HOOKS` in
`tools/prospect.py` and update the table above with what you actually saw.

## Rules for using a signal

1. **Only send what actually ran.** If the scan is clean, use the clean variant —
   do not invent a finding. Our entire product claim is that we prove things.
2. **Lead with the impact sentence, not the check name.** "Anyone can send email as
   you" beats "your DMARC policy is p=none."
3. **Give the fix away in the first email.** It costs nothing, it proves competence,
   and it inverts the relationship — we're not asking, we're giving.
4. **Never imply we scanned their infrastructure.** We didn't. Say "public DNS and
   your homepage" if asked. Over-claiming here would be the same failure mode we
   sell against.
5. **One finding per email.** A list reads as a scanner report and converts worse.

## The bridge from finding → the real conversation

The finding gets attention. It is **not** the product. Every sequence pivots from
the finding to the trigger with a single question:

> "These are the ones a reviewer sees from outside. The ones that actually block
> deals are the ones they ask about next — authentication, access between customer
> accounts, and whether anyone's tested it. Are you in a security review right now?"

That question does the qualifying. A "yes" moves them to
`sequences/01-questionnaire-blocked.md` regardless of which sequence they entered on.

## Clean-scan variant

Roughly a third of well-run Series A domains pass all eight. Do not force a
finding. Use the pass as the opener instead — it is genuinely differentiating,
flatters accurately, and still reaches the same pivot:

> "Ran the public checks on `{{domain}}` — all eight pass, which is rarer than it
> should be. That's the outside view. The questions that actually stall enterprise
> deals are the ones nobody can check from outside…"
