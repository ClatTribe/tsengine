---
name: operate-email-auth
description: Triage missing or unenforced email authentication (DMARC/SPF/DKIM) — can a stranger send mail as this domain?
version: 1.0.0
matches:
  rule_ids:
    - operate::dmarc-not-enforced
    - operate::spf-dkim-missing
---

## Triage

The question is not "is a DNS record missing" — it is **can someone send mail that your customers'
mail servers will accept as you?**

Grade by what the domain is used for:

- **A domain that sends customer or transactional mail** without enforcing DMARC is a live phishing
  channel aimed at your own users and customers. This is the high-severity case.
- **A parked or non-sending domain** is lower severity but not benign: an unused domain with no
  enforcing policy is a *preferred* spoofing vehicle precisely because nobody watches its mail.
- **`p=none`** is the trap. DMARC is published, monitoring works, dashboards look green — and
  nothing is rejected. Treat `p=none` as unenforced, because operationally it is.

Dismiss as benign only when an enforcing policy (`p=quarantine` or `p=reject`) is live at the
organisational domain *and* SPF and DKIM both align.

## Investigation

Establish exploitability and whether it is already being exploited.

- **Read the actual published records**, not the intent. Confirm the `_dmarc` TXT policy, the SPF
  record's terminal mechanism, and that a DKIM selector genuinely resolves. An SPF ending in `~all`
  or `?all` does not stop delivery.
- **Check alignment, not just presence.** SPF and DKIM can both pass while DMARC still fails, if
  neither aligns with the From: domain. Presence of three records is not the same as a working chain.
- **Look for spoofing already in flight.** Cross-check certificate-transparency and typosquat
  findings for the same brand: an unenforced domain *plus* a freshly registered lookalike with a new
  certificate is phishing infrastructure being staged, and warrants `malicious` rather than a posture
  verdict.
- **Check subdomains.** An enforcing organisational policy with no `sp=` leaves subdomains open, and
  subdomain spoofing is the common bypass once the apex is locked down.

Verdicts:

- `malicious` — spoofing infrastructure observed (lookalike domain, spoofed mail reported) against an
  unenforced domain.
- `suspicious` — a customer-facing sending domain with `p=none` or no policy at all.
- `inconclusive` — records could not be resolved (DNS failure). Do not read a lookup failure as
  absence; say which record could not be checked.
- `benign` — enforcing policy live and aligned, or a confirmed non-sending domain already at
  `p=reject`.

## Tuning

- Do not propose suppressing this rule for "internal" domains. Internal domains are routinely used
  for internal phishing, which is the harder attack to spot.
- A monitoring window at `p=quarantine` is a legitimate temporary state — propose a time-boxed
  suppression with an expiry, not a permanent exclusion, so the finding returns if the rollout
  stalls.
- If the finding fires on a domain the organisation does not own, the fix is inventory (remove it),
  not an exclusion rule.
