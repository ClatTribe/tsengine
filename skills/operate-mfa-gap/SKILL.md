---
name: operate-mfa-gap
description: Triage an account without MFA, and decide whether it is a routine enrolment gap or a live takeover exposure.
version: 1.0.0
matches:
  rule_ids:
    - operate::admin-without-mfa
    - operate::user-without-mfa
---

## Triage

One question decides everything: **what can this account do if the password is already known?**

- **Administrator without MFA** is the highest-value takeover target in the estate. A single
  credential-stuffing hit yields directory control, and directory control yields everything else.
  Never dismiss this on the grounds that the password is "strong" — MFA exists because passwords
  leak, and a strong password that appears in a stealer log is just a leaked password.
- **Standard user without MFA** is graded by what the user reaches: mailbox only, or SSO into
  production and cloud consoles? A user who is an SSO gateway to the cloud account is effectively
  privileged even with no admin role.

Dismiss as benign only for a genuine service/shared identity that cannot interactively authenticate
at all — and even then, prefer a verdict of `suspicious` if it holds standing tokens, because a
non-interactive identity with long-lived credentials has the same blast radius with none of the
sign-in telemetry.

## Investigation

Decide whether this is an **enrolment gap** (nobody set it up) or an **exposure** (someone is
already positioned to use it).

Look for:

- **Whether the credential is already public.** Cross-check the account against breached-credential
  and stealer-log exposure. A no-MFA account whose password appears in either is not a posture
  finding — it is an incident, and should be verdicted `malicious` on that basis alone.
- **Sign-in origin.** Authentications from a new country, a hosting ASN, or a residential-proxy range
  on a no-MFA account are the takeover shape.
- **Whether MFA was ever enrolled, then removed.** Enrolment that regressed is far more suspicious
  than enrolment that never happened — legitimate users do not usually remove their second factor.
  Pair this with any nearby `mfa_removed` identity-threat detection.
- **Legacy/basic authentication.** A tenant still permitting legacy auth lets an attacker bypass MFA
  even where it *is* enrolled. If legacy auth is on, treat enrolment status as unreliable and say so.

Verdicts:

- `malicious` — credential known to be exposed, or sign-in evidence from an unexpected origin.
- `suspicious` — MFA removed after having been enrolled; or an admin/SSO-gateway account with no
  second factor and legacy auth permitted.
- `inconclusive` — no sign-in telemetry available. Say so; the posture gap is still real and should
  be remediated regardless of the verdict.
- `benign` — non-interactive identity with no standing tokens, or enrolment confirmed in progress.

## Tuning

- Never propose excluding accounts that hold admin or directory roles. That is the population this
  rule exists for, and an exclusion there is indistinguishable from turning the rule off.
- Break-glass accounts are the one legitimate exception and must be excluded **individually, by
  identifier**, with a documented owner and compensating controls — never by a name pattern, which an
  attacker who can create accounts can satisfy on purpose.
- If the rule is noisy because enrolment is genuinely mid-rollout, propose a time-boxed suppression
  with an explicit expiry, not a permanent exclusion.
