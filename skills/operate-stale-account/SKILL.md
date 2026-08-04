---
name: operate-stale-account
description: Triage a dormant identity that still holds access, and decide whether it is abandoned, seasonal, or a live foothold.
version: 1.0.0
matches:
  rule_ids:
    - operate::stale-account
---

## Triage

A stale account is only interesting because of what it still *can* do. Before anything else,
establish the blast radius:

- Does the account hold an admin or super-admin role binding? A dormant admin is a different alert
  from a dormant contractor.
- Does it hold standing OAuth grants, API tokens, or SSH keys? Those survive a password reset and
  are the usual reason a "disabled" account is still live.
- Is MFA enrolled? An idle account without MFA is a credential-stuffing target with no second gate.

Dismiss as benign only when all three are true: no privileged binding, no standing credential, and
the account is a known service/shared mailbox with a documented owner. Idle alone is not benign.

## Investigation

Reach a verdict on whether the dormancy is *administrative* (someone left, offboarding was
incomplete) or *adversarial* (the account is being kept alive quietly).

Look for:

- **Last sign-in vs last activity.** An account with no interactive logins but recent token refreshes
  or API calls is not dormant — something is using it non-interactively. Treat that as suspicious.
- **Sign-in geography and ASN.** A dormant account whose only recent authentication came from a new
  country or a hosting provider is the account-takeover shape, not the offboarding shape.
- **Privilege changes during dormancy.** A role granted to an account that nobody has interactively
  used is a strong signal — legitimate offboarding removes privilege, it does not add it.
- **Suspension state vs role binding.** A *suspended* account that still holds an admin binding is
  standing privilege that survived the disable — the deprovisioning-completeness gap. That is a real
  finding even with zero recent activity.

Verdicts:

- `malicious` — evidence of use during dormancy from an unexpected origin, or privilege added while
  idle.
- `suspicious` — non-interactive activity, or a privileged binding surviving suspension, without a
  documented owner.
- `inconclusive` — no sign-in telemetry available to distinguish the two. Say so; do not guess.
- `benign` — unprivileged, no standing credentials, documented service account.

## Tuning

If this rule is firing on accounts that are legitimately idle by design, propose narrowing rather
than silencing:

- Exclude documented service accounts by an explicit inventory attribute, never by a name pattern —
  `svc-*` is trivially spoofable by an attacker who can create accounts.
- Raise the idle threshold only with the owner's agreement, and only for unprivileged accounts.
- Never propose excluding accounts that hold admin bindings, regardless of idle time. That is the
  population the rule exists for.
