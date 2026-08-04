---
name: operate-excess-super-admins
description: Triage super-administrator sprawl — how many people hold unrestricted directory control, and did anyone grant themselves that?
version: 1.0.0
matches:
  rule_ids:
    - operate::excess-super-admins
---

## Triage

Super-admin sprawl is a blast-radius finding, not a misconfiguration. Every additional holder is
another account whose compromise ends the investigation, and the count is rarely the whole story.

Grade it by composition, not just quantity:

- **How many holders are human, interactive accounts?** Ten super-admins where six are service
  identities is a different problem (credential management) from ten individual people.
- **Do the holders have MFA?** A super-admin without a second factor collapses this finding and the
  MFA finding into a single takeover path — treat them together, not as separate tickets.
- **Are any holders stale?** A dormant super-admin is the worst combination in the estate: maximum
  privilege, minimum observation.

Dismiss as benign only when the count is at or below the organisation's documented threshold *and*
every holder is a named, active, MFA-enrolled human with a stated reason. "It has always been this
way" is not a reason.

## Investigation

The important question is not "are there too many" but **how did they get there**.

- **Compare against the last known-good set.** New super-admins since the previous assessment are the
  signal. A role granted to an account that nobody interactively uses, or granted outside a change
  window, is privilege escalation regardless of who appears to have granted it.
- **Look for self-grants.** An account that granted itself super-admin, or was granted it by an
  account compromised earlier in the same window, is the persistence step of an intrusion.
- **Check for privilege that survived offboarding.** A suspended or disabled account that still holds
  the role is standing privilege the deprovisioning process missed — real, even with zero activity.
- **Check break-glass hygiene.** Break-glass accounts legitimately hold super-admin, but should be
  few, individually documented, credential-vaulted, and alerted on when used. An undocumented
  "emergency" account is just an extra super-admin.

Verdicts:

- `malicious` — a role granted during or after a suspected compromise, or a self-grant.
- `suspicious` — new holders with no change record; or holders lacking MFA; or privilege surviving a
  suspension.
- `inconclusive` — no role-change audit history available to distinguish accumulation from
  escalation. Say so explicitly; the standing privilege remains real either way.
- `benign` — count within the documented threshold, all holders named, active, MFA-enrolled and
  justified.

## Tuning

- Raising the threshold is almost never the right fix. If the count is genuinely justified, propose
  documenting the holders rather than moving the line — a threshold raised to match reality stops
  measuring anything.
- Excluding service identities is reasonable **only** if they are separately covered by a
  credential-hygiene control; otherwise the exclusion hides the accounts least likely to have MFA.
- Never propose excluding break-glass accounts from the count. Their whole purpose is to be few and
  visible.
