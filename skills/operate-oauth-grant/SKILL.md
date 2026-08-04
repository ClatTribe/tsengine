---
name: operate-oauth-grant
description: Triage a third-party OAuth grant — is this app a sanctioned integration or a shadow admin nobody approved?
version: 1.0.0
matches:
  rule_ids:
    - operate::oauth-admin-scope
    - operate::oauth-unverified-app
---

## Triage

An OAuth grant is a standing credential that survives password resets and, in most estates, is not
covered by MFA at all. Grade it by **scope first, publisher second**:

- **Directory or admin scope** (read/write users, roles, groups, org settings) makes the app
  effectively a shadow administrator. Whether it is "trusted" is beside the point until you know who
  granted it and why — a trusted vendor with an admin scope is still admin access held by a third
  party.
- **Unverified publisher** is a weaker signal on its own — plenty of legitimate internal tools are
  unverified — but unverified *plus* a broad scope *plus* an unknown grantor is the consent-phishing
  shape.
- **Per-user vs admin consent** matters. An admin-consented grant applies org-wide; a per-user grant
  compromises one mailbox. Same app, very different blast radius.

Dismiss as benign only when the app is on a documented sanctioned list *and* its granted scopes match
what that documentation says it needs. An app that is sanctioned but holds more scope than documented
is scope creep, not benign.

## Investigation

Determine whether this grant was an informed decision or an attack.

- **Who consented, and when.** A grant created by a single user shortly after a phishing wave, or
  outside working hours, is consent phishing until proven otherwise. A grant created by an
  administrator during a documented rollout is not.
- **Publisher identity vs app name.** Consent-phishing apps impersonate familiar names. Compare the
  publisher/tenant identity against the display name; a "Microsoft 365 Backup" app published by an
  unrelated tenant is the whole attack in one line.
- **What the scopes actually permit.** Mail read/send scopes enable silent exfiltration and internal
  phishing from a real account. Directory write enables persistence that outlives any password reset.
  Reason about the capability, not the scope string.
- **Whether it has been used.** A grant with no activity is a latent risk; a grant with sustained API
  activity from an unexpected region is an active one.

Verdicts:

- `malicious` — impersonating publisher, or consent obtained by phishing, or activity from an
  unexpected origin.
- `suspicious` — admin/directory scope with no documented owner or business justification.
- `inconclusive` — no consent audit log available to attribute the grant. Say so; the standing access
  is still real.
- `benign` — sanctioned app, admin-consented, scopes match documentation.

## Tuning

- Never propose excluding by app *display name* — it is attacker-controlled. Exclude by publisher or
  application id, which are not.
- If sanctioned integrations dominate the findings, the fix is an inventory of approved app ids that
  the rule can reference, not a blanket suppression of the admin-scope check.
- Do not propose suppressing the unverified-publisher check org-wide to quiet internal tools; scope
  the exclusion to the specific internal app ids instead.
