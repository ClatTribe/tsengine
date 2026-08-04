# Detection Skills

Skills in the [Detection Skills](https://detectionskills.io) format — a folder with a `SKILL.md`
carrying YAML frontmatter and Triage / Investigation / Tuning sections. It is the Agent Skills
format, so these run anywhere Agent Skills run, not only here.

See [ADR 0017](../docs/adr/0017-detection-skills.md) for why we consume this standard rather than
compete with it.

## Layout

```
skills/<skill-name>/SKILL.md
```

## Frontmatter

```yaml
---
name: operate-stale-account          # required — a verdict is attributed to it
description: one line
version: 1.0.0
matches:                             # how a skill joins to our findings
  rule_ids:
    - operate::stale-account         # exact, or a namespace prefix ending in "::"
  cwes:
    - 89                             # "89" and "CWE-89" both work
  tools:
    - semgrep
---
```

Detection Skills are usually authored against SIEM/EDR telemetry fields. Our findings come from OSS
scanners and posture snapshots, so `rule_id` / `cwe` / `tool` is the join key. A skill that matches on
none of them simply never matches — reported as "no skill matched", never stretched into a false one.

## What a skill CANNOT do

A `SKILL.md` is untrusted input. It contributes **reasoning only**. These frontmatter keys are
refused at load, loudly:

`tools`, `allowed_tools`, `permissions`, `scope`, `allowed_hosts`, `egress`, `network`, `budget`,
`max_requests`, `gate_tier`, `tier`, `auto_apply`, `require_approval`, `exec`, `command`, `run`

Tools, scope, budget and human approval are the framework's to decide. A skill proposes a verdict;
the framework validates it against a closed enum and requires every cited finding id to really exist.
A tuning suggestion goes to the human-approval desk — it never auto-applies.

## Writing a good one

- **Be specific about dismissal.** The valuable half of triage is knowing when *not* to escalate.
  State the conditions for `benign` explicitly.
- **Name the evidence, not the conclusion.** Write what to look at and what each observation implies,
  so the verdict is derivable rather than asserted.
- **Prefer narrowing to silencing in Tuning.** And never propose an exclusion that an attacker could
  satisfy on purpose (a name pattern like `svc-*` is spoofable; an inventory attribute is not).
