# Metrics — what to measure, and when to kill something

## The funnel

```
domains scanned  →  emails sent  →  replies  →  calls  →  connected accounts  →  paid
```

`connected account` is the real activation event, not signup. A signup that never
connects a system has seen nothing and will not convert.

## Targets

Starting points, not benchmarks — replace with your own numbers after ~500 sends.

| Stage | Metric | Target | Kill threshold |
|---|---|---|---|
| Cold (seq 02) | Reply rate | 8%+ | <4% after 200 sends → the list is wrong |
| Cold | Positive reply | 3%+ | <1% → the offer is wrong |
| Blocked-deal (seq 01) | Reply rate | 20%+ | <10% → they weren't really triggered |
| Free scan | Scan → email capture | 25%+ | <10% → the `/scan` page is the problem |
| Nurture (seq 03) | Email 2 → signup click | 12%+ | <5% → inside/outside gap isn't landing |
| Product | **Signup → connected account** | 40%+ | <20% → onboarding is broken, stop all outbound |
| Product | **Connected → first proven finding < 1 hour** | 80%+ | <50% → this is an engineering bug, not GTM |
| Sales | Call → paid | 25%+ | <10% → we're calling unqualified people |

## Diagnosing by where it breaks

| Symptom | Almost always means |
|---|---|
| Emails open, nobody replies | The finding isn't landing as *their* problem. Rewrite the impact line, not the subject |
| Replies, no calls | We're asking too early. Give more before asking |
| Calls, no connections | Onboarding friction or a trust problem about cloud access. Watch a call |
| Connections, no findings | **Engineering.** Stop outbound until fixed — we'd be selling something that doesn't demonstrate |
| Findings, no purchase | The artifact isn't what the reviewer wanted. Ask the buyer to forward the reviewer's actual reply |

## The two leading indicators worth watching weekly

1. **Time from connect → first proven finding.** This is the product's whole
   promise. If it drifts above an hour, the demo stops working and every
   downstream number decays a week later.
2. **Share of replies that mention a specific deal or date.** That's the trigger
   rate in the list. If it's falling, list quality is degrading — fix sourcing
   before writing new copy.

## Attribution

Keep it crude and honest at this stage:

- `?domain=` permalinks in outbound carry a source tag; scans are attributable to the sequence.
- Badge renders are their own source — every render is a branded backlink.
- Ask "what made you run the check?" (sequence 03, email 3). Self-reported
  attribution from a warm contact beats any tracking we could build now.

Don't build attribution infrastructure until something is working well enough to
be worth measuring precisely.

## What NOT to measure

- **Open rates.** We send plain text with no tracking pixel — deliberately, because
  this audience notices. Opens are unmeasurable and that's the correct trade.
- **Emails sent.** An activity metric that rewards volume over list quality.
- **Vanity scan counts.** A scan that produces no email capture and no signup
  cost us nothing and earned us nothing.

## Review cadence

- **Weekly:** reply rate by sequence, connect rate, time-to-first-finding.
- **Monthly:** kill or rewrite any sequence under its threshold; re-check list
  sourcing against `icp.md`; confirm no disqualified segment (healthcare/PHI,
  card-data fintech) has crept into the send list.
