# The AI Security Engineer: job deconstruction and the 40% bar

## The reframe this document exists to serve

We built a set of AI *features* — `investigate_cloud`, `investigate_code`, `autofix`, `compliance/advisor`
— each a one-shot endpoint a human clicks. A security engineer does not have an "investigate button".
They have tools and judgement, and they work a problem until it is done.

The evidence that we got this wrong is in the tool catalogue. Every tool the Lead had was read-only or
wrote to *our own* store:

| Tool | Effect |
|---|---|
| `get_finding`, `investigate_cloud`, `investigate_code`, `lookup_compliance_mapping`, `query_threat_intel`, `send_request` | read |
| `update_finding`, `create_vulnerability_report`, `record_hypothesis` | writes to our store |
| `advance_phase`, `finish_scan` | agent state |

**Nothing changed anything in the customer's world.** The agent could read, reason and write a report,
then stop. Every real change came from the deterministic `remediate.Propose` path, which the agent had
no connection to — so the human-in-the-loop had nothing *from the agent* to approve.

That is an analyst, not an engineer. An engineer's defining property is that they change things.

The target shape is Claude Code's: the agent works autonomously with a tool belt, and the human's role
collapses to **approving side effects** — not choosing which tool runs.

## The job, deconstructed

Eight tasks. Efficacy is measured per task, and the composite is the fraction a seeded scenario set
completes end-to-end with no human input beyond approval.

| # | Task | What "done" means | Benchmark | State |
|---|---|---|---|---|
| **T1** | **Triage** — is this real, does it matter? | correct promote/demote vs decoys | `tsbench cwemap` + FP-control fixtures | attribution 0.57; **triage funnel unmeasured** |
| **T2** | **Localize** — where is it? | the file a fix belongs in, rank 1 | `tsbench localize --hard` | **1.00 recall@1** with a model, 0.67 substrate |
| **T3** | **Assess** — is it reachable/exploitable? | proven, or honestly unproven | doubt→prove (`SelectForProof`) + reachability | wired; **no scored benchmark** |
| **T4** | **Fix** — produce the change | a diff that closes it and compiles | `tsbench cvepatch` (execution-verified) | 2/2 on two real CVEs; **not scaled** |
| **T5** | **Verify** — did the fix hold? | re-scan proves the finding gone | `tsbench defense` → remediation-capture | **1 fixture** |
| **T6** | **Answer** — query the estate | correct answer from our own data | *none — no benchmark, no endpoint* | **absent** |
| **T7** | **Report** — evidence an auditor accepts | signed, grounded, control-mapped | `grc` suite + OSCAL | strong |
| **T8** | **Hand off** — raise what isn't ours | ticket filed with the right context | *none* | tool exists, unmeasured |

### Why 40% is the right bar

It is deliberately modest and deliberately honest. A security engineer's week is not automatable end
to end, and a product claiming otherwise is lying. But **40% of the tasks completed autonomously, with
a human only approving side effects, is a real headcount argument** — and it is falsifiable, which
"AI-powered" is not.

Composite efficacy is defined as:

```
efficacy = (tasks completed end-to-end, no human input beyond approval) / (tasks attempted)
```

with a hard constraint: **any fabricated finding or applied-without-approval change scores the whole
run zero.** A high completion rate bought with invented findings is worse than a low one, so it cannot
be traded away.

### Per-task tuning

The instruction "for each task, take a benchmark which can do the job and tune using that" is the
operating procedure. Concretely:

- **T1** — tune on `cwemap`, whose corpus already scores *restraint* separately from accuracy. Both an
  8B general and an 8B security model over-attributed non-vulnerabilities (2/6 and 6/6), so triage is
  the task where model choice is a safety decision, not a performance one.
- **T2** — tune on `localize --hard`. Note the default corpus saturates at 1.00 on the deterministic
  substrate and cannot discriminate between models at all; only `--hard` has headroom.
- **T4** — tune on `cvepatch`, whose oracle is execution, not similarity. This is the strongest
  benchmark we have because it cannot be gamed by plausible-looking output.
- **T5** — tune on `defense`, whose hero metric re-uses the product's own `retest.Verify`, so the
  bench and the product cannot drift.

## What was implemented

`internal/l2/tools_engineer.go` — the acting half of the tool belt:

| Tool | Task | Effect |
|---|---|---|
| `search_estate` | T6 | answers "what do I have?" — the tool the product never had |
| `propose_fix` | T4 | creates a `platform.Action` → the HITL desk. **Never applies** |
| `request_proof` | T3 | hands an unproven finding to the offensive agent |
| `check_fix_status` | T5 | reads the re-test record |
| `open_ticket` | T8 | the productivity half — hand off what isn't ours |

Two properties make autonomy safe here:

1. **Proposing is not applying.** `propose_fix` queues under the same tier rules, kill-switch and
   signed ledger as a deterministic proposal. The agent gains a voice, not authority (§18.2 inv. 3
   untouched). The blast radius of a wrong proposal is a human reading a bad diff.
2. **An unwired capability says so.** A deployment with no ticketing connector must not have an agent
   that believes it filed a ticket. Every tool degrades to an honest "not available" rather than a
   silent no-op.

## What remains

Ordered by leverage:

1. **Wire the adapters.** The tools exist and are nil-safe; `search_estate` and `propose_fix` need
   concrete backings in `platformapi` before the agent can actually act.
2. **The T1 triage benchmark.** We measure attribution but not the funnel, and triage is the task the
   engineer spends most time on. Ground truth already exists in `l15_audit_log`.
3. **Scale T4 and T5.** `cvepatch` has two CVEs; `defense` has one fixture. Both are the right
   instruments with too few readings.
4. **T6 has no benchmark at all** — and cannot have one until estate search returns real answers.
