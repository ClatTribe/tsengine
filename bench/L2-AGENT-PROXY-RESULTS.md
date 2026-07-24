# L2-agent parity — measured through the frontier-LLM proxy (2026-07-24)

The two flagship L2 agents, driven by a **frontier LLM via the OpenAI-compat file-relay proxy**
(`LLM_BASE_URL` → relay; every ledger row `model=claude-proxy`, a real LLM-call path, NOT `--answer-file`).
Each bench's scorer is deterministic and §10-grounded, so the LLM supplies judgment but **cannot game the
score** — a recorded finding is rejected unless a tool result backs it.

## AI security engineer — three axes, all measured this session

| Axis | Bench | Competitor / floor | AI engineer (frontier via proxy) | Ledger |
|---|---|---|---|---|
| **Impact accuracy** | `impact` | substrate ranks by tags: **0%** on the mistagged estate | **100% PASS, +100 pts, 0 invented** | `impact-ledger.jsonl` |
| **Impact discovery** | `discover` (8 scenarios) | severity/keyword baseline **0–50%** | **8/8 PASS · recall 100% · precision 100% · 0 invented** | `discover-ledger.jsonl` |
| **Cloud depth (attack-path)** | `cloud-engine --cloudquery --agent` | deterministic substrate | **2/2 recall · 0 invented · STRONG (1.00)** — matched, resisted 8 noise findings | `cloudengine-ledger.jsonl` |

**What each proves against a competitor.**
- *Accuracy*: the substrate (≈ any tag/severity-sorting scanner) ranks a throwaway "critical" RCE above an
  AdministratorAccess key tagged medium → 0%. The engineer reads the detail and re-ranks correctly → +100.
- *Discovery*: on an estate mixing real cross-surface chains with plausible noise, the engineer finds every
  real impact and flags zero decoys — including the hard precision cases (an explicit-Deny-broken AssumeRole
  chain rejected, a hardened all-noise estate flagged empty, two individually-low findings composed into the
  wedge). A severity-sorter scores 0–50%.
- *Cloud depth*: navigating a live cloud graph by tool calls, the agent recorded only the two grounded
  internet→crown paths and refused the 8 config-hygiene findings (public-logs bucket, public-IP instances,
  MFA-delete, a privesc finding that doesn't reach a crown) — 0 invented.

## The §10 grounding bar, observed firing live

- **impact/estate-mistagged (first attempt):** the frontier brain claimed the admin key *reaches a crown
  jewel* (reasoning "admin = takeover"). `reaches_crown` is a grounded attack-path fact the fixture doesn't
  model, so the scorer counted it **invented** and failed the run. The corrected run re-judged only PRIORITY
  (allowed) and left CROWN empty → PASS. Judgment re-ranks impact; it never fabricates reachability.
- **cloud-engine:** `record_issue` would have rejected any path not in the graph — so the agent could not
  have recorded the `ci-role` privesc finding even had it tried; only tool-confirmed paths commit.

## Honest gaps this run surfaced (the improvement backlog)

1. **Cloud depth lift is not yet measured.** The default account is *non-discriminating* — the substrate
   already finds 2/2, so the head-to-head measured parity, not lift. The `--discrimination` sweep shows
   large accounts leave **6 recoverable paths the bounded substrate misses**; driving the agent there
   (proxy, ~30 turns) is the pending lift measurement.
2. **Remediation not exercised.** The cloud run recorded the paths but did not `propose_fix` each, so
   remediation coverage read 0%. The full engineer job is detect **+ verified fix** (the defensive
   remediation-capture metric) — the next drive should propose and verify a fix per path.

## AI offensive agent — gated on live targets (not on the LLM)

The proxy unblocks the *brain*, but the XBOW 104-flag suite needs live challenge targets (absent here; no
docker), so the offensive number stays **89/104** (`XBOW-SCOREBOARD.md`, a concluded tractable ceiling).
The remaining 15 are need-sandbox-tooling / EOL-unbuildable / infeasible-black-box — the offensive backlog.
