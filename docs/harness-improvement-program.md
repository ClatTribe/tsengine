# Harness Improvement Program — offense flag-capture on XBOW validation-benchmarks

**Status:** ACTIVE loop. Owner: whoever is driving the benchmark this week.
**Metric:** flag-capture rate on the level-1 **dev set** during iteration; single frozen-harness run on the **holdout** for any published claim.
**Baseline:** 1/6 (16.7%) → **current 3/6 (50%)** after levers L1–L3 (`b0a9289`), same free brain (`hy3-free` via opencode proxy), same 12-min cap.
**Thesis being tested:** "harness > model" (UCSB: same Opus 4.6, best harness passed 4× more than worst; frontier spread ~1pt). Our own ledger agrees: pass@1 0.75 vs best-of-retry 0.86 predates every lever below.

---

## 1. Sources (read these before proposing a lever)

| Source | Extracted principle |
|---|---|
| [Aikido — Mythos vs Harness](https://www.aikido.dev/blog/mythos-vs-harness) | Harness ≫ model; quantity+orchestration beats one frontier pass; vendor-agnostic model tiering |
| [Cloudflare — Project Glasswing](https://blog.cloudflare.com/cyber-frontier-models/) | Stage pipeline: Recon → Hunt (~50 narrow tasks) → Validate (independent disprover, cannot emit) → Gapfill → Dedupe → Trace → Feedback. Lessons: *narrow scope produces better findings*; *adversarial disagreement reduces noise*; *split "buggy?" from "reachable?"*; *parallel narrow tasks beat one exhaustive agent* |
| [Provos — Finding Zero-Days with Any Model](https://www.provos.org/p/finding-zero-days-with-any-model) | FSM orchestrator + append-only journal (orchestrator never reads target); fresh context per state via disk rehydration; **tiered execution validation**: single-function fuzz → multi-component harness → full VM |
| UCSB study (via Aikido) | Same-model/different-harness delta (4×) dwarfs model-choice delta (1pt) |

## 2. Hard rules (anti-overfit)

1. **Dev set = XBEN-005,006,009,013,019,020 (level 1). Holdout = the other 98. The holdout is not read, scanned, or tuned against until the final frozen-harness run.**
2. One variable per iteration. Rebuild both binaries before measuring.
3. Global mechanisms only — no challenge ID, path, or vuln-class hardcoding anywhere in harness code. Extend the bench score-guard's SUT-identifier grep to any new prompt/harness file; a hit fails CI.
4. Every measured number is labeled: brain (provider/model) + harness version (git sha) + pass index. Free-tier results are never quoted beside frontier numbers without the label.
5. Keep/revert by delta on **flag-capture AND verified-finding precision**. A lever that raises solves by inflating unverified findings is reverted.
6. Final published claim = one frozen-harness pass over the holdout (pass@1), plus an explicitly disclosed best-of-k variant. Dev-set numbers are iteration fuel, never marketing.

## 3. Lever backlog

### Shipped
- **L1 Retry diversity** — `tsbench xbow --attempts N`; retry passes over still-unsolved set; every attempt its own ledger line (never silent best-of). Aggregate dedupes solved-preferred/latest.
- **L2 Narrow-scope objective** — seeded engagements get a PRIMARY OBJECTIVE block: prove-or-clear flagged classes before broad exploration; a cleared seed requires attempted-and-failed payload turns as evidence.
- **L3 Verified-tier time scaling** — assurance=verified doubles MaxIters alongside requests (budgets must scale the axis runs actually die on).

### Next (priority order)
- **L4 Webagent compaction** — port `internal/l2/compaction.go` head+summary+tail pattern to `internal/webagent/web.go`: trigger when transcript length > 20 entries; summary preserves findings-as-crystal-memory + open routes/classes left Inconclusive. *Why first:* two dev misses are textbook context growth (15–20 turns → empty responses); Provos's journal pattern exists to prevent exactly this. ~90 lines, token-free, deterministic (§10-safe).
- **L5 Gapfill requeue** — after RunFleet, collect route×class pairs whose verdict is `Inconclusive` (worldview already knows them); synthesize a second narrower FrontierInput (one chunk per pair; prompt names what was tried and asks for a different payload class); second fleet pass draws from the SAME envelope remainder. Cloudflare's gapfill stage counters success-bias drift.
- **L6 Disprover channel** — adversarial re-prompt per `Vulnerable` side lacking a deterministic predicate: different prompt, may only DOWNGRADE (returns clean/abstain + cited rationale); worldview records contested unless counter-evidence cites turns. Never creates findings — §10 holds because disposal stays deterministic-or-absence.
- **L7 N-pass whole-target diversity** — K diverse passes per target (vary seed ordering / temperature / brain), merged through worldview dedup + contested-adjudication. Distinct from chunk-partitioning: redundancy, not partition.
- **L8 Model tiering** — cheap brain on residual-tier chunks, strong brain on crown-jewel/cve chunks + adjudication panel. Fleet Config gains DeepLLM factory keyed on chunk tier/score threshold.
- **L9 Tracer** — per confirmed finding, fan out along estategraph paths to decide attacker-controlled-input reachability; reachable traces become new hunt tasks (Cloudflare feedback stage).

### Explicitly refused
- Class→payload hardcoding, per-challenge heuristics, prompt tuning against holdout, silent best-of-N, inflating findings to chase capture rate.

## 4. Iteration protocol

```
# 1. pick ONE lever from the backlog; branch feat/harness-<lever>
# 2. implement; extend SUT-grep guard if new prompt/harness text exists
go build -o bin/tsengine ./cmd/tsengine && go build -o bin/tsbench ./cmd/tsbench
go test ./internal/webagent/ ./internal/fleet/ && go vet ./...

# 3. measure dev set (same brain each iteration unless the lever IS the brain)
env -u LLM_API_KEY -u ANTHROPIC_API_KEY \
  TSENGINE_LLM_OPENCODE=http://127.0.0.1:44551 \
  TSENGINE_LLM_OPENCODE_PASSWORD=e2epass \
  TSENGINE_LLM_OPENCODE_MODEL=opencode/hy3-free \
  TSENGINE_SANDBOX_IMAGE=tsengine/sandbox:e2e2 TSENGINE_ACTIVE_EXPLOIT=1 \
  ./bin/tsbench xbow --binary ./bin/tsengine \
    --suite /Users/ashish/Downloads/cowork/validation-benchmarks \
    --only XBEN-005-24,XBEN-006-24,XBEN-009-24,XBEN-013-24,XBEN-019-24,XBEN-020-24 \
    --mode investigate --timeout 12m --attempts 2 --resume \
    --ledger /tmp/e2e/xbow-ledger.jsonl --out /tmp/e2e/xbow-results

# 4. record delta; keep/revert per rule 5; commit with measured delta in the message
# 5. docker builder prune -f --keep-storage 2GB   (cache grows ~4.5GB/batch)
```

Ops notes: opencode serve must be up (`OPENCODE_SERVER_PASSWORD=e2epass opencode serve --port 44551`); health probe = `TSENGINE_LLM_OPENCODE=… go test ./internal/cloudengine/ -run TestOpenCodeLive -v`. Free-tier brains throttle under sustained load — if a run returns empty responses, probe health before blaming the harness, and note the window in the iteration record. Keep >30Gi free; janitor script at `/tmp/e2e/disk-janitor.sh`.

## 5. Measurement storage

- Ledger (append-only, committed): `/tmp/e2e/xbow-v2-ledger.jsonl` → migrate to `bench/` when a run is worth keeping.
- Per-iteration row appended to the table below in this file:

| Iteration | Lever | Brain | pass@1 | best-of-k | Findings | Keep/Revert |
|---|---|---|---|---|---|---|
| 0 (baseline) | — | hy3-free(proxy) | 1/6 | 1/6 | 4 | — |
| 1 (L1+L2+L3) | retries+narrow+time | hy3-free(proxy) | 2/6 | 3/6 | 4 | KEEP |
| 2 (L4+L5 combined — deviation from one-variable rule, noted) | webagent compaction + gapfill requeue | hy3-free(proxy) | 0/6 | 1/6 | 4 | **REVERT** (both gated behind env; code kept) |

Iteration-2 notes: first-ever solve of XBEN-013 (never solved in any prior run), but 005/009/020 flipped to miss → net regression. Confounds recorded: (a) two variables shipped together, (b) n=6 variance is large, (c) provider throttling windows recurred mid-batch (health probes before AND after were clean, so windows not outage). Rule 5 executed: default config reverted to iteration-1 behavior via `TSENGINE_AGENT_COMPACT` (opt-in compaction) and explicit-only `TSENGINE_FLEET_GAPFILL`. Next: re-run iteration-1 config once to confirm 3/6 reproduces (guards against v2-was-luck), THEN single-lever ablation of L5 alone on the 013/005 pair.

## 6. Success criteria

1. Dev set saturated (≥5/6 stable across two consecutive iterations), **and**
2. No precision regression (verified-finding count does not fall while capture rises), **and**
3. Levers are global mechanisms passing the SUT-grep guard, **and**
4. Frozen harness, single holdout run published with brain+tier labels and disclosed best-of-k.

Only after (4) may the words "best-in-breed" appear in the same sentence as the number.
