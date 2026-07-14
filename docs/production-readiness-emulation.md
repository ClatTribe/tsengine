# Production readiness via emulation — the honest go/no-go

Can we assess production readiness **without customer credentials**? Yes — the product was
built so every integration has a credential-free *emulation* path (posted-snapshot detectors +
the dev proxy for the LLM). This is what that emulation proves, what it can't, and the verdict.

## What emulation covers (and the evidence)

Every benchmark below runs with **no customer credential** — synthetic estates through the real
detectors + the dev proxy (frontier Claude) for the agents.

| Capability | Benchmark | Result | Credential-free? |
|---|---|---|---|
| Per-integration detection | `tsbench integration` | 7/7 clean-sweep, 13/13 recall, 0 FP | ✅ deterministic |
| AI agent depth (cloud/code) | `tsbench integration --agent` (proxy) | cloud 3/3 paths, code 1/1, **0 invented** | ✅ proxy |
| Cross-tool correlation | `tsbench …` (correlation bench) | 3/3 cross-surface chains, 0 spurious | ✅ deterministic |
| L2 Lead triage | `tsbench l2lead` (proxy) | surfaced ✓, led-with-crown ✓, grounded | ✅ proxy |
| **Alert triage under noise** | `tsbench triage` | **TP 100%, FP-rejection 100%, 0/3 decoys mis-escalated** | ✅ deterministic |
| Remediation efficacy | `tsbench defense` | remediation-capture via `retest.Verify` | ✅ deterministic |
| Multi-language reachability | `internal/reachability` tests | Go+JS/TS+Python, e2e | ✅ deterministic |

**What this establishes:** the machinery is *correct and grounded* — it detects the planted
threats, correlates them across surfaces, triages noise the way an AI SOC is measured
(FP-rejection + calibration), the agents don't hallucinate (§10), and fixes are verified. That is
strong evidence the engine + agents behave correctly.

## What emulation CANNOT prove (the honest limits)

1. **Live recall on real deployed targets.** Every number above is on a *synthetic* estate. Real
   per-asset detection recall (vs a live WAVSEP/OWASP-Benchmark/real cloud account) has only ever
   been measured for SAST (0.387 Youden). Emulation proves correctness, not field recall.
2. **Real-noise false-positive rate.** The triage bench uses *designed* decoys; a real alert
   stream is messier. FP-rejection on real data may be lower than 100%.
3. **Agent quality at scale.** The agent runs were driven by frontier Claude through the manual
   proxy — frontier-grade, but small-N and hand-driven, not a customer's LLM key at volume.
4. **The live "hands."** Live cloud fetch, GitHub PR-open, IdP suspend, Slack alerts are
   credential-gated stubs. Their *detection/decision* twins are emulated; the *mutation* isn't.

## Verdict

- **Pilot / design-partner: yes.** The whole loop — ingest → AI engineer → correlate → triage →
  compliance → HITL — runs single-box, credential-free, and passes every benchmark. Good enough
  to put in front of a friendly customer.
- **General availability for paying customers: not yet.** The blockers, in order:
  1. **Merge the 6 open PRs** (#1005/#1007/#1009 wiring; #1011/#1012/#1013 benchmarks) — nothing
     ships until they land.
  2. **Green CI** — `lint` fails on pre-existing repo debt (`strings.Title`, gofmt drift in
     unrelated files); clean it so the pipeline is trustworthy.
  3. **One real-target validation** — recall + agent quality against ≥1 deployed app + a real LLM
     key, to convert "correct in emulation" into "works in the field."
  4. **Scale hardening** — Postgres store, cloud-KMS vault, HA/microVM (all behind today's
     interfaces).
  5. **Billing / self-serve.**

## Where we stand vs competitor AI SOCs

Per [ai-soc-sota-gap.md](ai-soc-sota-gap.md): **ahead** on grounding, cross-surface correlation,
verified remediation, and HITL; **now at parity** on the category's headline metric (FP-rejection
+ calibration) via the triage bench. The remaining SOTA work is field-validation (real noise) and
the investigation-depth / feedback-loop dimensions, not a rebuild.

**Bottom line:** the benchmarks are the right instrument and they're green — but a passing
benchmark is a floor, not a launch signal. Ready to **pilot**; the path to **GA** is merge →
green CI → one live validation → scale → billing.
