# Is the AI Security Engineer state of the art? — competitor + benchmark gap analysis

The question: how does tsengine's **AI Security Engineer** (the L2 Lead generalist +
cloud/code specialists over the L1 substrate) compare to the leading **AI SOC** products, what
do the recognized benchmarks measure, and what must we build/test/change to be state of the art.

## 1. The competitor AI-SOC landscape (2026) and the metrics they market

| Vendor | Positioning | Headline metric they sell on |
|---|---|---|
| **Dropzone AI** | Autonomous Tier-1 alert triage across the stack, 24/7 | **5× faster MTTR**, 90+ integrations, "investigates every alert" |
| **Prophet Security** | Fleet of autonomous AI agents (T1–T3), triage → hunt | **96% false-positive reduction**, **90% MTTR reduction**, zero dwell time |
| **Simbian** | AI SOC agents + a published AI-SOC **LLM benchmark** | TP/FP verdict accuracy, evidence-grounded interpretation |
| **CrowdStrike Charlotte AI** | Agentic detection triage inside Falcon | agentic triage accuracy, "hours → seconds" |
| **Microsoft Security Copilot** | Agents (phishing triage, alert triage) | analyst-time saved, autonomous handling rate |
| **Google (Sec-Gemini / Alert triage agent)** | triage agent | **~30 min → ~1 min**, 5M+ alerts/yr processed |
| **Radiant / Intezer / Torq HyperSOC / 7AI / Qevlar** | AI SOC / autonomous investigation | autonomous-resolution %, MTTR, FP reduction |

**The pattern:** every AI SOC sells on ONE core promise — *cut alert fatigue*: correctly **dismiss the
flood of false positives** while **never missing the real threat**, fast, with an auditable rationale. The
marketed numbers are **false-positive reduction %**, **MTTR reduction**, and **autonomous-resolution rate**.

## 2. What the recognized benchmarks actually measure

Unlike offense (XBOW's flag-capture is the de-facto standard), **defense/AI-SOC has no single neutral
leaderboard yet** — but a cluster of 2025-26 academic benchmarks has converged on the dimensions:

- **SIR-Bench** (*investigation depth in incident-response agents*) — three headline metrics:
  **TP-detection rate** (97.1% SOTA), **FP-rejection rate** (73.4% SOTA — note how much *lower*, this is
  the hard part), and **novel key findings per case** (5.67 — investigation depth).
- **OpenSec** (*calibration under adversarial evidence*) — does the agent stay correct when the evidence is
  **misleading/planted** (a benign thing dressed up to look malicious, or vice-versa). Measures over-
  confidence and mis-calibration, not just accuracy.
- **Simbian AI-SOC LLM benchmark** — evidence-grounded TP/FP verdicts + security-contextual interpretation.
- **CyberSOCEval** — malware-analysis + threat-intel reasoning.
- **CyberSecEval** (Meta) — attack-helpfulness, insecure-code, prompt-injection — an LLM-safety eval,
  *not* triage accuracy (the recognized gap it doesn't cover).

**The SOTA eval dimensions, distilled:** (1) TP-detection recall, (2) **FP-rejection under noise**,
(3) **calibration under adversarial/misleading evidence**, (4) investigation depth (novel findings),
(5) evidence grounding / no-hallucination, (6) explainability, (7) time/cost per investigation,
(8) MITRE ATT&CK coverage, (9) learning from analyst feedback.

## 3. Where tsengine's AI Security Engineer stands today

Mapped to those dimensions (from this session's benchmarks — `tsbench integration`, `l2lead`,
`correlation`, `defense`):

| Dimension | tsengine today | Verdict |
|---|---|---|
| TP-detection recall | 7/7 integrations, 13/13 planted; agents 3/3 + 1/1 via frontier proxy | **Strong** (on clean estates) |
| Cross-tool correlation | 3/3 cross-surface chains, 0 spurious | **Strong** (a real differentiator — few AI SOCs correlate code+cloud+identity) |
| Evidence grounding (§10) | invented=0 across agent runs; `record_*` refuses ungrounded | **Strong — arguably ahead** (deterministic tools dispose, LLM proposes) |
| Remediation efficacy | `retest.Verify` / defense bench (fix verifiably closes the issue) | **Ahead** (most AI SOCs triage but don't verify the fix) |
| HITL / safety | tiered autonomy, kill-switch, signed ledger | **Ahead** (auditable, gated) |
| **FP-rejection under noise** | only clean decoys; **no noisy alert stream** | **GAP — the #1 AI-SOC metric** |
| **Calibration under adversarial evidence** | not tested (decoys are benign, not *misleading*) | **GAP** (OpenSec dimension) |
| Investigation depth (novel findings/case) | not measured as a metric | **GAP** |
| Time/cost per investigation | not measured (iterations tracked, not gated) | **Gap (minor)** |
| MITRE ATT&CK coverage | techniques on findings, not benchmarked | **Gap (minor)** |
| Learning from feedback | ledger exists; no feedback-loop eval | **Gap (product)** |

**Reading:** we are **at or ahead of SOTA on grounding, correlation, remediation-verification, and HITL**
— genuinely differentiated (an AI *engineer* that fixes + proves, not just a triage bot). We **lag on the
one metric every AI SOC leads with: FP-rejection under realistic alert noise, and calibration when the
evidence is adversarially misleading.** Our estates are clean; SOTA is measured on floods of mostly-benign
alerts. That is the gap to close to be *demonstrably* state of the art.

## 4. What to build/test/change (prioritized)

1. **`tsbench triage` — the alert-triage benchmark (the #1 gap, this PR).** A realistic *noisy* estate
   where the large majority of alerts are benign/low-value, seeded with a few real threats AND
   **adversarially-misleading decoys** (a benign finding dressed to look critical; a "leaked key" that's a
   documented public sample; a CVE on an unreachable dep). Score the SIR-Bench/OpenSec metrics:
   **TP-detection rate, FP-rejection rate, calibration (mis-escalated decoys), precision**. Run it against
   the deterministic L1.5 triage *and* the L2 Lead via the proxy. This makes our number directly comparable
   to Prophet's "96% FP reduction" and SIR-Bench's 73.4% FP-rejection.
2. **Reachability/exploitability as the FP-rejection lever.** The reason to reject a CVE alert is *it isn't
   reachable/exploitable* — we already have `reachability` (multi-language now) + exploitability enrichment.
   The triage bench should reward using them to dismiss noise (a CVE on an unreachable dep → correctly
   deprioritized), turning an existing strength into the marketed metric.
3. **Investigation-depth metric** — count grounded "novel findings" per case (chains discovered, blast
   radius computed) as a scored dimension, aligning to SIR-Bench.
4. **Calibration report** — for every escalation, is confidence proportional to evidence? Penalize
   over-escalation of decoys (the OpenSec lens); we already have the confidence scalar + verification_status.
5. **Time/cost budget per investigation** — gate iterations/tokens as a scored efficiency dimension
   (AI SOCs sell speed; we should measure it, not just track it).
6. **MITRE ATT&CK coverage roll-up** — a bench that reports technique coverage across a scenario.
7. **Feedback loop (product)** — persist analyst accept/dismiss and measure whether triage improves — the
   5th Simbian/Prophet dimension. Longer-horizon.

**Bottom line:** the AI Security Engineer is already differentiated where it's hard (grounding, cross-
surface correlation, verified remediation, HITL). To be *provably* state of the art it needs the one thing
the category is measured on — **FP-rejection + calibration under realistic alert noise** — which is a
benchmark + a scored use of reachability/exploitability, not a rebuild. #1 above is built in this PR.

_Sources: Prophet Security, Dropzone AI, Simbian AI-SOC LLM benchmark, SIR-Bench (arXiv 2604.12040),
OpenSec (arXiv 2601.21083), CyberSOCEval (arXiv 2509.20166), Gartner Hype Cycle for Security Operations
2026, Help Net Security AI-SOC evaluation._
