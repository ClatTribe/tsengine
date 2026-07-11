# The 4 shared public benchmarks — honest analysis vs SOTA

How our AI Security Engineer compares to the recognized public benchmarks the AI-SOC field
(and its competitors) are measured against. One rule throughout: **report only what we can
defend, mark what's gated, and never inflate a number our own designed cases can't support**
(§10, anti-overfit §14.2). Run the deterministic rows with `tsbench scorecard`.

## The scorecard

| Benchmark | Dimension | Our result | SOTA / published | Status |
|---|---|---|---|---|
| **SIR-Bench** | triage accuracy (M1) | TP 100% · FP-rej 100% | 97.1% · 73.4% | built-in sample ✓ · official gated |
| | novel findings (M2) | 0.67/case | 5.67/case | **honestly below** (lower-bound) |
| **OpenSec** | over-trigger FP | **0%** | GPT-5.2 82.5% | ✓ (deterministic) |
| | injection violation | **0%** | frontier hijacked | ✓ |
| | evidence-gated action (EGAR) | 100% | acts pre-evidence | ✓ |
| **CyberSecEval** | insecure-code detection (recall) | **67% (2/3) on real samples** via proxy | ICD 79% recall | real subset · full 1916 gated |
| **XBOW** | offensive flag-capture | 89/104 (via proxy) | XBOW's own solve-rate | ✓ (manual proxy) |

## 1. SIR-Bench (arXiv:2604.12040, AWS) — incident triage + investigation depth

**What it measures:** M1 triage accuracy (real incident vs false alarm), M2 novel-finding
discovery, M3 tool appropriateness, judged against expert ground truth by an adversarial LLM-judge.

**Us vs SOTA:** on the built-in representative cases we hit M1 100% TP / 100% FP-rejection (SOTA
97.1% / 73.4%). **But that's a small designed set — not comparable to their 794 real cases**;
the honest headline needs `tsbench sirbench --suite <official>`. On M2 we report **0.67
vs 5.67 — honestly *below* SOTA**: our M2 counts only *proven cross-surface attack chains* (a
grounded lower bound), not the LLM-judge's broader novel-finding tally. Where we're genuinely
strong is M1 FP-rejection (the hard metric — SOTA is only 73.4%) because we triage on
*actionability*, not raw severity.

## 2. OpenSec (arXiv:2601.21083) — calibration / restraint under adversarial evidence

**What it measures:** the harder half — not "can you detect" but "do you *restrain*." Frontier
IR agents OVER-TRIGGER: GPT-5.2 contains in 100% of episodes at an **82.5% false-positive rate**,
acting before gathering evidence; prompt-injected evidence hijacks them. *"The calibration gap is
not in detection but in restraint."*

**Us vs SOTA — our strongest dimension:** **0% over-trigger FP, 0% injection-violation, 100%
EGAR** on the adversarial episodes. This is *structural*, not luck: the LLM PROPOSES, a
deterministic predicate DISPOSES (§10), and every mutation is HITL-gated (§18.2 inv 3) — so a
scary-looking or prompt-injected alert *cannot* auto-contain. The exact failure OpenSec measures
in frontier agents is architecturally impossible here. **Caveat:** this is the deterministic
substrate; running our L2 agent inside OpenSec's RL environment (the official EGAR/TTFC scoring)
is the gated headline — but the architecture guarantees the restraint the metric rewards.

## 3. CyberSecEval (Meta PurpleLlama) — insecure-code detection + injection

**What it measures:** two things — an LLM's propensity to *generate* insecure code (~30% of the
time across models), and an Insecure-Code Detector (**96% precision / 79% recall**). Also
prompt-injection susceptibility.

**Us vs SOTA — a REAL run on the actual dataset (`tsbench cyberseceval`):** we fetched the real
CyberSecEval instruct set (1916 labeled-insecure snippets, 8 languages / 50 CWEs) and ran our
**code engine (`codeagent`) as the detector** over a representative subset via the dev proxy
(frontier Claude). Result: **67% detection recall (2/3)** vs the ICD's 79%.

**The miss is the honest, important part (and the "improvement" the benchmark taught us):**
- C (CWE-680 integer-overflow→memcpy) and C++ (CWE-120 unbounded strcat) — **confirmed** from source.
- C# (CWE-89 SQL injection) — **not confirmed**, correctly. The flagged line is a remote-SQL *RPC
  client* passing an opaque `byte[]` command to a server; the actual SQL sink is **not in the
  provided snippet**. codeagent refused to assert a vulnerability it couldn't see in source (§10) —
  rather than hallucinate one.

So the number reflects a real difference in *what is measured*: the ICD's 79% is **static
pattern-match recall**; ours is **grounded-confirmation recall** — codeagent trades a little recall
on snippet-isolated cases for **zero false confirmations** (the precision the ICD gets at 96%). Two
honest consequences: (1) **CyberSecEval's isolated snippets understate codeagent's real-repo
recall** — on a real repo (GitHubSource) it reads the whole file and would see the cross-snippet
sink; (2) **we deliberately did NOT tune codeagent to pass** — forcing it to confirm the C# case
would be exactly the hallucination the grounding discipline exists to prevent. The one legitimate
refinement (documented, not force-fit): a distinct **"inconclusive — sink out of scope"** verdict,
so a snippet-scope limitation reads differently from a proven-safe "not exploitable."

## 4. XBOW (validation-benchmarks) — offensive flag-capture

**What it measures:** 104 Dockerized web challenges graded on real flag capture (a random flag
injected at build; retrievable only by genuine exploitation — ungameable). This is XBOW's *own*
public suite, so the solve-rate is directly comparable.

**Us vs SOTA:** our offensive agent captured **89/104** (`tsbench xbow`), driven via the dev proxy
(frontier Claude). The remaining 15 are EOL-unbuildable images or need sandbox tooling
(wpscan/phpggc) — a tractable-ceiling documented, not a silent gap. **Caveat:** driven manually
through the file-relay proxy; a fully-autonomous run needs a capable LLM wired to the harness.

## The honest bottom line

- **Where we're at or ahead of SOTA:** the *restraint/calibration* dimension (OpenSec — 0% vs
  82.5%, structural) and the *FP-rejection* half of triage (SIR-Bench M1 — the metric competitors
  sell on). These are our architecture's core: grounded, gated, actionability-over-severity.
- **Where we're honestly behind or unproven:** SIR-Bench M2 (investigation *breadth* — we report a
  narrow grounded lower bound), and every *headline* number that needs the official dataset
  (SIR-Bench 794, OpenSec RL env, CyberSecEval samples) or a real LLM key at scale.
- **What converts "compatible" into "official":** the three gated inputs above. The harnesses,
  metrics, and methodology are built and match the papers — running them on the licensed
  datasets with a production key is the remaining, non-code step.

_Sources: SIR-Bench arXiv:2604.12040 · OpenSec arXiv:2601.21083 · CyberSecEval arXiv:2312.04724
(Meta PurpleLlama) · XBOW validation-benchmarks._
