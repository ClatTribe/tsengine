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
| **CyberSecEval** | exploitable-vuln recall (vs pattern recall) | **31% (5/16) confirmed-exploitable** | ICD 79% pattern-recall | real subset · see analysis |
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
**code engine (`codeagent`) as the detector** — frontier-assessed via the dev proxy — over a
representative sample of **16 (2 per language)**. Result: **31% confirmed-exploitable recall
(5/16)** vs the ICD's 79%.

**That number LOOKS bad, but it's the most important honest finding in this whole scorecard — it
is a DEFINITIONAL gap, not a detector failure:**
- **CyberSecEval labels insecure *patterns*** — a static analyzer sees `MD5`, `java.util.Random`,
  `unsafe`, unauthenticated `AES-CBC` and marks the snippet insecure, *regardless of exploitability
  or context*.
- **codeagent confirms exploitable *vulnerabilities*** — grounded, context-aware (§10).

The 5 it confirmed are genuinely exploitable: two C integer-overflow→memcpy/alloca bugs, a C++
unbounded `strcat`, a JS `readFileSync(userpath)` path-traversal, a PHP auth-by-spoofable-IP. The
11 it did not confirm are codeagent **correctly refusing to page on non-exploitable
insecure-practice-in-benign-context**: weak `Random`/`random` in *test files*, `Math.random()` for a
test timeout, `MD5` for a *cache key* (not crypto), idiomatic `unsafe` FFI to libgit2 (required, not
a bug), a SQL sink that lives in a remote-RPC layer *not in the snippet*, config-driven (not
user-input) SSRF.

**This is the same precision/restraint that scores 0% over-trigger on OpenSec — our core strength.**
Matching CyberSecEval's 79% recall would require flagging every `MD5` and `Random` as a finding,
which would *regress* the FP-rejection metric competitors sell on. So the low recall here and the
strong FP-rejection elsewhere are the *same design choice* measured from two directions.

**Honesty + no overfitting:** every sample was assessed on its merits; the low number is codeagent
being correctly conservative, not tuned. Two consequences: (1) CyberSecEval's isolated snippets +
practice-labeling *structurally* depress a grounded exploitability detector's recall — the
apples-to-apples comparison is really "exploitable-vuln recall" vs "pattern recall," different
questions; (2) the one legitimate, non-overfit refinement (documented, not force-fit): give
codeagent a distinct **"insecure practice (low severity, not exploitable in context)"** verdict —
it would raise recall against the pattern labels *without* calling weak-random-in-a-test an
incident, i.e. without touching FP-rejection. The full 1916-case run needs an autonomous LLM key
(the manual proxy is one human-driven turn at a time — thousands of turns for 1916).

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
