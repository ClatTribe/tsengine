# Neutral benchmarks — how we evaluate the AI Security Engineer and the AI Pentester

**Rule: every capability claim is measured on a benchmark someone else built.** We do not grade our own
homework. Where no neutral benchmark exists for a capability, this document says so plainly rather than
substituting one of ours and presenting it as an external result.

That rule costs us something, and it is worth being clear about what. We have ~10 internally-built
benchmarks in `internal/bench` (below). They are useful as *regression tests* — they catch us breaking
our own product. They are not evidence of capability relative to anyone else, and they must not be
quoted as if they were.

---

## 1. What a neutral benchmark has to be

1. **Someone else defined the tasks.** Not us, not derived from our fixtures.
2. **Someone else defined the oracle.** A pass/fail we cannot argue with — an exploit that fires, a
   test that goes green, a flag string that matches. Not an LLM judge we configured.
3. **Published baselines exist**, so our number means something next to somebody's.
4. **Reproducible by a third party** — public dataset, public harness, a license that permits use.

An internal fixture set fails (1) and (2) no matter how carefully it is built.

---

## 2. The map — capability → benchmark

### 2.1 AI Pentester (offence)

| Capability | Neutral benchmark | Oracle | Status here |
|---|---|---|---|
| End-to-end exploitation of a real web app | **[CVE-Bench](https://arxiv.org/pdf/2503.17332)** (ICML 2025 Spotlight) — real-world web-app CVEs | Exploit succeeds against a live container | **Not wired.** The closest match to what we sell. Highest priority. |
| Flag capture on adversarial targets | **XBOW's published 104** | Flag string match — ungameable | **Wired** (`tsbench xbow`). Third-party tasks. Needs a capable model to be meaningful. |
| General offensive-security capability | **[Cybench](https://arxiv.org/pdf/2408.08926)** (ICLR 2025 Oral) — 40 professional CTF tasks | Flag match, with subtask credit | **Not wired.** |
| Breadth of offensive tasks | **[NYU CTF Bench](https://neurips.cc/virtual/2025/poster/118134)** (NeurIPS 2024) — CSAW challenges | Flag match | **Not wired.** Overlaps Cybench; pick one first. |
| Pentest-shaped (not CTF-shaped) tasks | **[AutoPenBench](https://aclanthology.org/2025.emnlp-industry.114.pdf)** — generative-agent pentesting | Task-specific milestones | **Not wired.** Reported: 21% autonomous, 64% with human hints. |
| Web-scanner detection accuracy (L1, not the agent) | **WAVSEP** (Shay Chen) | Per-class TP/FP → Youden | **Wired** (`internal/bench/wavsep.go`). Measures the scanner tier, not the agent. |

### 2.2 AI Security Engineer (defence)

| Capability | Neutral benchmark | Oracle | Status here |
|---|---|---|---|
| **Fix a real vulnerability** | **[PatchEval-Verified](https://github.com/bytedance/PatchEval)** (ByteDance, Apache-2.0) — 230 CVEs, 2015–2025, **Go / JavaScript / Python** | Docker execution: `fix-run.sh` must exit clean AND the vuln must no longer be exploitable | **Not wired — top priority.** Language mix is exactly our customers' stack. Published baselines: GPT-5.6-Sol 83.9%, DeepSeek-V4-Flash 80.4%. |
| PoC generation + patching on real CVEs | **[SEC-bench](https://arxiv.org/pdf/2506.11791)** (NeurIPS 2025) | Reproducible PoC artifacts + validated patches | **Not wired.** Previously rejected as C/C++-heavy and ~200GB; PatchEval covers our languages better. Reported ceiling: 18% PoC, 34% patching. |
| SAST detection accuracy (L1, not the agent) | **OWASP Benchmark v1.2** | Per-CWE TP/FP → Youden | **Wired** (`internal/bench/sast.go`). Measured 0.387 Youden. |
| Cloud config posture | **CIS Benchmarks** | Control pass/fail | **Wired** (`internal/bench/cloud.go`, `tsbench cloud-baseline`). CIS is neutral; the fixture account is ours. |
| Vulnerability *reasoning* quality | **SecLLMHolmes** | Hand-built CVE instances with known answers | **Not wired.** |
| Threat hunting / blue-team response | **[standardised threat-hunting benchmark](https://arxiv.org/html/2509.23571v3)** (2025) | Detection of injected malicious activity | **Not wired.** Newest option; evaluate before committing. |
| **Triage — deciding what matters out of a scanner dump** | **NONE EXISTS** | — | This is the single largest honest gap. It is what the engineer spends most of its time on and there is no neutral leaderboard for it. Our `tsbench triage` is a regression test, not evidence. |
| **Cross-surface attack-path correlation** | **NONE EXISTS** | — | Our differentiating claim, and unmeasurable against anyone else today. |

### 2.3 Meta

| | |
|---|---|
| **[CAIBench](https://arxiv.org/pdf/2510.24317)** | A meta-benchmark aggregating cybersecurity-agent benchmarks. Worth tracking as the aggregator rather than wiring individually. |
| **[PACEbench](https://arxiv.org/pdf/2510.11688)** | Practical cyber-exploitation, closer to real targets than CTFs. |

---

## 3. What this means for our own benchmarks

These stay in the tree as **regression tests** and are relabelled as such. None may be quoted as a
capability result:

`defense.go` · `defensexbow.go` · `triage.go` · `impact.go` · `containment.go` · `autonomy.go` ·
`parity.go` · `discoverygen.go` · `clouddiscrimination.go` · `l2scorecard.go` · `cvepatch.go`

`cvepatch.go` specifically is **superseded by PatchEval**. It was built because SEC-bench was the wrong
language domain and too large; PatchEval is Go/JS/Python with a 230-case verified subset, which removes
that objection entirely. Keep it running as a fast local regression, stop treating it as the number.

---

## 4. Order of work

1. **PatchEval** — the defence claim, in our customers' languages, with an execution oracle and
   published baselines to sit next to.
2. **CVE-Bench** — the offence claim against real web apps rather than CTFs.
3. **Cybench** — general offensive capability, widely cited, good for comparability.
4. Re-label the internal suite as regression tests (done in this document; enforce in the scoreboard).

## 5. Infrastructure honesty

PatchEval, CVE-Bench and SEC-bench all require **Docker + Linux + substantial disk** (PatchEval: ~500GB
for all images). None can run on a laptop without Docker. Producing real numbers needs a build host —
that is a provisioning task, not an engineering one, and no number should be published until it runs
there. An adapter that cannot yet be executed is wired code, not a result.
