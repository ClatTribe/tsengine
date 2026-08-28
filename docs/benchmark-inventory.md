# Benchmark inventory — what we have, what each PROVES, and what it needs

**Why this file exists.** During the 2026-08-28 harness campaign I twice proposed building a
benchmark this repo already had (`discover`, then `bountybench`), because nothing listed them in one
place with what each proves. A benchmark nobody can find is a benchmark nobody runs. Check this
table BEFORE writing a new bench.

## The distinction that matters

**WHO AUTHORED THE ANSWER KEY.** An in-house fixture measures fixture↔code agreement, not efficacy
(§14.2 rule 5). Only an externally-authored corpus can support a best-in-breed claim.

| Bench | Answer key | Proves | Needs |
|---|---|---|---|
| **bountybench** | **Stanford/BountyBench** | real bounties, 31 projects, Detect/Exploit/Patch split. INVENTORY ONLY — their harness scores | `--tasks <bountytasks clone>` (523MB) |
| **cvepatch** | **CVE-Bench (external)** | real CVEs + gold patch; localized/anchors. `fixed` needs their oracle | `--dataset fixtures/cvepatch/cvebench.json` |
| **IAM-Vulnerable** (go test) | **BishopFox** | AWS privesc recall + **FP control set** (the half that can go DOWN) | `IAM_VULNERABLE_DIR`, `IAM_VULNERABLE_TOOLTEST_DIR` |
| **Rhino GCP** (go test) | **RhinoSecurityLabs** | GCP privesc recall (no FP set — read one-sided) | `RHINO_GCP_CATALOGUE` |
| **SCuBA** (go test) | **CISA** | identity/SaaS baselines, EXECUTION-PROVEN mappings | transcribed, no input |
| **cloud-engine --cloudgoat** | **Rhino (published)** | cloud attack path vs documented real-lab compromise | none |
| **xbow / defense-xbow** | **XBOW** | flag capture / patch-and-prove. defense-xbow needs offensive capture FIRST | `--suite ../validation-benchmarks`; arm64: 21/104 need amd64 mysql |
| **patcheval** | external | patch correctness | Docker |
| — | — | — | — |
| **discover / discover-suite** | OURS | **CROSS-ASSET** recall+precision+grounding, 8 scenarios / 52 findings / 4 surfaces. Self-validating (flag-all must produce FPs) | `--scenario` or `--from-scan` |
| **cloud-engine --agent** | OURS | cloud agent vs substrate head-to-head | `--max-hypotheses 5` or it saturates |
| **crosssurface-agent** | OURS | NARROW ablation: does estate-awareness change what the agent finds | none |
| **defense / impact / accuracy / triage / localize / cwemap / autonomy / containment / scorecard** | OURS | regression + capability coverage | mostly none |

## Rules
1. **Survey this table before building a bench.** Twice burned.
2. **Quote the author with the number.** "8/8 on our own scenarios" ≠ "8/8 on BishopFox's corpus".
3. **A corpus that told us what to add is no longer held out** — lead with its FP half if it has one.
4. **Don't score against classes we have no detector for** — that is the honest denominator
   (bountybench prints it: 21 covered / 25 not).
