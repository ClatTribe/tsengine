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

## AWSGoat (INE) — neutral cross-asset calibration, static

Cloned read-only (82MB); **never deployed** (`terraform apply` would stand up internet-exposed
vulnerable infra in a real AWS account — outward-facing and billable). The Terraform IS the estate:
`cloudtocode.IndexDir` reads 246 (module-1) + 40 (module-2) resources with no AWS credentials.

Ground truth = INE's 11 published attack manuals (an answer key we did not write).

**Step coverage: 9/11** — verified against the same "must name a real detector" rule as bountybench.
Uncovered: CWE-200 sensitive-data-exposure (app-level, see refusals above), CWE-668 ECS breakout.
IAM privesc is covered and VERIFIED: `cloudiam.DetectPrivesc` finds the `AttachRolePolicy`
escalation module-1's manual documents, from the Terraform alone.

### THE GAP THIS CORPUS FOUND (worth more than the 9/11)

AWSGoat's module-1 chain is: XSS → SQLi → IDOR → **SSRF → IMDS → stolen instance creds → IAM
privesc**. We detect the individual steps, but **nothing bridges SSRF to the cloud role it
compromises**:

- `internal/correlate` has NO ssrf handling at all, and no notion of `169.254.169.254`/IMDS.
- `EntAWSKey` extracts static `AKIA` keys from finding text. Credentials obtained via IMDS never
  appear as such a string, so no entity links the web finding to the cloud principal.

So on the canonical cloud attack chain we would report a web SSRF and a cloud privesc as two
unrelated findings — missing exactly the cross-surface hop the product is sold on. Our own
`discover` fixtures bridge via leaked keys/ARNs/hosts, which is why they never surfaced this.

**This is the argument for neutral corpora in one example**: 8/8 on fixtures we wrote, and a
first-class gap on the first externally-authored chain we checked.
