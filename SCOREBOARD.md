# tsengine competitive scoreboard

_Track 1 verification artifact (`docs/competitive-roadmap.md`). Regenerate after a bench run: `tsbench scoreboard --results <json> --out SCOREBOARD.md`._

| Category | Metric | Ours | At-par bar | Status |
|---|---|---|---|---|
| Web app · DAST | per-class Youden (TPR−FPR) | — not run | 56% — OWASP-ZAP 56% (best OSS DAST); commercial ceiling Acunetix/Netsparker 87% | — pending run |
| Repository · SAST | overall Youden | 39% | 35% — Fortify 35%; ceiling Veracode 51% | ✅ at/above par |
| L2 agent · autonomy | detection_rate (must-find) + verified_rate | — not run | 100% — must-find parity (detection_rate = 1.0), zero FP; verified_rate the differentiator | — pending run |
| Cloud account · CSPM | CIS-section recall | — not run | 100% — must-find CIS recall (Prowler/Scout/Wiz self-publish — no neutral leaderboard) | — pending run |
| API · recall parity | recall vs standalone OSS | — not run | 100% — orchestration drops nothing the standalone tool found | — pending run |
| IP/host · recall parity | recall vs standalone OSS | — not run | 100% — orchestration drops nothing the standalone tool found | — pending run |
| Domain · recall parity | recall vs standalone OSS | — not run | 100% — orchestration drops nothing the standalone tool found | — pending run |
| Container · SCA recall parity | recall vs standalone OSS | — not run | 100% — orchestration drops nothing the standalone tool found | — pending run |

**Summary:** 1 at/above par · 0 below · 7 pending a live run.

## Capability axis — internal instrument, NOT a market claim

The table above is the **asset** axis: it answers *"are we at par with the category
leader"*, which is why every row carries a neutral external bar. It cannot answer *"is
the engineer getting better at remediation"* — a learning question that cuts across every
asset. That is this axis (ADR 0018 item 1).

**These rows have no external bar and must never be published as one.** A benchmark's
value is its neutrality, and a vendor scoring its own product against ground truth it
authored is precisely the circularity `cloudengine/holdout.go` was written to escape. The
numbers below are useful for one thing only: telling whether a change moved a capability.

Every row is **credential-free and runnable on a laptop** — that is the point, because a
capability you cannot measure without infrastructure is one you will not measure.

_Run 2026-08-21 on `feat/frontier-ghoidc`._

| Capability | Harness (runnable command) | Result | Reads on |
|---|---|---|---|
| Attack-path discovery | `tsbench cloud-engine --scenarios 12 --seed 7` | recall 100% (48/48) · FP-reduction 100% (24/24) · 0 false paths | seeded synthetic accounts |
| **Attack-path generalization** | `tsbench cloud-engine --holdout 8 --holdout-k 3 --seed 11` | held-out FP-reduction **100%** · overfit gap **0.0 pts** · recall 100% | **held-out shapes, labelled by an INDEPENDENT oracle** |
| Remediation capture | `tsbench defense --mode substrate` | 100% remediation · 100% path recall, all 4 scenarios | seeded code+cloud estates |
| Offensive recall + grounding | `go test ./internal/webrange/` | agent sweep PASS · decoys present · no SUT leak in scorer | procedurally-generated range w/ decoys |
| Vulnerability localization | `tsbench localize` | recall@1 **1.00** · MRR **1.00** (8/8 scenarios, heuristic tier) | seeded CWE scenarios |

**The one row that means something on its own is generalization.** The rest score ~100%
because their ground truth and the code under test share an oracle — `holdout.go` says so
in its own header. The held-out row deliberately does not: it labels truth with
`cloudiam` including permission boundaries and trust policies, machinery the scored path
does not run. It read **50% with a 50-point overfit gap** before the permission-boundary
fix and reads 100% after, which is the only number here that changed because the product
got better rather than because it was asked an easier question.

## Competitor leaderboards (the bar)

- **Web app · DAST** — Shay Chen WAVSEP comparison, sectoolmarket.com (Acunetix 87% / Burp-Active 78% / HP-WebInspect 76% / IBM-AppScan 69% / Netsparker 87% / OWASP-ZAP 56%)
- **Repository · SAST** — OWASP Benchmark v1.2 (SAST cohort) (Checkmarx 47% / Fortify 35% / SonarQube 6% / Veracode 51%)
- **L2 agent · autonomy** — agentic-offensive leaders, exploitation-verified: Aikido (Doyensec head-to-head), XBOW (HackerOne US #1), strix (OSS), Horizon3 NodeZero (GOAD) (Aikido 49 verified vs XBOW 31 (Doyensec, $4k tier) — white-box, 4% FP / NodeZero attack-path proven / XBOW PoC-validated, ~0 FP (3% FP vs Aikido per Doyensec) / strix PoC-validated multi-agent)
- **Cloud account · CSPM** — CIS AWS Foundations Benchmark (mock-account recall)
- **API · recall parity** — standalone OSS tool (per-tool recall parity, CLAUDE.md §2.4)
