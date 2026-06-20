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

## Competitor leaderboards (the bar)

- **Web app · DAST** — Shay Chen WAVSEP comparison, sectoolmarket.com (Acunetix 87% / Burp-Active 78% / HP-WebInspect 76% / IBM-AppScan 69% / Netsparker 87% / OWASP-ZAP 56%)
- **Repository · SAST** — OWASP Benchmark v1.2 (SAST cohort) (Checkmarx 47% / Fortify 35% / SonarQube 6% / Veracode 51%)
- **L2 agent · autonomy** — agentic-offensive leaders, exploitation-verified: Aikido (Doyensec head-to-head), XBOW (HackerOne US #1), strix (OSS), Horizon3 NodeZero (GOAD) (Aikido 49 verified vs XBOW 31 (Doyensec, $4k tier) — white-box, 4% FP / NodeZero attack-path proven / XBOW PoC-validated, ~0 FP (3% FP vs Aikido per Doyensec) / strix PoC-validated multi-agent)
- **Cloud account · CSPM** — CIS AWS Foundations Benchmark (mock-account recall)
- **API · recall parity** — standalone OSS tool (per-tool recall parity, CLAUDE.md §2.4)
