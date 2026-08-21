# tsengine competitive scoreboard

_Track 1 verification artifact (`docs/competitive-roadmap.md`). Regenerate after a bench run: `tsbench scoreboard --results <json> --out SCOREBOARD.md`._

| Category | Metric | Ours | At-par bar | Status |
|---|---|---|---|---|
| Web app · DAST | per-class Youden (TPR−FPR) | — not run | 56% — OWASP-ZAP 56% (best OSS DAST); commercial ceiling Acunetix/Netsparker 87% | — pending run |
| Repository · SAST | overall Youden | **46.5%** | 35% — Fortify 35%; Checkmarx 47%; ceiling Veracode 51% | ✅ at/above par — third on the published cohort |
| L2 agent · autonomy | detection_rate (must-find) + verified_rate | — not run | 100% — must-find parity (detection_rate = 1.0), zero FP; verified_rate the differentiator | — pending run |
| Cloud account · CSPM | CIS-section recall | — not run | 100% — must-find CIS recall (Prowler/Scout/Wiz self-publish — no neutral leaderboard) | — pending run |
| API · recall parity | recall vs standalone OSS | — not run | 100% — orchestration drops nothing the standalone tool found | — pending run |
| IP/host · recall parity | recall vs standalone OSS | — not run | 100% — orchestration drops nothing the standalone tool found | — pending run |
| Domain · recall parity | recall vs standalone OSS | — not run | 100% — orchestration drops nothing the standalone tool found | — pending run |
| Container · SCA recall parity | recall vs standalone OSS | — not run | 100% — orchestration drops nothing the standalone tool found | — pending run |

**Summary:** 1 at/above par · 0 below · 7 pending a live run.

**Provenance note on the SAST row.** It read **39%** until now, a figure that predates the
neutral OWASP measurement by roughly 1,100 PRs — the real number (46.5% Youden over all 2,740
BenchmarkJava cases) was published in #1223 and recorded in CLAUDE.md §16, and this table was
never updated. So the two documents in this repo disagreed about the same measurement, in the
direction that understated us, which is how nobody noticed.

Stated plainly because it bears on how much this row is worth: **I could not re-run it here.**
The BenchmarkJava corpus is not in the tree, so 46.5% is carried over from the commit that
published it rather than reproduced. The three capability rows below WERE re-run and are
reported at their measured values.

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
| **IAM privesc — recall** | `go test ./internal/bench/ -run IAMVulnerable_Live` (needs `IAM_VULNERABLE_DIR`) | **31/31 paths** | **BishopFox IAM-Vulnerable — EXTERNAL answer key** |
| **IAM privesc — FP/FN control** | `go test ./internal/bench/ -run PolicyCases_Live` (needs `IAM_VULNERABLE_TOOLTEST_DIR`) | **0 false positives / 5** · **0 false negatives / 4** · **Youden 1.00** on the control set (was 0.50) | **BishopFox tool-testing — EXTERNAL, two-sided** |
| **Identity/SaaS posture (EXTERNAL)** | `go test ./internal/bench/ -run SCuBA` (corpus transcribed, no env needed) | **0.993** detection recall · **0.990** on mandatory SHALL policies (was 0.322 / 0.426 on first run) | **CISA SCuBA baselines — EXTERNAL, and the STRONGEST of the three.** Its mappings are EXECUTION-PROVEN: for every mapped policy the test builds a violating snapshot, runs the real assessor and asserts the rule fires. The two cloud rows below only DECLARE their mappings |
| **GCP privesc — recall** | `go test ./internal/bench/ -run GCPPrivesc_Live` (needs `RHINO_GCP_CATALOGUE`) | **23/23 methods** (was 15/23 = 65.2%) | **RhinoSecurityLabs catalogue — EXTERNAL answer key. RECALL ONLY — see below** |

**The two IAM rows are the only ones whose answer key we did not write.** They come from
BishopFox's IAM-Vulnerable, the corpus CLAUDE.md §2.2.1 already names for the cloud
specialist. Read them together and read the caveats:

- Recall was **64.5%** on first run and is now 31/31. The corpus is therefore **no longer
  held out** — it told us which techniques were missing and we added exactly those. That
  is real coverage (each is a published primitive: SSM, CodeBuild, EC2 Instance Connect,
  SageMaker jobs, `cloudformation:UpdateStack`), and it is no longer a clean measurement.
- The FP/FN control set is the half that can go DOWN when you add detections, which is why
  it matters more. **0 false positives across all five**, including the three DENY-precedence
  cases the corpus was built to catch tools failing — and now **0 false negatives**, so the
  control set is clean on both sides.

  **This paragraph used to argue the opposite, and it was wrong in an instructive way.** It
  read: *"they fail for the SAME reason fp4 and fp5 pass: we evaluate at resource `*` and
  treat any condition as non-firm. That is one design decision bought in both directions,
  not two bugs, and moving it would trade the zero-FP result away."* That reasoning is what a
  plausible trade-off argument looks like when it is actually two defects wearing one coat.
  They were separable. Evaluating at the literal resource `*` was simply wrong — `*` in a
  REQUEST is the resource named `*`, which no real ARN is, so every resource-scoped grant
  answered "not allowed" and its escalation disappeared, in production as well as here.
  Treating every condition as unresolvable was the second, independent one: a date bound on
  a request-time key is decidable from the clock, and a grant whose window closed in 2020
  read exactly like one gated on MFA. Both were fixed, and the false positives stayed at
  zero — the trade the paragraph asserted did not exist. The lesson worth keeping is that
  "we bought this deliberately" is the most comfortable thing to believe about a failing
  case, and the cheapest way to check it is to try fixing one and see what actually moves.

**The three external rows are not equally trustworthy, and the ranking is worth knowing.**
SCuBA is the strongest: nothing can be claimed there without the assessor being run against a
violating snapshot and observed to fire. Over nine iterations it refused four separate
mistakes — two unproven mappings, one attempt to claim policies CISA scopes as *procedural*
(credit outside the stated denominator), and one genuine product design error where two
findings were written as mutually exclusive and would have under-reported the tenant that had
done the harder half of the work. The two cloud rows have no equivalent guard: their mappings
are declared, and a wrong one would score.

**The GCP row is weaker evidence than the AWS pair, and the asymmetry is the point.** It
went 65.2% → 100% the same way AWS did — the catalogue named what was missing and we added
exactly that, so it too is no longer held out. But AWS has a neutral FP control set
(BishopFox's tool-testing) and **GCP has no published equivalent**, so nothing external
measures what those eight new techniques cost in false positives. There is an in-house FP
guard (`gcpiam/privesc_fp_test.go`: benign permission sets must fire nothing; a deploy
permission without `actAs` must fire nothing) — that is a regression guard, not evidence of
specificity, and it is exactly the kind of self-graded number this section exists to warn
about. Read the GCP row as one-sided until a neutral control set exists.

**Of the internal rows, the one that means something on its own is generalization.** The rest score ~100%
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
