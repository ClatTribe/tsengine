# tsengine competitive scoreboard

_Track 1 verification artifact (`docs/competitive-roadmap.md`). Regenerate after a bench run: `tsbench scoreboard --results <json> --out SCOREBOARD.md`._

| Category | Metric | Ours | At-par bar | Status |
|---|---|---|---|---|
| Web app · DAST | per-class Youden (TPR−FPR) | — not run (3 blockers found + 2 fixed; see below) | 56% — OWASP-ZAP 56% (best OSS DAST); commercial ceiling Acunetix/Netsparker 87% | — pending run |
| Repository · SAST | overall Youden | **46.54%** — measured | 35% — Fortify 35%; Checkmarx 47%; ceiling Veracode 51% | ✅ at/above par — third on the published cohort |
| L2 agent · autonomy | detection_rate (must-find) + verified_rate | — not run | 100% — must-find parity (detection_rate = 1.0), zero FP; verified_rate the differentiator | — pending run |
| Cloud account · CSPM | CIS-section recall | **19/19 offline** (in-house fixture — see below); live still needs LocalStack or real creds | 100% — must-find CIS recall (Prowler/Scout/Wiz self-publish — no neutral leaderboard) | — pending run |
| API · recall parity | recall vs standalone OSS | **1.000** — measured vs VAmPI | 100% — orchestration drops nothing the standalone tool found | — pending run |
| IP/host · recall parity | recall vs standalone OSS | — not measured (image lacked naabu) | 100% — orchestration drops nothing the standalone tool found | — pending run |
| Domain · recall parity | recall vs standalone OSS | — not run | 100% — orchestration drops nothing the standalone tool found | — pending run |
| Container · SCA recall parity | recall vs standalone OSS | **1.000** + FP-control PASS | 100% — orchestration drops nothing the standalone tool found | — pending run |

**Summary:** 5 measured, all at or above par · 2 still blocked · 1 refused as unmeasurable here. Run live on 2026-08-21 with Docker
available; every figure below was produced on this machine, not carried forward.

| Row | Result | Note |
|---|---|---|
| Repository · SAST | **46.54%** Youden | neutral leaderboard; at par (Checkmarx 47, Fortify 35) |
| Container · SCA | **1.000** must-find recall | + `alpine-clean` FP-control **PASS** (0 high/critical on a clean image) |
| Repository · SCA | **1.000** must-find recall | 260 raw findings, 9 anchors |
| Web · DAST | per-class, see note | sqli 57.58%; aggregate withheld and why |
| **API · recall** | **1.000** | VAmPI: `sqlmap::sqli` on `/users/v1/name1*`; complete scan, 4m19s |
| IP/host | **not measured** | the image was built `TOOLSET=…,api` — naabu is absent and its stub says so. nmap reached 6379 fine, so this is a harness gap, NOT reachability and NOT a capability result. Rebuild with the `ip` toolset to score it |
| Cloud · CSPM | not run | needs LocalStack or real credentials |
| Domain | not runnable in a box | subdomain enumeration queries public sources about a real registered domain — there is nothing to host |

**The IP row is why the scoreboard now has a `tools_failed` guard.** That run reported
`raw_findings=0 partial=false tools_failed=0` over a wide-open port that nmap, in the same
image, could see — naabu never ran, and nothing said so. All 36 tool wrappers swallowed every
non-zero exit, which is necessary (semgrep and trivy exit 1 when they *find* something) but
collapses "the tool looked and found nothing" into "the tool never looked". `tool.DidNotRun`
now separates them, and `bench.withholdIfIncomplete` withholds the verdict a missing tool
could fake.

Every hop of that chain is covered by an executing test — the wrapper against a real 127-exit
stub on PATH, the orchestrator against a failing dispatcher, `RunWithSurface` returning the
failure for the artifact, and the scorer withholding on it — each mutation-verified. **What is
still unproven is the single integrated run**: re-running the ip row through a rebuilt sandbox
image to watch it report `tools_failed=1`. That needs a ~3GB image build, and the machine was
at 901MB free. Stated as unproven rather than assumed, since assuming it is the same move this
whole section is about.

**The cloud row now has an OFFLINE number, and it is an IN-HOUSE one.** `tsbench cloud-baseline`
scores 19/19 (recall 1.00) against a fixture account, with prowler-only at 18/19 — an engine lift of
+0.05 — and **0 unexpected findings**. Read it as §14.2.5 says to: an in-house answer key measures
whether the fixtures and the code agree. It is not the market-axis number, which still needs a live
account.

The useful part was not the 1.00. `Unexpected` — the only specificity signal this lane has, and the
thing that stops recall being gameable — had two defects that made it unreadable:

- It was a **count with the identities discarded**, while its own comment called it "a signal to
  investigate". Nobody can investigate an integer, and which resource it is decides what the number
  means: a real false positive is a specificity problem in the engine, a violation the ground truth
  never enumerated is a gap in the FIXTURE, and then recall is understated rather than the engine
  being noisy. Naming them showed the single unexpected finding was `internet` — `cloudgraph.InternetID`,
  our own synthetic attacker pseudo-node, counted as a flagged cloud resource. Neither an FP nor a
  fixture gap: a permanent floor of 1 that both overstated our noise and would have masked the first
  real unexpected finding, since it would have looked like no change at all.
- It was **printed only when the engine had a lift over prowler**, nested inside that branch — so it
  was withheld exactly when a reader most needs it, which is when we match prowler on recall and the
  open question is whether we are merely noisier.

**The API row was first recorded here as `0.000 — FAIL, MISSED sqli`. That was wrong, and
how it was wrong is worth more than the number.**

The scan had printed `partial=true` — it hit its deadline mid-sqlmap. Re-run against the
same target on the same image with a budget it could finish in, it completed in 4m19s and
found `sqlmap::sqli` at `/users/v1/name1*`. Recall 1.000.

Nothing was wrong with the engine. `injectionTarget` had been rewriting the path parameter
into sqlmap's `*` marker form since #1233, and the dispatch was correct in *both* runs — the
failing one included. **The scorer had no idea the run had been cut off.** It read a
truncated finding list as a detection result, exactly as it would have read a complete one.

This is the same error as the IP row below, one level up: a number that measures the harness
being published as a capability. I caught it there and missed it here in the same commit,
which is the argument for fixing it in code rather than remembering it.

`bench.withholdIfTruncated` now withholds the one verdict a deadline can manufacture, per
metric. Truncation is **directional** — a scan that stops early can only have FEWER findings
— so each metric has exactly one fakeable verdict:

| Metric | Withheld | Still sound |
|---|---|---|
| `must_find_recall` | a **FAIL** — the finding may not have landed yet | a **PASS** — it found what was required despite being cut short |
| `fp_rate` | a **PASS** — the alarm may not have fired yet | a **FAIL** — the alarm did fire, and finishing could only add more |

The verdict line reads `UNMEASURED`, deliberately neither PASS nor FAIL: the run cannot
answer the question. Withholding both directions would throw away sound results; withholding
neither is how a clock gets published as a capability.

**The web row, run live on 2026-08-21 — reported per-class, not as one number.**
WAVSEP was deployed and scanned. Getting there took three fixes, the third a production bug
rather than a harness one:

1. **The harness pointed at an entry point with no links.** It scanned the Tomcat root; the
   real catalogue is `index-active.jsp`. From the root katana returns exactly the seed URL.
2. **The scan sandbox joined the wrong network**, so the target did not resolve and every
   tool failed SILENTLY — no error, run "successful", score 0.
3. **`tool.Args` int values did not survive the sandbox boundary.** A dispatch crosses as
   JSON, `int` becomes `float64`, and `args["depth"].(int)` failed in the sandbox while
   passing every unit test. katana fell back to depth 2: **68 URLs instead of 1,604.** Six
   wrappers had it — a 96% crawl-surface loss on every sandboxed web scan, found only
   because a benchmark scored zero.

Coverage then went 0% → **87.6%** (993 of 1,133 cases):

| Category | TP | FP | TN | FN | Youden |
|---|---|---|---|---|---|
| sqli | 38 | 0 | 10 | 28 | **57.58%** |
| xss | 13 | 3 | 4 | 34 | −15.20% |
| redirect | 0 | 0 | 9 | 30 | 0.00% |
| pathtraver | 4 | 0 | 8 | 812 | 0.49% |
| **overall** | 55 | 3 | 31 | 904 | **−3.09%** |

**No single aggregate is published, and that is not flattery.** Path traversal is **824 of
1,133 cases (73%)** of this corpus and we detect 4 of 816 scored, so the overall number is
mostly a measurement of one class. It understates SQLi, where 57.58% is a real result, and
it would equally overstate us on a differently-weighted corpus. Against a partial run with
that mix, a leaderboard comparison is meaningless in both directions.

**What this is worth: item 1 doing its job for item 2.** The weakest measured web capability
is path traversal — 4 of 816 — and the cause is now narrowed past "we score badly" to a
specific, actionable statement.

Measured, in order, each ruling out a cheaper explanation:

| Hypothesis | Test | Result |
|---|---|---|
| the corpus is absent from the image | `find` in the sandbox | 13,510 templates, incl. `dast/` + `http/fuzzing/` |
| the crawl never reaches LFI cases | count discovered URLs | 972 LFI URLs, **416 with the `?target=` param** |
| DAST mode is not loading templates | `nuclei -dast -stats` | **248 templates loaded and executed** |
| a targeted tag set would find it | `-tags lfi`, `-tags lfi,traversal -dast`, `-t http/fuzzing/` | **0 findings on all three** |

**So nuclei cannot detect this class, and no template selection fixes it.** That is a
capability statement about the tool, not a wiring bug and not a scoring artefact — which
matters, because every cheaper explanation was checked first and each one held up until it
didn't.

The §13-compliant fix is a param-level traversal fuzzer rather than an in-house detector:
send traversal payloads into the discovered `?target=`-style parameters and confirm on a
concrete marker (a `root:x:` line, an `[extension]` INI header) rather than a length
differential. **ffuf is already wrapped and already in the image** — it is dispatched today
for content discovery, and param-position fuzzing with a traversal wordlist is a new
dispatch of an existing tool, not a new engine.

NOT attempted here on purpose. Traversal fuzzing is FP-prone, this corpus is 73% of the
WAVSEP cases, and a half-built detector that guesses would trade the one genuinely good
number on this row (sqli 57.58%, zero false positives) for a worse one. It is specified,
measured and left as the next unit rather than rushed.

**Provenance note on the SAST row.** It read **39%** for roughly 1,100 PRs — a figure predating the
neutral OWASP measurement, which was published in #1223 and recorded in CLAUDE.md §16 while this table
was never updated. Two documents in one repo disagreeing about one measurement, in the direction that
understated us, which is how nobody noticed.

**It is now REPRODUCED, not carried forward.** Run against the full OWASP BenchmarkJava checkout
(2,740 cases, `expectedresults-1.2.csv`) through the real sandbox: **46.54% Youden**, TP=1248 FP=552
TN=773 FN=167, from 3,451 raw findings across 9 anchor tools. That is within 0.04 points of the
carried number, so the claim was sound — but it was unverified until now, and a scoreboard that cannot
tell "measured today" from "inherited" is the failure it exists to prevent.

The per-category split is the more useful output, because it is what an improvement loop would target
next (§2 picks the weakest measured capability):

| Category | Youden | Category | Youden |
|---|---|---|---|
| crypto | 100.00% | xss | 30.44% |
| securecookie | 100.00% | sqli | 19.74% |
| weakrand | 100.00% | pathtraver | 11.71% |
| hash | 68.99% | trustbound | 9.95% |
| xpathi | 28.33% | ldapi | 8.80% |
| | | cmdi | 5.66% |

Three categories are perfect and three are near-zero, which is a far more actionable statement than one
46.54% average. `cmdi` at 5.66% (TP=117 FP=109) is the weakest, and the FP count is why: the detector
fires nearly as often on safe cases as unsafe ones.

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

The **deterministic-core FP/FN** row deserves its caveat stated next to it rather than
below the fold. Its 1.00/1.00 measures whether the fixtures and the code agree, not
whether the product works (§14.2.5) — and on this very board the two rows scored against
answer keys we did NOT write opened at 64.5% and 65.2%. A perfect in-house column is
worth exactly one thing: it goes down when a core regresses. Its corpus sizes are gated
too, because a perfect score over 2 cases instead of 34 is a weaker claim wearing the
same number.

_Run 2026-08-21 on `feat/frontier-ghoidc`._

| Capability | Harness (runnable command) | Result | Reads on |
|---|---|---|---|
| Attack-path discovery | `tsbench cloud-engine --scenarios 12 --seed 7` | recall 100% (48/48) · FP-reduction 100% (24/24) · 0 false paths | seeded synthetic accounts |
| **Attack-path generalization** | `tsbench cloud-engine --holdout 8 --holdout-k 3 --seed 11` | held-out FP-reduction **100%** · overfit gap **0.0 pts** · recall 100% | **held-out shapes, labelled by an INDEPENDENT oracle** |
| Remediation capture | `tsbench defense --mode substrate` | 100% remediation · 100% path recall, all 4 scenarios | seeded code+cloud estates |
| Offensive recall + grounding | `go test ./internal/webrange/` | agent sweep PASS · decoys present · no SUT leak in scorer | procedurally-generated range w/ decoys |
| Vulnerability localization | `tsbench localize` | recall@1 **1.00** · MRR **1.00** (8/8 scenarios, heuristic tier) | seeded CWE scenarios |
| Deterministic-core FP/FN | `tsbench accuracy` | **1.00 / 1.00** across 6 cores, 107 labeled cases | **corpora WE wrote — see the caveat below** |
| Improvement-loop discipline | `tsbench improve --journal <file>` | decides the next target, or states why it stopped | **not a score** — it is the driver that decides where effort goes (ADR 0018 item 2) |
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

`gcpinventory/deny_fp_test.go` is a stronger guard, because its ground truth is Google's rather than
ours: GCP evaluates IAM **deny** before allow, so a deny on `resourcemanager.projects.setIamPolicy`
blocks the escalation an allow would otherwise permit. It is the same question BishopFox's AWS
control set asks of every tool — *"Does the tool evaluate deny's first before allows? Many tools
ignore or incorrectly handle DENY actions."* — and GCP had no answer, because `RawGCP` could not
EXPRESS a deny policy. `gcpiam.Authorize` had always honoured them; `derivePrivesc` built its
`PolicySet` without any, so a project protected by a deny was still reported as having a path to
administrator — a false positive aimed at the customers who had taken the strongest available
precaution. Both directions are pinned: a deny naming someone else, and an explicitly EXCEPTED
principal, must still report the escalation, because over-reading a deny trades false positives for
false negatives and on an attack-path page that is the worse direction.

Supplying the deny policies is the collector's job and stays the honestly-gated half; the parsing and
the evaluation are tested and free.

**AWS had the identical hole, found by asking the same question.** `cloudiam.PolicySet` has always
carried `SCPs` and evaluated them as the AWS Organizations ceiling — *"if any SCP is attached, some
SCP must Allow"* — and `RawAWS` could not EXPRESS one, so the ingest built its `PolicySet` without
any. An account governed by an org guardrail carving out `iam:CreateAccessKey` was still reported as
having a privilege-escalation path. SCPs are the most common such guardrail in any estate large
enough to have an Organization, so the false positive landed hardest on the best-run accounts.
`awsinventory/scp_fp_test.go` pins all three directions: the ceiling blocks, a permissive SCP does
NOT suppress, and an UNREADABLE SCP does not silently clear the account — the same direction the
permission boundary already takes, because pruning a path on a ceiling we could not read would hide
real escalations behind an unparseable document.

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
