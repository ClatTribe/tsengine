# The AI Security Engineer benchmark — better than XBOW by measuring the whole job

XBOW proves a vuln is **exploitable**. A scanner proves it **exists**. Neither tells the organisation what
it **means for them**, nor proves it can be **fixed**. This benchmark measures the two things a real
security engineer does that neither does — and it is the "better than XBOW" claim, made testable.

It is the defensive twin of `tsbench xbow` (the offensive flag-capture suite), and it is derived from the
**same XBOW challenge corpus** so the two are directly comparable: exploit it (`xbow`), then prove you can
fix it and explain what it means (`defense-xbow` + `impact`).

## Impact discovery — FINDING the vuln that creates real impact (the primary axis)

The AI Security Engineer's highest-value job is not fixing — it's **finding the vuln that creates real
organisational impact**: the one that reaches a crown jewel (customer/regulated data, admin/root, a
financial system), often via a **cross-surface chain** no single scanner sees, buried in a backlog of
scary-but-contained noise. `tsbench discover` (`internal/bench/impactdiscovery.go`) measures it: given a
noisy code+cloud estate, the engineer surfaces the impactful findings, scored by **recall** (never miss the
one that matters), **precision** (don't cry wolf), and **grounding** (§10), BY IMPACT CATEGORY.

**Live (model=claude-proxy)** on a 7-finding estate (4 real across 4 categories + 3 noise):

| Ranker | Recall | Precision | Notes |
|---|---|---|---|
| AI engineer (reads detail) | **100%** | **100%** | found the code→cloud chain, the public-PII bucket, the mis-tagged admin key, the internet-exposed billing DB; dismissed the isolated critical RCE, the unreachable CVE, the static-blog XSS → **PASS** |
| Severity-first | 50% (missed 2) | 50% (2 false alarms) | missed exactly `lateral_movement 0/1` + `privilege_escalation 0/1` (the judgment-requiring ones) and cried wolf on the critical-on-a-devbox |

The gap is the AI value-add: it finds the impact severity-based tools miss and ignores the noise they raise.

**Un-spoon-fed correlation test** (`estate-correlate`): the harder, honest version — the impact is NOT
stated in any finding. The estate gives RAW facts (IAM key→role, role→assumeRole, role→`GetObject` on a
bucket, bucket→`customer-pii` tag) and the engineer must CHAIN them to discover that a *medium* leaked key
reaches customer PII, while dismissing a *critical* isolated RCE and a *high* SSH that's corp-CIDR-only.

| Ranker | Recall | Precision |
|---|---|---|
| AI engineer (correlates the facts) | **100%** | **100%** → PASS |
| Severity-first | **0%** (missed the chain) | **0%** (flagged the critical RCE + high SSH noise) |

Severity-first is *exactly inverted* from the truth — the strongest evidence that finding real impact is
correlation/judgment, not a severity lookup.

**Decoy-chain test** (`estate-decoy`): the precision/grounding counterpart — a chain can *look* like it
reaches a crown jewel but be **broken**, and a good engineer must **dismiss** it (§10 — don't invent
impact). One real *medium* chain (leaked key → role → financial invoices) sits beside two decoys that a
naive "any hop touches a jewel" heuristic flags: a *high* leaked key whose `AssumeRole` to the PII lake is
killed by a **permission-boundary explicit Deny** (mirrors `cloudiam.Authorize`'s definitive-deny prune),
and a *critical* RCE that "fronts the customer DB" but is **VPN-only, no internet route** (mirrors
`cloudgraph.PruneUnreachable`). The break lives ONLY in the Context facts — the finding states just the
temptation — so dismissing a decoy requires real correlation, not reading a hint.

| Ranker | Recall | Precision |
|---|---|---|
| AI engineer (traces the deny + reachability) | **100%** | **100%** → PASS |
| Severity-first (flags critical RCE + high key) | **0%** (missed the real medium chain) | **0%** |
| "Any hop touches a crown jewel" heuristic | 100% | **33%** (flagged both broken decoys) → fails |

The heuristic's 33% precision is the point: reaching-a-jewel is *necessary but not sufficient* — the chain
must actually **resolve** (no explicit deny, network-reachable). That resolution is exactly the deterministic
substrate's job (`cloudiam`/`cloudgraph`), and the engineer's job is to *reason over its verdicts* — not to
re-flag a jewel the facts prove is unreachable.

**Correlation across all four impact categories** (each an un-spoon-fed scenario — the finding states only
the neutral surface, the impact is derived from the Context facts; each carries a decoy a naive ranker
flags). All PASS live via the proxy (recall 100% / precision 100%):

| Category | Scenario | Real chain to discover | Decoy to dismiss |
|---|---|---|---|
| `lateral_movement` | `estate-correlate` | medium leaked key → role → assumeRole → customer-PII bucket | critical isolated RCE, corp-CIDR-only SSH |
| `lateral_movement` (precision) | `estate-decoy` | medium leaked key → financial invoices | high key (AssumeRole DENIED), critical RCE (VPN-only) |
| `privilege_escalation` | `estate-privesc` | medium leaked key → `PassRole`+Lambda → account admin | medium key reaching only a public bucket |
| `external_exposure` | `estate-external` | high DB with `0.0.0.0/0` ingress → customer orders + payment tokens | high internet-SSH bastion with no key + no data behind it |
| `data_exposure` | `estate-crosssurface` | public S3 bucket of customer records | — (covered in the mixed estate) |

The through-line: in every category the impactful finding is a *below-the-scary-severity* item whose impact
only appears after correlating the facts, and each category's decoy is a *high/critical* item a severity or
keyword heuristic wrongly promotes. That inversion — real impact low-tagged, noise high-tagged — is the
measured AI value-add, held consistent across the whole impact taxonomy.

## The two halves of the job → three measured axes

| Axis | Question | How it's scored | CLI |
|---|---|---|---|
| **Remediation-capture** | did the estate get *verifiably* safer? | patch the real vuln → re-fire the recorded exploit (must fail) + regression (app must still work) — execution-verified | `tsbench defense-xbow` |
| **Impact-accuracy** | did the engineer prioritise by *real org impact*, not raw severity? | grounded rubric vs the substrate's facts (RiskWeight + crown-jewel reach) | `tsbench impact` |
| **Value-add over the substrate** | did the engineer catch impact the tags *mis-classify*? | the gap between the substrate-only ranking and the engineer's, on mis-tagged findings | `tsbench impact --naive-baseline` vs live |

## The deterministic / AI line (why this is honest, not hype)

The benchmark keeps the product's core boundary crisp (`CLAUDE.md` §2.7 / §13): **the deterministic
substrate computes the facts; the AI engineer is scored on judgment over them, and must invent nothing
(§10).**

- Deterministic (and NOT what we benchmark the LLM on): does the vuln exist, is it on a reachable path
  (`cloudgraph`), does it bridge surfaces (`crossdetect`), what's the tag-based RiskWeight, is the finding
  gone after the fix (`retest.Verify`).
- AI engineer (what we DO benchmark): produce a fix that survives re-attack without breaking the app;
  prioritise by real impact; **catch when the tags are wrong** — the one place a lookup cannot help.

## Results (live, `model=claude-proxy` — Claude via the no-key dev proxy; a customer key replaces it in prod)

**Remediation** — the engineer proposed a root-cause fix, re-attack confirmed it dead, app still served:

| class | fix | verdict |
|---|---|---|
| lfi | confine reads to a public dir | ✅ remediated |
| sqli | parameterise the query | ✅ remediated |
| cmdi | drop the shell, argument vector | ✅ remediated |
| ssti | never eval user input as a template | ✅ remediated |
| idor | enforce object-level authorization | ✅ remediated |
| xxe | disable external entities + DTD | ✅ remediated |

**Impact** — the engineer led with a *medium* leaked key that reaches customer PII over a *critical* on a
throwaway box: `priority 1/1 lead, PASS`. A severity-first answer scores `0/1 lead` (fails).

**Value-add** — on a finding tagged *medium/tier-3* whose detail is an *AdministratorAccess key*: the
substrate-only ranking scored `0/1 lead` (buried it); the engineer read the detail and scored `1/1 lead,
PASS`. **The 0→100 gap is the measured AI value-add.**

Evidence ledgers: `bench/defense-xbow-selftest-ledger.jsonl`, `bench/impact-live-ledger.jsonl`.

## Correctness of the benchmark itself (positive + negative controls)

A grader is only trustworthy if it correctly *fails* bad inputs. Proven in CI:
- `TestDefenseXBOWSelftest_Calibration` (`-tags=integration`): a correct patch → `remediated`, a no-op →
  `ineffective`, an **app-breaking patch → `broke_app`** (the anti-sabotage guard — you cannot "fix" by
  killing the app).
- `TestScoreImpact_PenalisesSeverityFirst` / `_MisTagged_AIValueAdd`: severity-first and substrate-only
  rankings must fail; a real-impact / detail-reading assessment must pass.
- `TestScorer_NoSUTIdentifiers`: the scoring code contains no challenge-specific identifiers (anti-overfit,
  §14.2).

## How to run

```sh
# The deterministic gate (unit scorers + calibration on a real container + impact discrimination):
make bench-engineer

# Remediation, per category (real XBOW suite; needs a live LLM for the attack + patch steps):
LLM_BASE_URL=… LLM_MODEL=… LLM_API_KEY=… tsbench defense-xbow --category sqli
# Deterministic pipeline validation (no LLM):
tsbench defense-xbow --only <id> --patch-file <fix>
# Impact:
LLM_BASE_URL=… tsbench impact --scenario fixtures/impact/estate-mistagged.json
tsbench impact --scenario … --naive-baseline    # the substrate-only number to beat
```

## Honest gates (not fabricated)

- **The full 71-challenge remediation sweep needs an autonomous LLM key.** Every real challenge needs its
  recorded exploit (the offensive capture step); the self-test fixtures above are a per-class **capability
  floor** on clean vulns, not the hardened-challenge number. The live results here used Claude via a
  file-relay proxy (the no-key workaround) on the self-test fixtures; the real-suite number is a key away,
  and is *not* printed until measured.
- **Impact ground truth for mis-tagged findings is authored** (it must be — measuring judgment needs a
  ground-truth judgment), but every override is justified by the finding *detail* shown to the engineer, so
  it's a fair test, and the scoring code stays SUT-agnostic.

Design: [`docs/adr/0014-xbow-defense-benchmark.md`](../docs/adr/0014-xbow-defense-benchmark.md),
[`docs/adr/0013-code-depth-specialist.md`](../docs/adr/0013-code-depth-specialist.md),
[`docs/xbow-defense-selftest-scorecard.md`](../docs/xbow-defense-selftest-scorecard.md).
