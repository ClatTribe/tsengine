# The harness is the product

*How the tsengine AI Security Engineer finds vulnerabilities with any model — and why the model is the part we replace, not the part we trust.*

---

Frontier models now converge on capability. UK AISI benchmarked GPT-5.5 and Mythos in the same cyber-capability tier (71.4% vs 68.6% on the hardest category — one wins depending on the task). UCSB researchers ran one model under different harnesses and measured a **4× spread** — larger than the gap between any two frontier models. Niels Provos found an 18-year-old CVE with an open-weight model in a good harness. Mozilla's security team slots in each new model without rearchitecting.

The conclusion across the industry is the same one we built on from day one:

> **Model choice is a rounding error. The orchestration around the model is the product.**

We agree — and we think it doesn't go far enough. Because there is a second variable hiding inside "harness," and it matters more than how many agents you run:

> **Who is allowed to declare something true.**

Most harnesses answer "another LLM." Ours answers: **a deterministic predicate that ran and returned evidence.** That single decision changes the economics, the false-positive rate, and what "verified" is allowed to mean.

---

## The architecture

tsengine is a Go-native engine with a two-layer model. L1 is complete OSS vulnerability discovery — every leading community scanner wrapped, fired deterministically. L2 is the AI Security Engineer: a Lead agent orchestrating domain specialists over a catalog capped at 12 tools, because past ~12, LLM tool-use accuracy degrades steeply.

What follows is the harness, stage by stage.

### Stage 0 — Recon and fan-out: the LLM never drives it

A model told "enumerate the target, then scan it" will sometimes improvise. We removed the possibility. Surface discovery (crawls, port discovery, subdomain enumeration, API-spec ingestion) and tool fan-out run as a **hard deterministic stage** before any model sees anything. Identical target, identical plan. The failure mode where an agent ignores its recon directive is structurally impossible here — not prompted against, impossible.

Cost of this entire stage: **zero tokens.**

### Stage 1 — Anchors: always-fire coverage

Every asset type has a curated anchor set that fires on every scan — no model choosing, no model skipping. Recall equals the standalone OSS tools; if we drop a finding the underlying tool would have found, that's a regression, full stop. The model is not consulted about whether to look.

### Stage 2 — Escalation: depth where signals warrant, still zero-token

Expensive depth tools fire only on grounded signals: an injection finding summons a taint-analysis pass; a WordPress surface summons the CMS specialist; observed software matching a KEV-listed CVE summons a targeted probe. Signal-gated, budget-capped, deterministic — the same inputs always produce the same ordered plan. Threat-intel-led probe selection ranks by real exploitation evidence (CISA KEV, EPSS, SSVC automatability, public-exploit and weaponization availability) drawn from seven OSINT feeds refreshed out-of-band and pinned per scan for reproducible evidence.

This is the quiet answer to "run many cheap agents for breadth": **our breadth is code, not agents.** It doesn't just cost less than N mini-agents — it costs nothing, and it can't hallucinate a target.

### Stage 3 — The agent loop: propose, never dispose

Only now does an LLM act, over a ≤12-tool catalog tied to an observe-orient-decide-act loop with hard budgets (a default scan caps at ~$1, 60 turns, 20 wall-clock minutes — a legacy of an early unbounded run that burned real money for zero findings).

The agent's job is the open-ended part: what looks interesting here, how do these findings chain, what should we try next. Its spec generator proposes exploitation demonstrations — including, on failure, a refine loop where the failed predicates and results feed back so the next attempt proposes something *different*, plus engagement memory shared across findings of a target (a uniform WAF wall learned on one route informs the others).

Then the load-bearing rule:

> **The model proposes. The framework disposes.**

No demonstration upgrades a finding because the model says so — only when a machine-checkable predicate holds over captured responses: a three-leg ownership differential for broken object-level authorization (victim reads it, attacker reads it, stranger cannot), a before/after privilege transition for escalation proofs, benign canaries for injection classes, re-fired scanner runs for verification. An independent *LLM* validator can be argued with by a persuasive hunter. A predicate cannot. This is also, deliberately, the narrowness in our design: predicates exist for provable classes, and everything else stays honestly unproven rather than softly "confirmed."

### Stage 4 — Panels, with one exception

For the one pipeline where candidates are model-proposed rather than tool-grounded (proactive code sweeps), an odd panel of independently-configured jurors votes; majority wins; ties and dead panels **fail open** — a deadlock is not evidence of absence. Every dropped candidate rides back with the panel's reasoning and vote tally, recoverable, never swallowed. Everywhere else an LLM verdict annotates and never suppresses: a panel of language models does not get to delete a scanner's finding.

### Stage 5 — Fleet scale-out

Authorized surfaces decompose into intelligence-led chunk plans ordered by enrichment signal, split into state-coupled waves (auth-dependent work after session establishment), executed by bounded workers sharing one request governor — a single atomic envelope and a latching circuit breaker, so no wave can starve the budget or hammer an unhealthy target. Results land in a per-engagement coverage ledger keyed by canonical route × vulnerability class, where conflicting evidence renders **Contested, never averaged** — Vulnerable×Clean does not become 50%, and a route with no verdict reads "no established verdict," never clean.

### Stage 6 — Deduplication and honesty about gaps

Cross-tool merge collapses duplicate detections; unified issues consolidate multi-signal findings with worst-severity and corroboration counts. And what a scan could *not* check ships as a first-class disclosure — declared coverage gaps are excluded from coverage statistics, because a skipped check rendered as a clean one is the most dangerous sentence in security reporting.

---

## The brain is a plug-in

Because the model is a component, swapping it is configuration, not surgery:

- **Bring your own key.** Tenants seal their own model credentials; agents run on them. Free-tier tenants run zero model calls — the deterministic spine still scans.
- **Per-role models.** Reasoning-over-data and code/exploitation reasoning accept different models, because trusting a small model's triage summary is a different risk than trusting its exploit patch.
- **Local models.** An on-prem Ollama endpoint drives the offensive loop where data can't leave the building.
- **Graded, not assumed.** Each tenant's own eval suite — built from *their* reinstatements, ignores, and confirmed fixes — scores whichever brain they picked on *their* estate. Model swap is measurable per customer, not per vendor marketing page.

Vendors locked to one model must make that model perfect. We price the model as what it is: an input with a cost curve.

---

## What this buys, in numbers

We publish the numbers that can go down alongside the ones that go up:

| Capability | Score | Key |
|---|---|---|
| Identity/SaaS baseline detection (CISA SCuBA) | **0.993** total · 0.990 mandatory-SHALL | External — CISA's own baselines, every mapping execution-proven |
| SAST (OWASP Benchmark, all 2,740 Java cases) | **46.5% Youden** — third on the published cohort, between Checkmarx 47% and Fortify 35% | External |
| Cloud IAM privesc (BishopFox IAM-Vulnerable) | **64.5%** first external run — after scoring 100% on every internal bench | External, includes the FP control half |
| GCP privesc (Rhino catalogue) | **65.2%** | External, recall-only |
| Internal fixture agreement | 107/107 | Internal — measures fixtures-vs-code agreement, **not** efficacy; stated as such wherever it renders |

That last pair is the point. Two independent answer keys said ~two-thirds on a capability where every self-written bench said perfect. We kept both numbers visible, because the honest one is the one that moves.

And the false-positive bar: exploitation-verified or annotated — a `pattern_match` never renders as verified, a mitigation never presents as a fix, and a panel that couldn't decide keeps the finding.

---

## Where this goes next

Designed, evaluated, not yet shipped — listed because a roadmap that only contains victories isn't a roadmap:

- **Tiered models**: a cheap proposer tier widening what's tried, deterministic disposal unchanged (zero added FP surface).
- **Redundant passes as an option**: N diverse attempts per surface with sublinear cost via coverage-ledger settling.
- **Cross-model panels**: jurors drawn from distinct configured models where more than one exists, because persona diversity is weaker independence than model diversity.
- **Coverage-per-dollar arms** in our benchmark suite, so multi-agent economics claims are tested on this harness rather than quoted from someone else's.

---

## The short version

Mythos-class models are remarkable, and irrelevant to architecture decisions. Attackers will run whatever is cheap, repeatable, and scalable — so defenders should build for exactly that world: a harness where breadth is deterministic, depth is signal-gated, verification is mathematical, the model is a swappable part, and every claim traces to evidence a tool produced.

Build the harness so the truth-telling doesn't depend on the brain plugged into it. Then model progress becomes something you absorb, and model hype becomes something you can measure.
