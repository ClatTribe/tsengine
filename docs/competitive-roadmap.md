# Competitive roadmap — close the gap, one category at a time

**Goal:** a *fractionally autonomous security team for SMB, human-in-the-loop*. Become
**best-in-class in one category first (agentic capability), then reach parity on all three**
(agentic, UX, features). Every phase is gated by a **benchmark or a named competitor** — we
do not call a phase "done" until a number or a head-to-head proves it.

The competitive read this plan answers is in the session analysis (mid-2026): we span three
markets no single rival spans — agentic offensive (XBOW, NodeZero, strix), AI SOC (Dropzone,
Prophet, 7AI), and SMB compliance/vCISO (Vanta, Drata, Sprinto, Delve, Huntress). We are
*architecturally* strong and *UX*-strong, but our **agentic autonomy is unproven by benchmark**
and several SMB table-stakes features are missing.

---

## Track 1 — Agentic capability → **best-in-class** (lead category)

Verification mechanism: the `internal/bench` harness. L1 detection is already benched
(WAVSEP vs Acunetix 87%/Burp 78%, OWASP-SAST vs Veracode 51%, per-tool parity). **The L2
agent — the actual "agentic" capability — has no benchmark. That is the gap.**

| Phase | What | Verification gate |
|---|---|---|
| **A1** | **L2 agent benchmark** (`bench/agent`): detection_rate, **verified_rate** (PoC/evidence-grounded, the XBOW "no-false-positive" bar), completion_rate, FP control. `tsbench agent`. | The benchmark exists + is CI-tested; agentic capability becomes measurable for the first time |
| **A2** | **Unified scoreboard** (`tsbench scoreboard`): aggregate every asset bench + the agent bench into one competitor-delta scorecard, committed as the living "where we stand" artifact. | One command emits our number vs every competitor (Acunetix/Burp/Veracode/XBOW) |
| **A3** | **Close L1 recall gaps** the scoreboard exposes (known: WAVSEP pathtraver + open-redirect, ~77% of corpus). | WAVSEP per-class Youden moves toward Burp 78% / Acunetix 87% |
| **A4** | **L2.5 exploitation-verification upgrade**: pattern_match → verified via benign-PoC replay, so findings are evidence-grounded not guessed. | A1 `verified_rate` rises; matches the "exploitation-verified" competitor bar |
| **A5** | **Live HITL-gated autonomous action**: close the propose-only gap — one real remediation write-path executes *through the gate*. | Integration test: an approved action mutates + is verified, ledger-signed |

## Track 2 — UX → parity-plus (already near best-in-class)

Verification: feature-for-feature vs Vanta / Drata / Sprinto / Delve / Huntress.

| Phase | What | Verification gate |
|---|---|---|
| **U1** | **Security-questionnaire automation + Trust Center** (the #1 recurring SMB GRC value). | We auto-answer a standard questionnaire (SIG-lite/CAIQ) from real control state |
| **U2** | **Human/expert safety-net surface**: an async "request expert review" path in the inbox — the proven SMB trust model is *AI + a human*. | A gated review request routes + resolves through the ledger |
| **U3** | **Live cloud (AWS/GCP) connector onboarding** — engine already has `cloud_account`+prowler; platform onboarding doesn't wire it. | Connect a cloud account → posture findings flow through the same loop |

## Track 3 — Features → at par

Verification: the SMB-platform feature matrix (Coro/Huntress/Cynet/Guardz) + GRC matrix.

| Phase | What | Verification gate |
|---|---|---|
| **F1** | **Production multi-tenant infra**: SQLite/Postgres `Store` + cloud-KMS `secret.Vault` behind today's interfaces. | Same test suite passes on the durable store; survives restart |
| **F2** | **Integration breadth**: ServiceNow/PagerDuty ops surfaces; more IdP/cloud connectors. | N integrations live, each with a contract test |
| **F3** | **Public self-serve signup + billing** (vs operator-token provisioning). | A tenant self-provisions end to end |

---

## Sequencing rule

Track 1 to best-in-class **first** (A1→A5), because autonomy is the core of the thesis and
the one category with crisp benchmark verification. Tracks 2–3 follow to parity. Each phase
ships as one CI-green PR; the scoreboard (A2) is the running proof we keep at/above par.
