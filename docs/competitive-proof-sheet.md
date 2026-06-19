# Competitive proof sheet — tsengine / Sentinel

**One line:** a *fractional autonomous security team for the SMB* — it wraps the same
best-in-class OSS the category leaders are built on (so detection is at-par **by
construction**), then adds the operating layer each of them leaves to a human: grounded
triage → tier-gated remediation → signed, replayable evidence.

**Positioning:** there is **no single head-to-head competitor.** "A security team" spans
five lanes that today are five separate tools — each of which *assumes the SMB already
employs the operator who runs it.* We are that operator.

---

## The five lanes — competitor · OSS we wrap · parity proof · agentic edge

| Lane & leaders | Top OSS we wrap (the detection) | How we reach parity (the proof) | What the agentic layer adds |
|---|---|---|---|
| **AppSec** — Snyk, Semgrep, GitHub AS | `semgrep` (SAST), `codeql` (taint depth), `gitleaks`+`trufflehog` (secrets), `osv-scanner`+`trivy`+`grype` (SCA — same OSV/CVE DBs Snyk queries), `mobsfscan` | Same engines → recall parity. **SAST 47.86% Youden ≈ Checkmarx (47)** on OWASP Benchmark v1.2 (live, host semgrep). | L1.5 corroboration (two secret scanners agree → confidence), FP-filter, and `remediate` opens a **fix-PR** (tier-1 auto). They leave triage + fix to the engineer. |
| **Autonomous offensive** — XBOW, Horizon3 NodeZero, strix | `nuclei`, `sqlmap`, `dalfox`, recon (`katana`/`httpx`/`naabu`/`nmap`), `ffuf`, `hydra`, `kiterunner`, `inql` | Their bar = "exploitation-verified, no-FP." Our **L2 agent + verifyGate** + evidence-grounding *is* that bar. **Web-agent range 100% recall / 0 decoys; LLM red-team 100% (61/61) / 0 false breaches** (7 seeds each). WAVSEP scorer-ready vs Acunetix/Netsparker 87, Burp 78, ZAP 56. | Chains, plain-English narrative, customer-priority — translation for non-security teams that the offensive tools never produce. |
| **Compliance automation** — Vanta, Drata, Sprinto, Scrut | `prowler`+`scout-suite` (CIS cloud), `checkov` (IaC), `trivy`/`grype` (vuln evidence) feeding control state | Same CSPM/IaC OSS → evidence parity. The *mapping* is in-house `grc` (no "OSS compliance engine" exists). CIS-baseline scorer ready vs Prowler/Scout. | A control is a "gap" **only because a real finding cites it** (grounded). Then propose→gate→apply→**signed, replayable evidence pack** — auditor/insurer-grade, which Vanta/Drata can't produce. They flag a gap and hand a human a ticket. |
| **Identity posture** — Nudge, Push, Cerby, Wing | Mostly **provider APIs**, not OSS scanners (Google/M365/Okta directory); the OSS piece is `checkdmarc` (DMARC/SPF/DKIM). `operate` is the in-house engine | Detection parity via the same provider signals — MFA gaps, risky OAuth grants, stale accounts — each finding **citing the offending user/domain/app**. | They surface; we surface **and remediate** — the live gated **Okta suspend** (HITL-approved, signed) — and fold identity findings into the same compliance loop. |
| **vCISO / fractional** — Cynomi, MSSPs | The whole arsenal feeds the posture a vCISO assesses: EASM (`subfinder`/`amass`/`dnstwist`/`naabu`/`nmap`/`httpx`), cloud (`prowler`/`cloudfox`), identity (`operate`) | Cynomi is a worksheet for a *human* consultant; our assessment is **continuous and grounded in real scan evidence**, not a questionnaire. | Tier-gated autonomy + the **global kill-switch** mean the fractional team *operates*, not just advises. |

**Container/supply-chain** (Trivy/Snyk/Anchore self-published, no neutral board): `trivy`+`grype` (dual CVE DB), `dockle`/`hadolint` (CIS misconfig), `syft` (SBOM), `cosign` (signature verify) — **container CVE recall 1.0 / 0 FP live** (nginx:1.14 must-find), **0 findings on a clean image** (specificity).

---

## Why parity is a guarantee, not a hope — three architecture invariants

1. **Per-tool recall parity (L1).** We run the competitor's own OSS engine; the architecture *forbids* dropping what the standalone tool found ("L1 PRs that regress raw recall are rejected", CLAUDE.md §2.4). The `bench/*parity` gates assert recall == 1.0 vs the standalone tool. → **detection is at-par by construction** against any OSS-backed rival, plus corroborating tools they don't bundle.
2. **Evidence grounding = the no-FP bar.** No recorded issue exists without deterministic tool backing (anti-hallucination guard, §10). That's exactly the "verified, zero-FP" discipline XBOW/NodeZero sell *and* what makes compliance evidence defensible. Measured: 0 FP across the agent + LLM ranges and the clean-container specificity test.
3. **The agentic operating model is the moat.** Every rival assumes the customer employs the operator. Our loop — `detect → ground → propose → tier-gate (HITL) → apply → sign` — *is* the operator, with the **kill-switch + signed replayable ledger** (agentic-SMB spec OM-3/TS-3/TS-5) as the trust substrate that makes touching identity/cloud/code deployable for a wary SMB.

---

## Benchmark scoreboard (our score vs the published competitor bar)

| Asset / capability | Our result | Competitor baseline | Status |
|---|---|---|---|
| Repository · SAST (OWASP Benchmark v1.2) | **47.86% Youden** | Veracode 51 · **Checkmarx 47** · Fortify 35 · SonarQube 6 | ✅ ≈ Checkmarx (live, host semgrep) |
| Container · CVE (must-find) | **recall 1.0 / 0 FP** | Trivy/Snyk/Anchore (self-published) | ✅ live (host trivy) |
| L2 web-agent range | **100% recall / 0 decoys / 0 invented** | XBOW / NodeZero "verified, no-FP" | ✅ 7 seeds |
| L2 LLM red-team | **100% recall (61/61) / 0 false breaches** | — (internal) | ✅ 7 seeds |
| Web · DAST (WAVSEP) | scorer-ready (sandbox-gated) | Acunetix 87 · Netsparker 87 · Burp 78 · ZAP 56 | ⚠ runs in CI, not on a laptop |
| Cloud · CIS, API, IP | scorer-ready (sandbox-gated) | Prowler/Scout/Tenable (self-published) | ⚠ runs in CI |

---

## Honest caveats (so the claim survives scrutiny)

- **Parity is strongest where the lane is OSS-scanner-backed** (AppSec, offensive, cloud/compliance evidence). For **identity posture** it's provider-API-driven, so parity rests on covering the same provider signals — which we do — not on a shared scanner.
- **DAST/WAVSEP, cloud, api, ip benchmarks need the sandbox image**, which doesn't build in an egress-restricted environment; those parity numbers come from the build pipeline, not a laptop.
- **Remediation breadth is partial.** Live gated writes exist for **repo PRs** and **Okta suspend**; cloud / GWorkspace / M365 writes are honest stubs pending admin-write credentials (they surface a clear error, never a false "done").

> Sources: OSS arsenal — `internal/tool/*` + `docker/sandbox/Dockerfile`; benchmark numbers + competitor baselines — [benchmark.md](../benchmark.md); architecture invariants — [CLAUDE.md](../CLAUDE.md) §2/§10/§13/§18; product design — [docs/personas-and-workflows.md](personas-and-workflows.md).
