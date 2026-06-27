# ADR 0012 — AI-application security (LLM-app testing) as a wrapped-OSS asset

## Status

Proposed (backlog). This ADR scopes the capability and fixes the approach so a future phase can build it
without re-litigating §13. Nothing here is implemented yet — and this document exists precisely so we do
NOT silently ship an in-house AI-vuln detector.

## Context

The State-of-AI-in-Pentesting 2026 survey's strongest signal is that AI is *already* the source of security
problems: **76% of organizations have had to intervene to stop, restrict, or roll back AI-driven behavior**
in the past year (98% for teams shipping multiple times a day), and 71% say AI made incidents harder to
detect/investigate/fix. The risk inflow is AI-built and AI-using software.

tsengine today covers the **governance** and **inventory** sides of AI:

- AI-governance compliance frameworks — ISO 42001, NIST AI RMF 1.0, EU AI Act (mapped to the
  security-relevant AI controls; CLAUDE.md §8).
- The **AI-BOM** (`GET /v1/ai-bom`, WRD-1) — what the autonomous agent itself can touch.

What it does **not** have is **detection of vulnerabilities in the customer's OWN AI features** — the
application layer the OWASP LLM Top 10 covers: prompt injection, insecure output handling, sensitive-info
disclosure in responses, jailbreak/guardrail bypass, excessive-agency / insecure tool-or-plugin use, model
DoS. This is a distinct asset class competitors are beginning to carve out, and it's genuine whitespace for
us. The question this ADR answers is **how** we close it without violating the wrap-OSS rule (§13).

## Decision

Add AI-application security as a **new wrapped-OSS capability**, NOT an in-house detector — the same
discipline as every other asset (§13). Two design choices:

1. **Asset type vs capability.** Introduce a new asset type **`ai_application`** (the count-pinned
   `pkg/types.AllAssetTypes()` would go 8 → 9, with its test updated), whose target is an LLM endpoint /
   chat API the customer authorizes. It is single-stage like `repository` (the endpoint *is* the surface),
   and active probing is gated by the **same RoE Guard + explicit-consent + ownership-verification** path
   active exploitation already uses (ADR 0006 + `internal/ownership`) — an AI-app test sends adversarial
   prompts, so it is active-by-nature and must never run without consent.

2. **Wrap the leading OSS LLM-security tools** (anchor + registry tiers, §4):
   - **Anchor:** **garak** (NVIDIA's LLM vulnerability scanner — prompt-injection, jailbreak, toxicity,
     data-leak probes; the nuclei-equivalent for LLMs) — broad, signature-style coverage, low-config.
   - **Registry / depth:** **promptfoo** (red-team / eval harness for targeted attack suites) and
     **PyRIT** (Microsoft's risk-identification toolkit for multi-turn attacks) — surfaced on-demand via
     `dispatch_l2_probe` / tool-replay, like every other registry-tier tool.
   - Where no OSS covers a class (e.g. app-specific business-logic prompt leaks), it is a **documented
     backlog item**, never a silent in-house build (§13, same rule as API BOLA/BFLA → `internal/apiauthz`).

Findings map to the AI-governance controls already in the crosswalk (ISO 42001, NIST AI RMF, EU AI Act) at
emission, exactly like every other finding (§8) — so an AI-app vuln flows through the same
issues/incidents/grc/hitl machinery with zero new plumbing.

## Honesty / grounding (§10)

LLM-app testing is where false positives are most dangerous (a hallucinated "jailbreak" erodes trust faster
than a missed one — the report's KF#6). So:

- A garak/promptfoo probe result is **evidence** (the adversarial prompt + the model's response), and a
  finding is recorded only when the tool's machine-checkable predicate fires — same as any wrapped tool. No
  LLM judges another LLM into a finding without a captured, reproducible probe/response pair.
- Active-by-nature → the RoE Guard's destructive ban + budget + consent gate every probe, and the target
  must be ownership-verified (`internal/ownership`) before any prompt is sent.
- A model that resists every probe yields **zero** findings (a clean result, surfaced honestly by the
  coverage layer — `internal/coverage` would gain the `ai_application` toolset row).

## Phases

- **Phase 0** — `internal/tool/garak` wrapper (sandbox tool) + the `ai_application` asset handler
  (single-stage anchor dispatch) + the count-invariant test bump. The OSS image add (garak + its model
  client) is the sandbox cost; the live LLM-endpoint target + consent is the honest gate.
- **Phase 1** — promptfoo + PyRIT registry-tier wrappers (depth on-demand) + the AI-governance control
  mappings for the LLM-Top-10 CWEs.
- **Phase 2** — `/ai-application-security` marketing capability page + the `ai_application` surface in the
  assets/coverage UX.

Until Phase 0 ships, the honest line is: tsengine covers AI **governance + inventory** today; AI **application
vulnerability testing** is the documented next asset, wrapped-OSS by design.
