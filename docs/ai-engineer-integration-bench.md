# Testing the AI Security Engineer end-to-end — credential-free

The AI Security Engineer ingests from many integrations and reasons over them with two LLM
agents. This is how to exercise the **whole thing without any customer credential** — and the
benchmark that scores it.

## The idea

Every integration has two halves: a **live fetcher** that needs the customer's credential, and a
**snapshot-driven detector** that takes the same data as a struct/JSON and runs the identical
logic. The benchmark drives the detector half with a **synthetic estate** — planted must-detect
issues + hardened decoys — so the full detection + agent surface is testable offline. The only
thing the agents need is a *brain*, and that comes from the **dev proxy** (frontier Claude) or a
local Ollama — still no cloud key.

## Run it

```bash
# deterministic detectors — every integration, no creds, no LLM, no Docker:
go run ./cmd/tsbench integration                 # prints the scoreboard; exit != 0 unless clean-sweep
go run ./cmd/tsbench integration --out bench/ai-engineer-integration-scoreboard.md
go run ./cmd/tsbench integration --json          # machine-readable
```

Covers 7 integrations through their real detectors: identity/ITDR (`identitythreat.Detect`),
vendor risk/TPRM (`tprm.Assess`), device posture/MDM (`deviceposture.Assess`), OSINT external
exposure (`osint.Assess`), SaaS posture/SSPM·GitHub (`sspm.AssessGitHubOrg`), cloud drift
(`clouddrift.Diff`), cloud attack-path (`cloudengine.Assess`). Each scored for **detection recall**
(planted issues surfaced) + **FP-control** (a flagged decoy is a false positive, §10).

## Add the LLM agent layer (frontier brain via the dev proxy)

The cloud + code engineers are open-ended agents — they need a model. `cloudengine.LLMFromEnv`
resolves the dev proxy (frontier Claude) or a local Ollama, so this is still credential-free:

```bash
# 1. start the file-relay proxy (a frontier Claude session answers each turn):
python3 my_llm_proxy.py &                        # serves 127.0.0.1:8898

# 2. run one agent at a time (tractable against the manual proxy):
LLM_BASE_URL=http://127.0.0.1:8898/v1 LLM_MODEL=claude-proxy LLM_API_KEY=proxy \
  go run ./cmd/tsbench integration --agent --agent-only code   # or: --agent-only cloud
```

Or point `LLM_BASE_URL` at a local Ollama (`http://localhost:11434/v1`, `LLM_MODEL=qwen2.5`) for a
fully autonomous run. Without a model configured, `--agent` **skips honestly** — the deterministic
bench stays green in CI.

The agent layer scores **recall** (real issues confirmed) + **grounding** (an invented path or a
false-confirmed safe finding is a §10 violation — must be 0). The code test plants one real
string-concat SQLi + one safe parameterized decoy: a frontier model confirms the first and refuses
the second; a hallucinating one confirms both and fails.

## Recorded result

See [bench/ai-engineer-integration-scoreboard.md](../bench/ai-engineer-integration-scoreboard.md):
7/7 integrations clean-sweep (13/13 planted, 0 FP), and a recorded frontier-Claude run of both
agents at 100% recall with 0 invented issues.

## Live end-to-end (through the running platform)

The benchmark exercises the detectors directly. To watch the same estate flow through the real HTTP
API → storage → issues/compliance/HITL, POST the snapshots to the credential-free ingest endpoints
(`/v1/cloud/investigate`, `/v1/identity/events`, `/v1/osint/ingest`, `/v1/tprm/ingest`,
`/v1/devices/ingest`, `/v1/saas/{provider}/snapshot`, `/v1/cloud/drift`, …) against a `make dev`
platform — same data, exercised through the product surface. See
[docs/per-asset-gates.md](per-asset-gates.md) for what runs credential-free vs. gated per asset.
