# Testing the L2 agents — locally, like Claude Code

This is the runbook for exercising tsengine's L2 (LLM) agents — including with a **local Ollama thinking
model**, for free, no cloud key. It also documents how each product's agent is wired today.

## 1. The two LLM seams (why the agent is provider-agnostic)

Every L2 agent talks to the model through one of two narrow interfaces. Keeping the loop behind an
interface is exactly what lets it be unit-tested with a scripted mock (no key) and re-pointed at any
provider — cloud or local — with **no code change**.

| Seam | Shape | Used by | Implementations |
|---|---|---|---|
| `l2.Client` | rich, tool-calling (`Generate(system, history, tools) → text + ToolCalls`) | the **L2 Lead/translator** (`internal/l2`, the ≤12-tool OODA loop, §2.6) | `AnthropicClient`, **`OpenAICompatClient`** (Ollama/vLLM/OpenRouter), `MockClient` |
| `cloudengine.LLM` | minimal text-in/text-out (`Generate(prompt) → text`) | the **product investigate agents** — `cloudagent`, `webagent`, the `cloud-assess` translator | `Gemini`, **`OpenAICompat`** (Ollama/…), scripted mock |

Both seams now have an OpenAI-`/chat/completions` implementation, which is the protocol **Ollama, vLLM,
LM Studio, OpenRouter, and OpenAI** all speak. So "test it locally" is a config flip.

## 2. Three test layers (the test pyramid)

| Layer | What it proves | Needs | How |
|---|---|---|---|
| **Unit** (mock) | the loop, tool dispatch, budget, compaction, verification gate are correct — deterministically | nothing (no key) | `go test ./internal/l2/... ./internal/webagent/... ./internal/cloudagent/...` — the `MockClient`/scripted mock plays canned responses |
| **Eval — LOCAL** | the agent reasons + drives tools end-to-end on a real model, no cost | Ollama + a tool-capable model | point `LLM_BASE_URL` at Ollama (§3), run the agent, score with the bench |
| **Eval — CLOUD** | the headline `verified_rate` (PoC-grounded, the XBOW no-FP bar) at production quality | a cloud key + a live target | `LLM_API_KEY`/`ANTHROPIC_API_KEY`, then the same bench against WebGoat/Juice-Shop |

The **scorer is identical** across eval layers (`internal/bench` → `AgentScore`: detection_rate,
verified_rate, completion_rate, false_positives). Local Ollama lets you iterate on prompts/tools/flow on
the cheap; the cloud run produces the number you publish.

## 3. Local runbook (Ollama)

```bash
# 1. install + pull a TOOL-CAPABLE model (the agent loop needs function-calling)
ollama pull qwen2.5            # or qwen3, llama3.1, llama3.3, mistral-nemo, firefunction-v2
ollama serve                  # exposes http://localhost:11434/v1 (OpenAI-compatible)

# 2. point the agents at it — no API key, free
export LLM_BASE_URL=http://localhost:11434/v1
export LLM_MODEL=qwen2.5

# 3a. run a product agent (cloud security engineer) against a snapshot
tsengine cloud-investigate --snapshot fixtures/cloud/account.json --ledger /tmp/ledger.json

# 3b. or the offensive web agent against an AUTHORIZED local target
tsengine web-investigate --target http://localhost:3000 --ledger /tmp/web-ledger.json

# 4. score the L2 pass of a full scan against objectives
tsengine scan --asset web_application --target http://localhost:3000 -o /tmp/scan.json
tsbench agent --objectives fixtures/agent/objectives.example.json --scan /tmp/scan.json
```

> **Tool-capability caveat (honest).** The agent loop only works with a model that emits native tool
> calls. Pure chain-of-thought models (some `deepseek-r1` builds) will *reason* but never call a tool,
> so the loop can't act. Pick a model whose Ollama card lists **tools**. A "thinking" model that ALSO
> supports tools (qwen3, with thinking enabled) gives you both.

### Selector precedence (`ClientFromEnv` / `LLMFromEnv`)

1. `LLM_BASE_URL` set **or** `LLM_PROVIDER ∈ {openai, ollama, vllm, openrouter, lmstudio, local}` → the OpenAI-compat adapter (local or hosted).
2. else `ANTHROPIC_API_KEY` (l2.Client) / `LLM_API_KEY` (cloudengine.LLM) → the cloud client.
3. else `nil`/not-ok → the caller falls back to the deterministic output or a scripted mock (CI stays green with no key).

## 4. How each product's agent works today

| Product (asset) | Agent | Loop | Seam | What it does |
|---|---|---|---|---|
| **web_application / api** | `internal/webagent` | offensive ReAct over a bounded HTTP requester (no-follow redirects, host allow-list, request budget) | `cloudengine.LLM` | the XBOW-style exploitation agent (ADR-0008): sends crafted requests, reads the engine's view, proposes + verifies a PoC. The runner disposes (RoE gate) before any side effect. |
| **cloud_account** | `internal/cloudagent` | VulnAgent-style investigate loop (§10): the model drives, calling deterministic cloud tools (`cloudgraph` reachability, `cloudiam` effective-perms, the attack-path enumerator) | `cloudengine.LLM` | enumerates real attack paths, every claim backed by a tool result; remediations re-verified through `cloudiam.Authorize` before a PR/ticket. |
| **all assets** | `internal/l2` (the **Lead/translator**) | the ≤12-tool OODA loop (§2.6): phase-filtered catalog, token budget, context compaction, `create_vulnerability_report` commit, verification gate | `l2.Client` | translates L1's complete-but-raw findings into the developer artifact — prioritized list, attack-chain narrative, plain-English, compliance evidence. Reasoning is the model's; commits ride as tool params. |
| **LLM apps** | `internal/llmredteam` | red-team probe loop | `cloudengine.LLM` | adversarial prompts against a target LLM endpoint. |

Common substrate under all of them (CLAUDE.md §10): the LLM **reasons**, but every recorded issue
cites a deterministic **tool** result — the anti-hallucination guard. Mutations are HITL-gated; the
agent's own access stays read-only. The decision trail is signed into `pkg/ledger` (replayable).

## 5. Making it "cutting edge like Claude Code"

The harness already has the load-bearing pieces Claude Code relies on: a tool-use loop, a token
**budget** (`budget.go`), **context compaction** when the window fills (`compaction.go`), OODA
**phases** (`phase.go`), and a signed, replayable **ledger**. The local-Ollama path closes the dev loop:
iterate prompt/tool/flow changes against a free local model, watch the ledger replay, then confirm the
number on a cloud model. The open items are the **live eval targets** (a deployed WebGoat/Juice-Shop +
the cloud key) that turn the in-place harness into a published `verified_rate`.
