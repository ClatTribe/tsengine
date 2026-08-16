#!/usr/bin/env python3
"""An OpenAI-compatible endpoint whose "model" is a human (or an agent) with a text editor.

WHY THIS EXISTS. The L2 agents are gated on a frontier model: the repo's own scoreboard says an 8B
local model is "a smoke test, not a credible measurement". That leaves a gap — you cannot evaluate
the agents at all without an API key, so nobody does, and the agent half of the product goes
unmeasured for months at a time.

This closes the gap without a key. It speaks just enough of the OpenAI chat-completions API for
`cloudengine.OpenAICompatFromEnv` to talk to it, and instead of calling a model it writes the request
to a file and blocks until someone writes the reply. Whoever is driving reads the prompt, thinks, and
answers — so the "model" is whatever intelligence is at the keyboard.

    LLM_BASE_URL=http://127.0.0.1:8898/v1 LLM_MODEL=proxy LLM_API_KEY=proxy \
        go run ./cmd/tsbench cloud-engine --agent

    # then, per turn:
    #   read  ./llmproxy/turn_prompt.txt      (request N, pretty-printed)
    #   write ./llmproxy/turn_response.txt    (the assistant message, or a tool call)

WHAT IT IS NOT. This is not a way to fake a benchmark result. The agent's own grounding still applies
— a recorded finding must cite real evidence, and the deterministic predicates still dispose. A
driver who invents a finding gets scored as having invented one, which is the point. But a number
produced this way is a DEMONSTRATION at whatever sample size was driven, not a statistical result:
say "n=3, driven manually" or do not quote it.
"""

import json
import os
import sys
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

DIR = os.environ.get("LLM_PROXY_DIR", "llmproxy")
PROMPT = os.path.join(DIR, "turn_prompt.txt")
RESPONSE = os.path.join(DIR, "turn_response.txt")
POLL_SECONDS = 0.5
TURN = {"n": 0}


def _write_prompt(body: dict) -> None:
    """Render the request so a human can act on it without parsing JSON by eye."""
    TURN["n"] += 1
    lines = [f"===== TURN {TURN['n']} =====", ""]

    tools = body.get("tools") or []
    if tools:
        lines.append("--- TOOLS AVAILABLE ---")
        for t in tools:
            fn = t.get("function", t)
            lines.append(f"  {fn.get('name')}({', '.join((fn.get('parameters') or {}).get('properties', {}))})")
            if fn.get("description"):
                lines.append(f"      {fn['description'][:160]}")
        lines.append("")

    for m in body.get("messages", []):
        role = m.get("role", "?").upper()
        content = m.get("content")
        if isinstance(content, list):  # multimodal-shaped content
            content = " ".join(p.get("text", "") for p in content if isinstance(p, dict))
        lines.append(f"--- {role} ---")
        if content:
            lines.append(str(content))
        for tc in m.get("tool_calls") or []:
            f = tc.get("function", {})
            lines.append(f"  [tool_call] {f.get('name')}({f.get('arguments')})")
        lines.append("")

    lines += [
        "===== WRITE YOUR REPLY TO turn_response.txt =====",
        "Plain text becomes the assistant message. For a tool call, write EXACTLY:",
        '  TOOL <name> <json-arguments-on-one-line>',
        "",
    ]
    with open(PROMPT, "w") as fh:
        fh.write("\n".join(lines))


def _await_response() -> dict:
    """Block until a reply appears, then consume it so the next turn starts clean."""
    while not os.path.exists(RESPONSE):
        time.sleep(POLL_SECONDS)
    # Settle: a writer using shell redirection can create the file before the content lands.
    time.sleep(POLL_SECONDS)
    with open(RESPONSE) as fh:
        text = fh.read().strip()
    os.remove(RESPONSE)

    if text.startswith("TOOL "):
        rest = text[len("TOOL "):].strip()
        name, _, args = rest.partition(" ")
        return {
            "role": "assistant",
            "content": None,
            "tool_calls": [{
                "id": f"call_{TURN['n']}",
                "type": "function",
                "function": {"name": name.strip(), "arguments": args.strip() or "{}"},
            }],
        }
    return {"role": "assistant", "content": text}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self):  # noqa: N802 — http.server's interface
        body = json.loads(self.rfile.read(int(self.headers.get("Content-Length", 0))) or b"{}")
        _write_prompt(body)
        print(f"[proxy] turn {TURN['n']} awaiting {RESPONSE}", file=sys.stderr, flush=True)
        message = _await_response()

        out = {
            "id": f"chatcmpl-{TURN['n']}",
            "object": "chat.completion",
            "model": body.get("model", "proxy"),
            "choices": [{
                "index": 0,
                "message": message,
                "finish_reason": "tool_calls" if message.get("tool_calls") else "stop",
            }],
            "usage": {"prompt_tokens": 0, "completion_tokens": 0, "total_tokens": 0},
        }
        payload = json.dumps(out).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):  # noqa: N802 — some clients probe /v1/models first
        payload = json.dumps({"data": [{"id": "proxy", "object": "model"}]}).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_):  # keep stderr for turn notices only
        pass


if __name__ == "__main__":
    os.makedirs(DIR, exist_ok=True)
    for stale in (PROMPT, RESPONSE):
        if os.path.exists(stale):
            os.remove(stale)
    port = int(os.environ.get("LLM_PROXY_PORT", "8898"))
    print(f"[proxy] listening on 127.0.0.1:{port}, relaying through {DIR}/", file=sys.stderr, flush=True)
    HTTPServer(("127.0.0.1", port), Handler).serve_forever()
