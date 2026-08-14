# Use the AI Security Engineer from Claude Code / Cursor

The engine knows things a coding agent does not: whether a finding is real, where the vulnerability
actually lives, and which single fix has the most leverage. `tsmcp` exposes that over MCP so you can ask
from the editor instead of alt-tabbing to a dashboard.

## Setup

```bash
go build -o tsmcp ./cmd/tsmcp
```

Add to your MCP client config (Claude Code: `.mcp.json`; Cursor: `~/.cursor/mcp.json`):

```json
{
  "mcpServers": {
    "tsengine": {
      "command": "/absolute/path/to/tsmcp",
      "env": {
        "TSENGINE_URL": "https://your-workspace.example.com",
        "TSENGINE_TOKEN": "<a session token from your workspace>"
      }
    }
  }
}
```

Both env vars are required. The server refuses to start without them rather than running and answering
"unauthorized" to every call.

## What you can ask

| Tool | The question it answers |
|---|---|
| `ask_security_estate` | "are we exposed to log4j?" · "what critical findings are unproven?" |
| `where_is_the_vulnerability` | "which file do I actually open for finding f-123?" |
| `what_should_i_fix_first` | the choke point — the one thing that appears in the most attack paths |
| `list_open_issues` | the open issues, worst first, each with how confident the engine is |

## It is read-only, deliberately

There is no tool here that proposes a fix, opens a ticket, or changes anything. That is not an
oversight.

In an MCP session your coding agent is the actor — it writes the fix, opens the PR, runs the tests. What
it lacks is knowledge of your estate, so that is what this serves.

A write tool would also be a genuine hazard. A code-fix action is tier 1 in the remediation policy,
which **auto-applies**: it commits a branch and opens a real pull request. Exposing that over MCP would
let a conversational agent write to your repository with no approval desk, no tier check and no ledger
entry in between. Those gates live in the platform; a side door around them is not a feature.

Use the platform when you want the engineer to *act*. Use this when you want it to *answer*.

## What the answers will not do

They will not tell you that you are secure. An empty result says nothing matched, and an empty issue
list says it reflects what has been **scanned** — because "we found nothing" and "there is nothing" are
different statements, and only one of them is ever true.
