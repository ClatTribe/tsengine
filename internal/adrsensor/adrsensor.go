// Package adrsensor maps the output of Uber's ADR Sensor into an agentposture Snapshot.
//
// ADR (github.com/uber/ADR, Apache-2.0, MLSys 2026, production-deployed at Uber) is the leading OSS
// agent-telemetry collector: it parses the local logs of Claude Code, Cursor, Cline, Codex CLI, Warp
// and Claude Desktop and normalizes them into one AgentEvent schema. agentposture could previously
// only be driven by a hand-posted inventory; this package is the adapter that makes a REAL collector
// drive it, which is the difference between "we could assess your agent estate if you described it"
// and "point the sensor at your fleet."
//
// §13 holds: we wrap the OSS collector's OUTPUT rather than reimplementing six log parsers. Everything
// here is a pure transformation — no process execution, no network, trivially testable.
//
// GROUNDING (§10) — the important part. An AgentEvent records what an agent DID. It does not record
// org policy. So two Agent fields are deliberately never derived here:
//
//   - Sanctioned — whether the tool is on the approved list is a fact about the organization, not
//     about the telemetry. Inferring it would fabricate an approval nobody granted.
//   - Autonomy — whether a human approves consequential actions is a configuration fact. Observing
//     that an agent ran many tools does NOT establish it was unsupervised.
//
// Both stay zero-valued unless a caller supplies them from a real inventory, and agentposture treats
// an unstated field as unknown rather than bad. That keeps a telemetry-only ingest from manufacturing
// findings the evidence cannot support.
//
// TRUST BOUNDARY. This input is agent transcripts: adversarial by construction, since prompt
// injection is among the things they carry. We read STRUCTURED fields only — source, model, hostname,
// tool_name, tool_type, server_name — and never message content. Nothing from a transcript body
// reaches a Snapshot, so injected prose has no path into a finding or a downstream prompt.
package adrsensor

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/agentposture"
)

// ToolUsage is one tool invocation inside a chat message (ADR: ToolUsage).
type ToolUsage struct {
	ToolName   string `json:"tool_name"`
	ToolType   string `json:"tool_type"`             // mcp_tool | function_call | tool_use | terminal_command
	ServerName string `json:"server_name,omitempty"` // set for MCP tools
	// arguments/result/error are deliberately NOT read: they carry model- and tool-produced text,
	// which is the untrusted half of this input.
}

// ChatMessage is one turn (ADR: ChatMessage). Content is intentionally absent from this struct — we
// need the tool calls, never the prose.
type ChatMessage struct {
	Role  string      `json:"role"`
	Tools []ToolUsage `json:"tools,omitempty"`
}

// Event is the subset of ADR's AgentEvent this mapper reads.
type Event struct {
	Timestamp   time.Time     `json:"timestamp"`
	Source      string        `json:"source"` // claude | cursor | cline | warp | codex | cowork
	SessionID   string        `json:"session_id"`
	ChatHistory []ChatMessage `json:"chat_history,omitempty"`
	UserID      string        `json:"user_id,omitempty"`
	Model       string        `json:"model,omitempty"`
	Hostname    string        `json:"hostname,omitempty"`
	Username    string        `json:"username,omitempty"`
	IsTruncated bool          `json:"is_truncated,omitempty"`
}

// sourceNames maps ADR's short source ids to the agent names agentposture's checks expect.
// An unrecognized source passes through unchanged rather than being dropped — a new agent the sensor
// learns about should still appear in the estate, just under its own name.
var sourceNames = map[string]string{
	"claude": "claude-code",
	"cursor": "cursor",
	"cline":  "cline",
	"codex":  "codex",
	"warp":   "warp",
	"cowork": "cowork",
}

// ParseJSONL reads ADR Sensor's JSONL export (one AgentEvent per line).
//
// A malformed line is SKIPPED and counted, never fatal: this is a fleet export, and one corrupt
// record from one laptop must not discard every other machine's telemetry. The error return is
// reserved for a read failure on the stream itself.
func ParseJSONL(r io.Reader) (events []Event, skipped int, err error) {
	sc := bufio.NewScanner(r)
	// Agent events carry chat history, so lines are large; the default 64KiB token is far too small.
	sc.Buffer(make([]byte, 0, 1<<20), 16<<20)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		var e Event
		if jerr := json.Unmarshal([]byte(line), &e); jerr != nil || e.Source == "" {
			skipped++
			continue
		}
		events = append(events, e)
	}
	if serr := sc.Err(); serr != nil {
		return events, skipped, fmt.Errorf("adrsensor: read events: %w", serr)
	}
	return events, skipped, nil
}

// agentKey identifies one agent installation: the same tool run by the same person on the same host.
// Aggregating on all three keeps two engineers' Cursor installs from merging into one phantom agent.
type agentKey struct{ source, user, host string }

// ToSnapshot aggregates events into an agentposture Snapshot.
//
// Sessions counts DISTINCT session_ids, not events — ADR emits an event per parsed log record and
// chunks large sessions, so counting events would inflate activity by an arbitrary factor.
func ToSnapshot(events []Event) agentposture.Snapshot {
	type acc struct {
		agent    agentposture.Agent
		sessions map[string]bool
		mcp      map[string]bool
		tools    map[string]int
	}
	byKey := map[agentKey]*acc{}

	for _, e := range events {
		user := e.Username
		if user == "" {
			user = e.UserID
		}
		k := agentKey{source: e.Source, user: user, host: e.Hostname}
		a, ok := byKey[k]
		if !ok {
			a = &acc{
				agent: agentposture.Agent{
					Name: agentName(e.Source), User: user, Host: e.Hostname, Model: e.Model,
				},
				sessions: map[string]bool{}, mcp: map[string]bool{}, tools: map[string]int{},
			}
			byKey[k] = a
		}
		// Keep the most recently observed model: an agent's model changes over time, and the current
		// one is what a reviewer needs.
		if e.Model != "" && !e.Timestamp.Before(a.agent.LastSeen) {
			a.agent.Model = e.Model
		}
		if e.Timestamp.After(a.agent.LastSeen) {
			a.agent.LastSeen = e.Timestamp
		}
		if e.SessionID != "" {
			a.sessions[e.SessionID] = true
		}
		for _, m := range e.ChatHistory {
			for _, t := range m.Tools {
				if t.ToolType == "mcp_tool" && t.ServerName != "" {
					a.mcp[t.ServerName] = true
				}
				if t.ToolName != "" {
					a.tools[t.ToolName]++
				}
			}
		}
	}

	out := agentposture.Snapshot{}
	for _, a := range byKey {
		a.agent.Sessions = len(a.sessions)

		for name := range a.mcp {
			// Pinned/Verified are provenance facts about the server, which telemetry does not carry —
			// an invocation tells you the server RAN, not where it came from or whether anyone vetted
			// it. Left false so agentposture treats them as unknown rather than asserted-good.
			a.agent.MCPServers = append(a.agent.MCPServers, agentposture.MCPServer{Name: name})
		}
		sort.Slice(a.agent.MCPServers, func(i, j int) bool {
			return a.agent.MCPServers[i].Name < a.agent.MCPServers[j].Name
		})

		for name, n := range a.tools {
			// Target stays empty: it would have to come from tool arguments, which are untrusted
			// tool/model text. The tool NAME plus a count is the structured signal.
			a.agent.ToolUse = append(a.agent.ToolUse, agentposture.ToolUse{Tool: name, Count: n})
		}
		sort.Slice(a.agent.ToolUse, func(i, j int) bool {
			if a.agent.ToolUse[i].Count != a.agent.ToolUse[j].Count {
				return a.agent.ToolUse[i].Count > a.agent.ToolUse[j].Count
			}
			return a.agent.ToolUse[i].Tool < a.agent.ToolUse[j].Tool
		})

		out.Agents = append(out.Agents, a.agent)
	}
	// Deterministic order — the same export must produce the same snapshot every run (§10).
	sort.Slice(out.Agents, func(i, j int) bool {
		x, y := out.Agents[i], out.Agents[j]
		if x.Name != y.Name {
			return x.Name < y.Name
		}
		if x.User != y.User {
			return x.User < y.User
		}
		return x.Host < y.Host
	})
	return out
}

// agentName maps an ADR source id to the estate-facing agent name.
func agentName(source string) string {
	if n, ok := sourceNames[strings.ToLower(strings.TrimSpace(source))]; ok {
		return n
	}
	return source
}
