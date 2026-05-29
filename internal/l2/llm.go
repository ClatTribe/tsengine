// Package l2 is the L2 layer — the AI security & compliance engineer
// (CLAUDE.md §2.2). It runs a single LLM "Lead" agent over a ≤12-tool
// catalog (§2.6) that TRANSLATES L1's complete-but-raw findings into the
// developer/PM-facing artifact: prioritized findings, attack chains,
// remediation, plain-English, compliance evidence.
//
// L2 never detects (L1 does), never drives recon (L1's deterministic
// prepass does), and never runs the known signal→tool escalations (the
// deterministic escalation engine does). L2 is the OPEN-ENDED reasoning
// layer only — "what's interesting here that the rules didn't anticipate".
//
// This file is the provider-agnostic LLM boundary. The agent loop talks to
// Client; production wires the Anthropic implementation, tests wire a
// scripted mock. Keeping the loop behind this interface is what lets the
// whole agent be unit-tested without a live model or an API key.
package l2

import "context"

// Role is a conversation turn's author.
type Role string

const (
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool" // a tool result fed back to the model
)

// Message is one conversation turn. A tool-result turn sets ToolCallID +
// Content; an assistant turn that requested tools sets ToolCalls.
type Message struct {
	Role       Role       `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// ToolSchema is the tool description the LLM sees in its catalog. Params is
// a JSON-Schema object ({"type":"object","properties":{...},"required":[]}).
type ToolSchema struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Params      map[string]any `json:"params"`
}

// ToolCall is the model's request to invoke a tool.
type ToolCall struct {
	ID   string         `json:"id"`
	Name string         `json:"name"`
	Args map[string]any `json:"args"`
}

// Usage is per-call token + cost accounting. CostUSD is computed by the
// provider impl from its pricing (cache-aware where supported — the cost
// lever strix found load-bearing).
type Usage struct {
	InputTokens       int     `json:"input_tokens"`
	OutputTokens      int     `json:"output_tokens"`
	CacheReadTokens   int     `json:"cache_read_tokens,omitempty"`
	CacheWriteTokens  int     `json:"cache_write_tokens,omitempty"`
	CostUSD           float64 `json:"cost_usd"`
}

// Response is one model turn. StopReason ∈ {"tool_use","end_turn","max_tokens"}.
type Response struct {
	Text       string     `json:"text,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	StopReason string     `json:"stop_reason"`
	Usage      Usage      `json:"usage"`
}

// Client is the provider-agnostic LLM boundary. Generate runs one turn:
// given the system prompt, conversation history, and the tools available
// THIS turn (already phase-filtered + ≤12-capped by the agent), it returns
// the model's next response.
type Client interface {
	Generate(ctx context.Context, system string, history []Message, tools []ToolSchema) (Response, error)
	// Model returns the model identifier (recorded for reproducibility).
	Model() string
	// ContextWindow is the model's max input-token window. The agent uses
	// it to decide when to compact (the actual context size of the last
	// turn is read from Response.Usage.InputTokens).
	ContextWindow() int
}
