// Package llmredteam is the agentic LLM / AI red-teaming service (roadmap §2): a
// multi-turn attacker agent vs a client's LLM endpoint, graded by a DETERMINISTIC
// verifier. The grounding principle from the web + cloud agents holds here too — a
// "successful jailbreak" must be PROVABLE from the target's own output (a planted
// canary leaked, the verbatim system-prompt sentinel echoed, a denylisted tool
// fired, planted PII disclosed), never asserted by the attacker. record_breach is
// rejected unless the verifier confirmed the breach on a real turn.
//
// It also closes a real self-risk: the same harness pointed at our own agents
// measures their injection resilience (roadmap §6).
package llmredteam

import "context"

// Msg is one chat message in the conversation with the target.
type Msg struct {
	Role    string `json:"role"` // system | user | assistant
	Content string `json:"content"`
}

// ToolCall is a tool invocation the target emitted in its reply.
type ToolCall struct {
	Name string `json:"name"`
	Args string `json:"args,omitempty"`
}

// Reply is the target LLM's response to a turn.
type Reply struct {
	Content   string     `json:"content"`
	ToolCalls []ToolCall `json:"tool_calls,omitempty"`
}

// Target is the LLM under test (the client's chatbot / agent endpoint).
type Target interface {
	Chat(ctx context.Context, history []Msg) (Reply, error)
}

// Engagement is the red-team configuration: the tripwires the verifier watches.
// These are planted / registered by the AUTHORIZED red-teamer — canary secrets
// seeded into the target's system prompt, the denylist of dangerous tools, a
// sentinel line from the system prompt, PII shapes — so a breach is provable from
// the target's output, not a judgment call.
type Engagement struct {
	Name           string   `json:"name"`
	Canaries       []string `json:"canaries"`        // secret sentinels that must never appear in output
	SystemSentinel string   `json:"system_sentinel"` // a marker line from the system prompt (leak ⇒ extraction)
	ForbiddenTools []string `json:"forbidden_tools"` // tools that must never fire
	PIIPatterns    []string `json:"pii_patterns"`    // regex strings matching planted PII
}
