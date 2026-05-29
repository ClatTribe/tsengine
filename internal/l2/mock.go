package l2

import "context"

// MockClient is a scripted Client for tests + dry-runs: it returns
// pre-programmed Responses in order, capturing what it was asked. When the
// script is exhausted it returns a benign empty turn (no tool calls), so a
// runaway loop is caught by the watchdog/budget rather than a panic.
type MockClient struct {
	ModelName string
	Script    []Response
	i         int

	// Captured inputs (most recent last) for assertions.
	Systems   []string
	Histories [][]Message
	ToolSets  [][]ToolSchema
}

// Generate returns the next scripted Response.
func (m *MockClient) Generate(_ context.Context, system string, history []Message, tools []ToolSchema) (Response, error) {
	m.Systems = append(m.Systems, system)
	m.Histories = append(m.Histories, append([]Message(nil), history...))
	m.ToolSets = append(m.ToolSets, append([]ToolSchema(nil), tools...))

	if m.i >= len(m.Script) {
		return Response{StopReason: "end_turn", Usage: Usage{InputTokens: 1, OutputTokens: 1}}, nil
	}
	r := m.Script[m.i]
	m.i++
	return r, nil
}

// Model returns the mock model id.
func (m *MockClient) Model() string {
	if m.ModelName == "" {
		return "mock"
	}
	return m.ModelName
}

// scriptCall is a tiny helper for tests to script a tool-use turn.
func scriptCall(name string, args map[string]any, cost float64) Response {
	return Response{
		StopReason: "tool_use",
		ToolCalls:  []ToolCall{{ID: name + "-1", Name: name, Args: args}},
		Usage:      Usage{InputTokens: 100, OutputTokens: 20, CostUSD: cost},
	}
}
