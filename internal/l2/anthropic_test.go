package l2

import "testing"

// Consecutive tool-result turns must coalesce into ONE user message with
// multiple tool_result blocks (Anthropic API requirement).
func TestBuildBody_CoalescesToolResults(t *testing.T) {
	c := NewAnthropicClient("claude-sonnet-4-5")
	history := []Message{
		{Role: RoleUser, Content: "begin"},
		{Role: RoleAssistant, Content: "ok", ToolCalls: []ToolCall{
			{ID: "a", Name: "think", Args: map[string]any{"thought": "x"}},
			{ID: "b", Name: "advance_phase"},
		}},
		{Role: RoleTool, ToolCallID: "a", Content: "noted"},
		{Role: RoleTool, ToolCallID: "b", Content: "advanced"},
	}
	body := c.buildBody("SYS", history, []ToolSchema{{Name: "think", Params: obj(nil)}})

	if body.System != "SYS" || body.Model != "claude-sonnet-4-5" {
		t.Errorf("body header wrong: %+v", body)
	}
	// user(begin), assistant(text+2 tool_use), user(2 tool_result coalesced)
	if len(body.Messages) != 3 {
		t.Fatalf("messages = %d, want 3 (tool results coalesced)", len(body.Messages))
	}
	last := body.Messages[2]
	if last.Role != "user" || len(last.Content) != 2 {
		t.Errorf("coalesced tool_result msg = %+v", last)
	}
	for _, blk := range last.Content {
		if blk.Type != "tool_result" {
			t.Errorf("block type = %q, want tool_result", blk.Type)
		}
	}
	// assistant turn carries the 2 tool_use blocks (+ text).
	if body.Messages[1].Role != "assistant" || len(body.Messages[1].Content) != 3 {
		t.Errorf("assistant msg blocks = %+v", body.Messages[1].Content)
	}
	if len(body.Tools) != 1 || body.Tools[0].Name != "think" {
		t.Errorf("tools = %+v", body.Tools)
	}
}

func TestParseResponse_TextToolUseUsage(t *testing.T) {
	blob := []byte(`{
	  "content":[
	    {"type":"text","text":"let me check"},
	    {"type":"tool_use","id":"t1","name":"finish_scan","input":{"executive_summary":"done"}}
	  ],
	  "stop_reason":"tool_use",
	  "usage":{"input_tokens":1000,"output_tokens":50,"cache_read_input_tokens":800}
	}`)
	c := NewAnthropicClient("claude-sonnet-4-5")
	r, err := c.parseResponse(blob)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if r.Text != "let me check" || r.StopReason != "tool_use" {
		t.Errorf("resp = %+v", r)
	}
	if len(r.ToolCalls) != 1 || r.ToolCalls[0].Name != "finish_scan" {
		t.Errorf("tool calls = %+v", r.ToolCalls)
	}
	if r.ToolCalls[0].Args["executive_summary"] != "done" {
		t.Errorf("args = %+v", r.ToolCalls[0].Args)
	}
	if r.Usage.InputTokens != 1000 || r.Usage.CacheReadTokens != 800 {
		t.Errorf("usage = %+v", r.Usage)
	}
	// Cache-discounted cost should be well below the no-cache cost.
	if r.Usage.CostUSD <= 0 {
		t.Errorf("cost not computed: %v", r.Usage.CostUSD)
	}
}

func TestEstimateCost_CacheDiscount(t *testing.T) {
	full := estimateCost("claude-sonnet-4-5", Usage{InputTokens: 1_000_000, OutputTokens: 0})
	cached := estimateCost("claude-sonnet-4-5", Usage{InputTokens: 1_000_000, CacheReadTokens: 1_000_000, OutputTokens: 0})
	if cached >= full {
		t.Errorf("cache reads should cost less: cached=%.2f full=%.2f", cached, full)
	}
}
