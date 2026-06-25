package l2

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestOpenAICompat_GenerateMapsToolCall(t *testing.T) {
	var gotBody oaiBody
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/chat/completions") {
			t.Errorf("unexpected path %q", r.URL.Path)
		}
		b, _ := io.ReadAll(r.Body)
		_ = json.Unmarshal(b, &gotBody)
		// Ollama/OpenAI-shaped response: one tool call + usage.
		_, _ = w.Write([]byte(`{
		  "choices":[{"message":{"content":"Looking into it.","tool_calls":[
		    {"id":"call_1","type":"function","function":{"name":"get_finding","arguments":"{\"id\":\"f-001\"}"}}
		  ]},"finish_reason":"tool_calls"}],
		  "usage":{"prompt_tokens":120,"completion_tokens":18}}`))
	}))
	defer srv.Close()

	c := NewOpenAICompatClient("qwen2.5", srv.URL, "ollama")
	if !c.local {
		// srv.URL is 127.0.0.1 → treated as local (free).
		t.Error("a 127.0.0.1 endpoint should be detected as local")
	}
	resp, err := c.Generate(context.Background(), "you are a security engineer",
		[]Message{{Role: RoleUser, Content: "triage f-001"}},
		[]ToolSchema{{Name: "get_finding", Description: "read a finding", Params: map[string]any{"type": "object"}}})
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	// request shaping: system prepended, tool advertised as a function.
	if len(gotBody.Messages) != 2 || gotBody.Messages[0].Role != "system" {
		t.Errorf("expected system + user messages, got %+v", gotBody.Messages)
	}
	if len(gotBody.Tools) != 1 || gotBody.Tools[0].Function.Name != "get_finding" {
		t.Errorf("tool not mapped to a function def: %+v", gotBody.Tools)
	}
	// response parsing: tool call + args + stop reason + free local cost.
	if resp.StopReason != "tool_use" {
		t.Errorf("finish_reason tool_calls → tool_use, got %q", resp.StopReason)
	}
	if len(resp.ToolCalls) != 1 || resp.ToolCalls[0].Name != "get_finding" || resp.ToolCalls[0].Args["id"] != "f-001" {
		t.Errorf("tool call not parsed: %+v", resp.ToolCalls)
	}
	if resp.Usage.CostUSD != 0 {
		t.Errorf("local inference should be free, got cost %v", resp.Usage.CostUSD)
	}
	if resp.Usage.InputTokens != 120 || resp.Usage.OutputTokens != 18 {
		t.Errorf("usage not parsed: %+v", resp.Usage)
	}
}

func TestParseToolArgs_Robust(t *testing.T) {
	cases := map[string]map[string]any{
		`{"a":"b"}`:       {"a": "b"}, // normal: a JSON object string
		``:                {},         // empty → empty map
		`"{\"a\":\"b\"}"`: {"a": "b"}, // double-encoded (some local models) → unwrapped
	}
	for in, want := range cases {
		got := parseToolArgs(in)
		if len(got) != len(want) || (len(want) > 0 && got["a"] != want["a"]) {
			t.Errorf("parseToolArgs(%q) = %+v, want %+v", in, got, want)
		}
	}
}

func TestClientFromEnv_SelectsProvider(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("LLM_PROVIDER", "")
	// LLM_BASE_URL → OpenAI-compat (Ollama).
	t.Setenv("LLM_BASE_URL", "http://localhost:11434/v1")
	t.Setenv("LLM_MODEL", "qwen2.5")
	c := ClientFromEnv()
	if _, ok := c.(*OpenAICompatClient); !ok {
		t.Fatalf("LLM_BASE_URL should select the OpenAI-compat client, got %T", c)
	}
	if c.Model() != "qwen2.5" {
		t.Errorf("model should come from LLM_MODEL, got %q", c.Model())
	}
	// Nothing set → nil (caller falls back to mock / errors with guidance).
	t.Setenv("LLM_BASE_URL", "")
	if ClientFromEnv() != nil {
		t.Error("no provider env should yield a nil client")
	}
}
