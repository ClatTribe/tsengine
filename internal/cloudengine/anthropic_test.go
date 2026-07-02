package cloudengine

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestAnthropic_Generate drives the Claude adapter against a fake Messages API: asserts it sends the
// key in x-api-key (never the URL), the anthropic-version header, the prompt as a user message, and
// returns the text block. This is the frontier-model backend `ANTHROPIC_API_KEY` turns on for the agents.
func TestAnthropic_Generate(t *testing.T) {
	var gotKey, gotVer, gotModel, gotUserMsg, gotURL string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKey = r.Header.Get("x-api-key")
		gotVer = r.Header.Get("anthropic-version")
		gotURL = r.URL.Path
		b, _ := io.ReadAll(r.Body)
		var req anthropicReq
		_ = json.Unmarshal(b, &req)
		gotModel = req.Model
		if len(req.Messages) > 0 {
			gotUserMsg = req.Messages[0].Content
		}
		_ = json.NewEncoder(w).Encode(anthropicResp{Content: []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		}{{Type: "text", Text: `{"tool":"finish","args":{}}`}}})
	}))
	defer srv.Close()

	c := NewAnthropic("sk-ant-secret", "claude-opus-4-1", srv.URL)
	out, err := c.Generate(context.Background(), "you are a pentester, act")
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	if out != `{"tool":"finish","args":{}}` {
		t.Errorf("text = %q, want the JSON action", out)
	}
	if gotKey != "sk-ant-secret" {
		t.Errorf("x-api-key = %q, want the key", gotKey)
	}
	if gotVer == "" {
		t.Error("anthropic-version header not set")
	}
	if gotModel != "claude-opus-4-1" {
		t.Errorf("model = %q, want the override", gotModel)
	}
	if !strings.Contains(gotUserMsg, "pentester") {
		t.Errorf("prompt not delivered as a user message: %q", gotUserMsg)
	}
	if !strings.HasSuffix(gotURL, "/v1/messages") {
		t.Errorf("path = %q, want /v1/messages", gotURL)
	}
}

// TestAnthropicFromEnv gates on ANTHROPIC_API_KEY and defaults the model + base; LLMFromEnv prefers it.
func TestAnthropicFromEnv(t *testing.T) {
	t.Setenv("ANTHROPIC_API_KEY", "")
	if _, ok := AnthropicFromEnv(); ok {
		t.Error("AnthropicFromEnv should be off with no key")
	}
	t.Setenv("ANTHROPIC_API_KEY", "sk-ant-x")
	t.Setenv("ANTHROPIC_MODEL", "")
	c, ok := AnthropicFromEnv()
	if !ok {
		t.Fatal("AnthropicFromEnv should be on with a key")
	}
	if c.model == "" || c.baseURL == "" {
		t.Errorf("model/base not defaulted: model=%q base=%q", c.model, c.baseURL)
	}
	// LLMFromEnv must prefer Anthropic when its key is set.
	if llm, ok := LLMFromEnv(); !ok {
		t.Fatal("LLMFromEnv returned nothing with ANTHROPIC_API_KEY set")
	} else if _, isAnthropic := llm.(*Anthropic); !isAnthropic {
		t.Errorf("LLMFromEnv did not select Anthropic: %T", llm)
	}
}
