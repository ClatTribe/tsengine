package l2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// OpenAICompatClient is a Client over the OpenAI /v1/chat/completions protocol — the de-facto standard
// that OpenAI, OpenRouter, vLLM, LM Studio, and **Ollama** all speak. This is what lets the L2 agent be
// driven by a LOCAL thinking model for testing: point BaseURL at a local Ollama
// (http://localhost:11434/v1) and run the full agent loop with zero cloud cost and no API key — the
// "test it like Claude Code, locally" path. The wire mapping mirrors anthropic.go; only the schema
// differs (OpenAI messages/tool_calls vs Anthropic blocks).
//
// Tool-calling caveat (honest): the agent loop REQUIRES native function-calling. Use a tool-capable
// local model (qwen2.5, qwen3, llama3.1/3.3, mistral-nemo, firefunction). Pure chain-of-thought models
// without tool support (some deepseek-r1 builds) will reason but never emit a ToolCall, so the loop
// can't act — pick a model whose Ollama card lists "tools".
type OpenAICompatClient struct {
	apiKey    string
	model     string
	baseURL   string // e.g. https://api.openai.com/v1 or http://localhost:11434/v1
	maxTokens int
	ctxWindow int
	local     bool // a localhost/Ollama endpoint → inference is free (CostUSD=0)
	http      *http.Client
}

// NewOpenAICompatClient builds the client. Empty args fall back to env (LLM_MODEL / LLM_BASE_URL /
// LLM_API_KEY) then sensible defaults. For Ollama: NewOpenAICompatClient("qwen2.5",
// "http://localhost:11434/v1", "ollama") — the key is ignored by Ollama but some gateways want a value.
func NewOpenAICompatClient(model, baseURL, apiKey string) *OpenAICompatClient {
	if model == "" {
		model = envOr("LLM_MODEL", "gpt-4o-mini")
	}
	if baseURL == "" {
		baseURL = envOr("LLM_BASE_URL", "https://api.openai.com/v1")
	}
	if apiKey == "" {
		apiKey = os.Getenv("LLM_API_KEY")
	}
	baseURL = strings.TrimRight(baseURL, "/")
	low := strings.ToLower(baseURL)
	local := strings.Contains(low, "localhost") || strings.Contains(low, "127.0.0.1") || strings.Contains(low, "host.docker.internal") || strings.Contains(low, ":11434")
	cw := 128_000
	if local {
		cw = 32_768 // local models typically run a smaller window; the agent compacts against it
	}
	return &OpenAICompatClient{
		apiKey: apiKey, model: model, baseURL: baseURL, maxTokens: 4096,
		ctxWindow: cw, local: local,
		http: &http.Client{Timeout: 300 * time.Second}, // local thinking models can be slow
	}
}

func (c *OpenAICompatClient) Model() string      { return c.model }
func (c *OpenAICompatClient) ContextWindow() int { return c.ctxWindow }

// Generate runs one turn against the chat-completions endpoint.
func (c *OpenAICompatClient) Generate(ctx context.Context, system string, history []Message, tools []ToolSchema) (Response, error) {
	// A local endpoint needs no key; a hosted one (OpenAI/OpenRouter) does.
	if c.apiKey == "" && !c.local {
		return Response{}, errors.New("openai-compat: LLM_API_KEY not set (a hosted endpoint needs a key; for local Ollama set LLM_BASE_URL=http://localhost:11434/v1)")
	}
	body, err := json.Marshal(c.buildBody(system, history, tools))
	if err != nil {
		return Response{}, fmt.Errorf("openai-compat: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("content-type", "application/json")
	if c.apiKey != "" {
		req.Header.Set("authorization", "Bearer "+c.apiKey)
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return Response{}, fmt.Errorf("openai-compat: do: %w", err)
	}
	defer resp.Body.Close()
	var raw bytes.Buffer
	if _, err := raw.ReadFrom(resp.Body); err != nil {
		return Response{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("openai-compat: status %d: %s", resp.StatusCode, raw.String())
	}
	return c.parseResponse(raw.Bytes())
}

// --- request shaping -------------------------------------------------

type oaiBody struct {
	Model     string    `json:"model"`
	Messages  []oaiMsg  `json:"messages"`
	Tools     []oaiTool `json:"tools,omitempty"`
	MaxTokens int       `json:"max_tokens,omitempty"`
}

type oaiMsg struct {
	Role       string        `json:"role"`
	Content    string        `json:"content"`
	ToolCalls  []oaiToolCall `json:"tool_calls,omitempty"`
	ToolCallID string        `json:"tool_call_id,omitempty"`
}

type oaiToolCall struct {
	ID       string  `json:"id"`
	Type     string  `json:"type"`
	Function oaiFunc `json:"function"`
}

type oaiFunc struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // a JSON STRING per the OpenAI spec
}

type oaiTool struct {
	Type     string         `json:"type"`
	Function oaiToolFuncDef `json:"function"`
}

type oaiToolFuncDef struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

func (c *OpenAICompatClient) buildBody(system string, history []Message, tools []ToolSchema) oaiBody {
	msgs := make([]oaiMsg, 0, len(history)+1)
	if system != "" {
		msgs = append(msgs, oaiMsg{Role: "system", Content: system})
	}
	for _, m := range history {
		switch m.Role {
		case RoleUser:
			msgs = append(msgs, oaiMsg{Role: "user", Content: m.Content})
		case RoleAssistant:
			om := oaiMsg{Role: "assistant", Content: m.Content}
			for _, tc := range m.ToolCalls {
				args, _ := json.Marshal(tc.Args)
				om.ToolCalls = append(om.ToolCalls, oaiToolCall{ID: tc.ID, Type: "function",
					Function: oaiFunc{Name: tc.Name, Arguments: string(args)}})
			}
			msgs = append(msgs, om)
		case RoleTool:
			msgs = append(msgs, oaiMsg{Role: "tool", ToolCallID: m.ToolCallID, Content: m.Content})
		}
	}
	ot := make([]oaiTool, 0, len(tools))
	for _, t := range tools {
		ot = append(ot, oaiTool{Type: "function",
			Function: oaiToolFuncDef{Name: t.Name, Description: t.Description, Parameters: t.Params}})
	}
	return oaiBody{Model: c.model, Messages: msgs, Tools: ot, MaxTokens: c.maxTokens}
}

// --- response parsing ------------------------------------------------

type oaiResp struct {
	Choices []struct {
		Message struct {
			Content   string        `json:"content"`
			ToolCalls []oaiToolCall `json:"tool_calls"`
		} `json:"message"`
		FinishReason string `json:"finish_reason"`
	} `json:"choices"`
	Usage struct {
		PromptTokens     int `json:"prompt_tokens"`
		CompletionTokens int `json:"completion_tokens"`
	} `json:"usage"`
}

func (c *OpenAICompatClient) parseResponse(blob []byte) (Response, error) {
	var or oaiResp
	if err := json.Unmarshal(blob, &or); err != nil {
		return Response{}, fmt.Errorf("openai-compat: decode: %w", err)
	}
	if len(or.Choices) == 0 {
		return Response{}, errors.New("openai-compat: no choices in response")
	}
	ch := or.Choices[0]
	out := Response{Text: ch.Message.Content, StopReason: mapFinishReason(ch.FinishReason)}
	for _, tc := range ch.Message.ToolCalls {
		out.ToolCalls = append(out.ToolCalls, ToolCall{ID: tc.ID, Name: tc.Function.Name, Args: parseToolArgs(tc.Function.Arguments)})
	}
	out.Usage = Usage{InputTokens: or.Usage.PromptTokens, OutputTokens: or.Usage.CompletionTokens}
	if !c.local { // local inference is free; hosted gets an estimate
		out.Usage.CostUSD = estimateCost(c.model, out.Usage)
	}
	return out, nil
}

// parseToolArgs decodes a tool call's arguments. The OpenAI spec says arguments is a JSON string, but
// some local models emit a bare object — handle both, and an empty string → empty map.
func parseToolArgs(s string) map[string]any {
	s = strings.TrimSpace(s)
	if s == "" {
		return map[string]any{}
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(s), &m); err == nil {
		return m
	}
	// arguments was itself a quoted JSON string (double-encoded) — unwrap once.
	var inner string
	if err := json.Unmarshal([]byte(s), &inner); err == nil {
		if err := json.Unmarshal([]byte(inner), &m); err == nil {
			return m
		}
	}
	return map[string]any{}
}

func mapFinishReason(r string) string {
	switch r {
	case "tool_calls", "function_call":
		return "tool_use"
	case "length":
		return "max_tokens"
	case "stop", "":
		return "end_turn"
	default:
		return r
	}
}

func envOr(key, dflt string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return dflt
}

// ClientFromEnv selects the L2 client from the environment, so the same agent loop runs against a cloud
// model OR a local Ollama with no code change:
//   - LLM_BASE_URL set, or LLM_PROVIDER ∈ {openai,ollama,openai-compat,local,vllm,openrouter} → the
//     OpenAI-compatible adapter (set LLM_BASE_URL=http://localhost:11434/v1 + LLM_MODEL=qwen2.5 for a
//     local Ollama — free, no key).
//   - else ANTHROPIC_API_KEY set → the Anthropic client (LLM_MODEL overrides the default model).
//   - else nil (the caller falls back to a scripted MockClient or errors with guidance).
func ClientFromEnv() Client {
	provider := strings.ToLower(strings.TrimSpace(os.Getenv("LLM_PROVIDER")))
	openaiish := map[string]bool{"openai": true, "ollama": true, "openai-compat": true, "local": true, "vllm": true, "openrouter": true, "lmstudio": true}
	if os.Getenv("LLM_BASE_URL") != "" || openaiish[provider] {
		return NewOpenAICompatClient(os.Getenv("LLM_MODEL"), os.Getenv("LLM_BASE_URL"), os.Getenv("LLM_API_KEY"))
	}
	if os.Getenv("ANTHROPIC_API_KEY") != "" {
		return NewAnthropicClient(os.Getenv("LLM_MODEL"))
	}
	return nil
}
