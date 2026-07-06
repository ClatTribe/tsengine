package l2

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"time"
)

// AnthropicClient is the default Client implementation (Claude). Other
// providers implement the same Client interface; the agent loop is
// provider-agnostic. API key from ANTHROPIC_API_KEY.
type AnthropicClient struct {
	apiKey    string
	model     string
	maxTokens int
	http      *http.Client
	endpoint  string // overridable for tests
}

// NewAnthropicClient constructs the client. model defaults to a current
// Claude model; the key is read from ANTHROPIC_API_KEY if not supplied.
func NewAnthropicClient(model string) *AnthropicClient {
	return NewAnthropicClientWithKey(model, os.Getenv("ANTHROPIC_API_KEY"))
}

// NewAnthropicClientWithKey constructs the client with an EXPLICIT key — the
// per-tenant path: a customer who configures their own Claude key drives the
// L2 Lead (Triage / Investigate) on their OWN budget, not the operator's. An
// empty key falls back to ANTHROPIC_API_KEY so the dev/operator path is intact.
func NewAnthropicClientWithKey(model, key string) *AnthropicClient {
	if model == "" {
		model = "claude-sonnet-4-5"
	}
	if key == "" {
		key = os.Getenv("ANTHROPIC_API_KEY")
	}
	return &AnthropicClient{
		apiKey:    key,
		model:     model,
		maxTokens: 4096,
		http:      &http.Client{Timeout: 120 * time.Second},
		endpoint:  "https://api.anthropic.com/v1/messages",
	}
}

func (c *AnthropicClient) Model() string { return c.model }

// ContextWindow returns the Claude input-token window (200K for the
// current Sonnet/Opus generation).
func (c *AnthropicClient) ContextWindow() int { return 200_000 }

// Generate runs one turn against the Anthropic Messages API.
func (c *AnthropicClient) Generate(ctx context.Context, system string, history []Message, tools []ToolSchema) (Response, error) {
	if c.apiKey == "" {
		return Response{}, errors.New("anthropic: ANTHROPIC_API_KEY not set")
	}
	body, err := json.Marshal(c.buildBody(system, history, tools))
	if err != nil {
		return Response{}, fmt.Errorf("anthropic: marshal: %w", err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.endpoint, bytes.NewReader(body))
	if err != nil {
		return Response{}, err
	}
	req.Header.Set("content-type", "application/json")
	req.Header.Set("x-api-key", c.apiKey)
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := c.http.Do(req)
	if err != nil {
		return Response{}, fmt.Errorf("anthropic: do: %w", err)
	}
	defer resp.Body.Close()
	var raw bytes.Buffer
	if _, err := raw.ReadFrom(resp.Body); err != nil {
		return Response{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return Response{}, fmt.Errorf("anthropic: status %d: %s", resp.StatusCode, raw.String())
	}
	return c.parseResponse(raw.Bytes())
}

// --- request shaping -------------------------------------------------

type anthropicBody struct {
	Model     string          `json:"model"`
	MaxTokens int             `json:"max_tokens"`
	System    string          `json:"system,omitempty"`
	Messages  []anthropicMsg  `json:"messages"`
	Tools     []anthropicTool `json:"tools,omitempty"`
}

type anthropicMsg struct {
	Role    string           `json:"role"`
	Content []anthropicBlock `json:"content"`
}

type anthropicBlock struct {
	Type      string         `json:"type"`
	Text      string         `json:"text,omitempty"`
	ID        string         `json:"id,omitempty"`
	Name      string         `json:"name,omitempty"`
	Input     map[string]any `json:"input,omitempty"`
	ToolUseID string         `json:"tool_use_id,omitempty"`
	Content   string         `json:"content,omitempty"` // tool_result content
}

type anthropicTool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"input_schema"`
}

// buildBody maps our provider-agnostic types to the Anthropic wire format.
// Consecutive tool-result turns are COALESCED into one user message (the
// API requires all tool_results for a turn in a single user message).
func (c *AnthropicClient) buildBody(system string, history []Message, tools []ToolSchema) anthropicBody {
	var msgs []anthropicMsg
	for i := 0; i < len(history); i++ {
		m := history[i]
		switch m.Role {
		case RoleUser:
			msgs = append(msgs, anthropicMsg{Role: "user",
				Content: []anthropicBlock{{Type: "text", Text: m.Content}}})
		case RoleAssistant:
			blocks := []anthropicBlock{}
			if m.Content != "" {
				blocks = append(blocks, anthropicBlock{Type: "text", Text: m.Content})
			}
			for _, tc := range m.ToolCalls {
				blocks = append(blocks, anthropicBlock{Type: "tool_use", ID: tc.ID, Name: tc.Name, Input: tc.Args})
			}
			msgs = append(msgs, anthropicMsg{Role: "assistant", Content: blocks})
		case RoleTool:
			// Coalesce this + any following tool-result turns.
			blocks := []anthropicBlock{{Type: "tool_result", ToolUseID: m.ToolCallID, Content: m.Content}}
			for i+1 < len(history) && history[i+1].Role == RoleTool {
				i++
				blocks = append(blocks, anthropicBlock{Type: "tool_result", ToolUseID: history[i].ToolCallID, Content: history[i].Content})
			}
			msgs = append(msgs, anthropicMsg{Role: "user", Content: blocks})
		}
	}
	at := make([]anthropicTool, 0, len(tools))
	for _, t := range tools {
		at = append(at, anthropicTool{Name: t.Name, Description: t.Description, InputSchema: t.Params})
	}
	return anthropicBody{Model: c.model, MaxTokens: c.maxTokens, System: system, Messages: msgs, Tools: at}
}

// --- response parsing ------------------------------------------------

type anthropicResp struct {
	Content    []anthropicBlock `json:"content"`
	StopReason string           `json:"stop_reason"`
	Usage      struct {
		InputTokens          int `json:"input_tokens"`
		OutputTokens         int `json:"output_tokens"`
		CacheReadInputTokens int `json:"cache_read_input_tokens"`
		CacheCreationTokens  int `json:"cache_creation_input_tokens"`
	} `json:"usage"`
}

func (c *AnthropicClient) parseResponse(blob []byte) (Response, error) {
	var ar anthropicResp
	if err := json.Unmarshal(blob, &ar); err != nil {
		return Response{}, fmt.Errorf("anthropic: decode: %w", err)
	}
	out := Response{StopReason: ar.StopReason}
	for _, b := range ar.Content {
		switch b.Type {
		case "text":
			out.Text += b.Text
		case "tool_use":
			out.ToolCalls = append(out.ToolCalls, ToolCall{ID: b.ID, Name: b.Name, Args: b.Input})
		}
	}
	out.Usage = Usage{
		InputTokens:      ar.Usage.InputTokens,
		OutputTokens:     ar.Usage.OutputTokens,
		CacheReadTokens:  ar.Usage.CacheReadInputTokens,
		CacheWriteTokens: ar.Usage.CacheCreationTokens,
	}
	out.Usage.CostUSD = estimateCost(c.model, out.Usage)
	return out, nil
}

// price is per-million-token USD (input, output). Cache reads bill at ~10%
// of input — the cost lever strix found load-bearing. Approximate; the
// authoritative cost is the provider invoice.
type price struct{ in, out float64 }

var pricing = map[string]price{
	"claude-sonnet-4-5": {3.0, 15.0},
	"claude-opus-4-1":   {15.0, 75.0},
	"claude-haiku-4-5":  {1.0, 5.0},
}

func estimateCost(model string, u Usage) float64 {
	p, ok := pricing[model]
	if !ok {
		p = price{3.0, 15.0} // sensible default
	}
	const m = 1_000_000.0
	fresh := u.InputTokens - u.CacheReadTokens
	if fresh < 0 {
		fresh = u.InputTokens
	}
	return (float64(fresh)*p.in +
		float64(u.CacheReadTokens)*p.in*0.1 +
		float64(u.OutputTokens)*p.out) / m
}
