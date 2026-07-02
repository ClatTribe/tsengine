package cloudengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

// Anthropic is a minimal Claude Messages API client — the frontier-model backend for the L2 agents
// (web-investigate / cloud-investigate / pentest ModeDeep). The engine already speaks OpenAI-compat
// (Ollama, etc.) + Gemini; this adds native Claude so `tsbench` / the agents can run on a frontier
// brain with one env var.
//
// SECRET HANDLING (mirrors gemini.go): the key is read from ANTHROPIC_API_KEY at runtime and sent
// ONLY in the x-api-key header — never in a URL, log, error, or on disk. No literal key in code.
type Anthropic struct {
	apiKey  string // from ANTHROPIC_API_KEY — never logged
	model   string
	baseURL string
	http    *http.Client
}

// AnthropicFromEnv builds a Claude client when ANTHROPIC_API_KEY is set, else (nil, false) so callers
// fall through to the next backend. Model from ANTHROPIC_MODEL (default a current Sonnet — override
// for Opus); base URL from ANTHROPIC_BASE_URL (default the public API). NOTE: a Claude Max/Pro
// subscription is NOT an API key — this needs console.anthropic.com API access (separately billed).
func AnthropicFromEnv() (*Anthropic, bool) {
	key := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
	if key == "" {
		return nil, false
	}
	model := strings.TrimSpace(os.Getenv("ANTHROPIC_MODEL"))
	base := strings.TrimSpace(os.Getenv("ANTHROPIC_BASE_URL"))
	return NewAnthropic(key, model, base), true
}

// NewAnthropic builds a client from an explicit key + model + base (the per-tenant path — the
// customer's OWN key from the vault). Empty model → a current Sonnet default; empty base → the API.
func NewAnthropic(apiKey, model, baseURL string) *Anthropic {
	if strings.TrimSpace(model) == "" {
		model = "claude-sonnet-4-5" // capable default; ANTHROPIC_MODEL overrides (e.g. an Opus id)
	}
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "https://api.anthropic.com"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	// The agent loop is long-horizon; give each call a generous ceiling (matches the OpenAI-compat client).
	return &Anthropic{apiKey: apiKey, model: model, baseURL: baseURL, http: &http.Client{Timeout: 300 * time.Second}}
}

type anthropicReq struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	Messages  []anthropicMessage `json:"messages"`
}
type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type anthropicResp struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
}

// Generate sends one prompt and returns Claude's text. The key rides in the x-api-key header; the
// endpoint URL carries no secret, so it is safe to include in an error.
func (a *Anthropic) Generate(ctx context.Context, prompt string) (string, error) {
	body, _ := json.Marshal(anthropicReq{
		Model:     a.model,
		MaxTokens: 4096,
		Messages:  []anthropicMessage{{Role: "user", Content: prompt}},
	})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, a.baseURL+"/v1/messages", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-api-key", a.apiKey) // the ONLY place the key is used on the wire
	req.Header.Set("anthropic-version", "2023-06-01")

	resp, err := a.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("anthropic: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("anthropic: %s returned HTTP %d", a.model, resp.StatusCode) // status only — the request carried the key
	}
	var out anthropicResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("anthropic: decode: %w", err)
	}
	for _, c := range out.Content { // concatenate text blocks (skip any non-text/thinking block)
		if c.Type == "text" {
			return c.Text, nil
		}
	}
	return "", fmt.Errorf("anthropic: empty response")
}
