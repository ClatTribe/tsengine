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

// OpenAICompat is a text-in/text-out LLM over the OpenAI /chat/completions protocol — the de-facto
// standard Ollama, vLLM, LM Studio, OpenRouter, and OpenAI all speak. It lets the cloud/web investigate
// agents run against a LOCAL Ollama (free, no key) for testing — the same "test it locally like Claude
// Code" path the l2 agent gets via l2.OpenAICompatClient.
//
// SECRET HANDLING mirrors Gemini: the key (if any) rides only in the Authorization header, never a URL
// or log. A local Ollama needs no key.
type OpenAICompat struct {
	apiKey  string
	model   string
	baseURL string
	local   bool
	http    *http.Client
}

var openaiishProviders = map[string]bool{
	"openai": true, "ollama": true, "openai-compat": true, "local": true, "vllm": true, "openrouter": true, "lmstudio": true,
}

// OpenAICompatFromEnv builds the client when LLM_BASE_URL is set or LLM_PROVIDER names an OpenAI-compat
// backend (set LLM_BASE_URL=http://localhost:11434/v1 + LLM_MODEL=qwen2.5 for a local Ollama). Returns
// (nil, false) otherwise so the caller falls back to Gemini / deterministic output.
func OpenAICompatFromEnv() (*OpenAICompat, bool) {
	base := strings.TrimSpace(os.Getenv("LLM_BASE_URL"))
	provider := strings.ToLower(strings.TrimSpace(os.Getenv("LLM_PROVIDER")))
	if base == "" && !openaiishProviders[provider] {
		return nil, false
	}
	if base == "" {
		base = "https://api.openai.com/v1"
	}
	base = strings.TrimRight(base, "/")
	model := strings.TrimSpace(os.Getenv("LLM_MODEL"))
	if model == "" {
		model = "gpt-4o-mini"
	}
	low := strings.ToLower(base)
	local := strings.Contains(low, "localhost") || strings.Contains(low, "127.0.0.1") || strings.Contains(low, "host.docker.internal") || strings.Contains(low, ":11434")
	return &OpenAICompat{
		apiKey:  os.Getenv("LLM_API_KEY"),
		model:   model,
		baseURL: base,
		local:   local,
		http:    &http.Client{Timeout: 300 * time.Second}, // local thinking models are slow
	}, true
}

// NewOpenAICompat builds the client from an explicit key + model + base URL (the per-tenant path — the
// customer's OWN key from the vault). Empty baseURL → OpenAI; a localhost/Ollama base → free (no key).
func NewOpenAICompat(apiKey, model, baseURL string) *OpenAICompat {
	if strings.TrimSpace(baseURL) == "" {
		baseURL = "https://api.openai.com/v1"
	}
	baseURL = strings.TrimRight(baseURL, "/")
	if strings.TrimSpace(model) == "" {
		model = "gpt-4o-mini"
	}
	low := strings.ToLower(baseURL)
	local := strings.Contains(low, "localhost") || strings.Contains(low, "127.0.0.1") || strings.Contains(low, "host.docker.internal") || strings.Contains(low, ":11434")
	return &OpenAICompat{apiKey: apiKey, model: model, baseURL: baseURL, local: local, http: &http.Client{Timeout: 300 * time.Second}}
}

// ClientFor builds a text LLM from a per-tenant provider/model/key (the §18.5 "bring your own brain" —
// each MSP/tenant can drive the agents with its own model). Supports gemini + the OpenAI-compatible
// family (openai/ollama/vllm/openrouter); returns (nil,false) for an unsupported provider so the caller
// falls back to the operator-global LLM. Anthropic in the text seam is the documented follow-on.
func ClientFor(provider, model, apiKey string) (LLM, bool) {
	switch strings.ToLower(strings.TrimSpace(provider)) {
	case "gemini", "google":
		return NewGemini(apiKey, model), true
	case "openai", "openai-compat", "ollama", "vllm", "openrouter", "lmstudio":
		return NewOpenAICompat(apiKey, model, ""), true
	default:
		return nil, false
	}
}

// LLMFromEnv selects the investigate-agent LLM from the environment: an OpenAI-compatible backend
// (LLM_BASE_URL/LLM_PROVIDER — including a LOCAL Ollama) takes precedence, else Gemini (LLM_API_KEY).
// Returns (nil, false) when neither is configured, so callers degrade to deterministic output.
func LLMFromEnv() (LLM, bool) {
	if c, ok := OpenAICompatFromEnv(); ok {
		return c, true
	}
	if g, ok := GeminiFromEnv(); ok {
		return g, true
	}
	return nil, false
}

type oaiChatReq struct {
	Model    string       `json:"model"`
	Messages []oaiChatMsg `json:"messages"`
}
type oaiChatMsg struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}
type oaiChatResp struct {
	Choices []struct {
		Message oaiChatMsg `json:"message"`
	} `json:"choices"`
}

// Generate sends one prompt and returns the model's text.
func (o *OpenAICompat) Generate(ctx context.Context, prompt string) (string, error) {
	if o.apiKey == "" && !o.local {
		return "", fmt.Errorf("openai-compat: LLM_API_KEY not set (local Ollama needs none — set LLM_BASE_URL=http://localhost:11434/v1)")
	}
	body, _ := json.Marshal(oaiChatReq{Model: o.model, Messages: []oaiChatMsg{{Role: "user", Content: prompt}}})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	if o.apiKey != "" {
		req.Header.Set("Authorization", "Bearer "+o.apiKey) // the ONLY place the key is used
	}
	resp, err := o.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("openai-compat: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("openai-compat: %s returned HTTP %d", o.model, resp.StatusCode) // status only — request carried the key
	}
	var out oaiChatResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("openai-compat: decode: %w", err)
	}
	if len(out.Choices) == 0 {
		return "", fmt.Errorf("openai-compat: empty response")
	}
	return out.Choices[0].Message.Content, nil
}
