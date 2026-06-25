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

// LLM is the minimal text-in/text-out interface the L2 translator pass needs.
// Keeping it behind an interface lets CI run with a scripted mock (no key) and
// the real Gemini client plug in at runtime.
type LLM interface {
	Generate(ctx context.Context, prompt string) (string, error)
}

// Gemini is a minimal Google Generative Language (Gemini) client.
//
// SECRET HANDLING: the API key is read from the LLM_API_KEY env var at runtime
// and sent ONLY in the x-goog-api-key request header — never in a URL, a log
// line, an error message, or anything written to disk. There is no literal key
// anywhere in the code.
type Gemini struct {
	apiKey string // from os.Getenv("LLM_API_KEY") — never logged
	model  string
	http   *http.Client
}

// GeminiFromEnv builds a Gemini client from the environment. Returns
// (client, true) when LLM_API_KEY is set, else (nil, false) so callers can fall
// back to the deterministic output (graceful — CI has no key). The model comes
// from STRIX_LLM ("[provider/]model", litellm-style), defaulting to a flash model.
func GeminiFromEnv() (*Gemini, bool) {
	key := os.Getenv("LLM_API_KEY")
	if key == "" {
		return nil, false
	}
	model := os.Getenv("STRIX_LLM")
	if i := strings.LastIndex(model, "/"); i >= 0 {
		model = model[i+1:] // strip the "gemini/" provider prefix
	}
	if model == "" {
		model = "gemini-2.0-flash"
	}
	return &Gemini{apiKey: key, model: model, http: &http.Client{Timeout: 90 * time.Second}}, true
}

// NewGemini builds a Gemini client from an explicit key + model (the per-tenant path — the customer's
// OWN key, opened from the vault, not the env). Empty model → a current flash default.
func NewGemini(apiKey, model string) *Gemini {
	if strings.TrimSpace(model) == "" {
		model = "gemini-2.0-flash"
	}
	return &Gemini{apiKey: apiKey, model: model, http: &http.Client{Timeout: 90 * time.Second}}
}

type geminiReq struct {
	Contents         []geminiContent `json:"contents"`
	GenerationConfig geminiGenCfg    `json:"generationConfig"`
}
type geminiContent struct {
	Parts []geminiPart `json:"parts"`
}
type geminiPart struct {
	Text string `json:"text"`
}
type geminiGenCfg struct {
	Temperature      float64 `json:"temperature"`
	ResponseMIMEType string  `json:"responseMimeType,omitempty"`
}
type geminiResp struct {
	Candidates []struct {
		Content geminiContent `json:"content"`
	} `json:"candidates"`
}

// Generate sends one prompt and returns the model's text. The key rides in the
// x-goog-api-key header; the endpoint URL carries no secret, so it is safe to
// include in an error.
func (g *Gemini) Generate(ctx context.Context, prompt string) (string, error) {
	url := fmt.Sprintf("https://generativelanguage.googleapis.com/v1beta/models/%s:generateContent", g.model)
	body, _ := json.Marshal(geminiReq{
		Contents:         []geminiContent{{Parts: []geminiPart{{Text: prompt}}}},
		GenerationConfig: geminiGenCfg{Temperature: 0.2, ResponseMIMEType: "application/json"},
	})
	//nolint:gosec // G107: URL host is the fixed Gemini endpoint; only the model
	// path segment varies (from the STRIX_LLM env var, not a finding/target).
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("x-goog-api-key", g.apiKey) // the ONLY place the key is used on the wire

	resp, err := g.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("gemini: request failed: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// status only — never echo the request (it carried the key header).
		return "", fmt.Errorf("gemini: %s returned HTTP %d", g.model, resp.StatusCode)
	}
	var out geminiResp
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("gemini: decode: %w", err)
	}
	if len(out.Candidates) == 0 || len(out.Candidates[0].Content.Parts) == 0 {
		return "", fmt.Errorf("gemini: empty response")
	}
	return out.Candidates[0].Content.Parts[0].Text, nil
}
