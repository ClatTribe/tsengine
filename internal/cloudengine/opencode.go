package cloudengine

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// opencode.go is the LOCAL-PROXY brain: it drives an `opencode serve` instance over its HTTP API
// so the agents can run on whatever model the operator's opencode is configured for (including the
// free hosted tiers) WITHOUT any provider key of our own. This exists so end-to-end product tests
// can run on a competent brain at zero marginal cost — it is explicitly NOT a production path and
// NOT a substitute for the funded-key benchmark runs (ADR 0031 D3a): every number produced through
// it records THIS model id via ModelName, so a result can never impersonate a frontier run.
//
// Auth is HTTP Basic (OPENCODE_SERVER_PASSWORD on the serve side); the session is created lazily
// once per client and reused — one Generate = one message turn in that session.

// OpenCode drives an opencode serve endpoint as an LLM.
type OpenCode struct {
	baseURL   string
	user      string
	pass      string
	model     string // provider/model
	http      *http.Client
	usage     usageCounter // unknown from this seam; kept zero → TotalUsage reports zeros, callers render "unknown"
	mu        sync.Mutex
	sessionID string
}

// OpenCodeFromEnv builds the proxy when TSENGINE_LLM_OPENCODE points at a serve URL.
// TSENGINE_LLM_OPENCODE_PASSWORD (default "opencode"-user basic auth; password required by
// recent versions), TSENGINE_LLM_OPENCODE_MODEL (provider/model), and optionally
// TSENGINE_LLM_OPENCODE_AGENT override defaults.
func OpenCodeFromEnv() (*OpenCode, bool) {
	base := strings.TrimRight(strings.TrimSpace(os.Getenv("TSENGINE_LLM_OPENCODE")), "/")
	if base == "" {
		return nil, false
	}
	model := strings.TrimSpace(os.Getenv("TSENGINE_LLM_OPENCODE_MODEL"))
	if model == "" {
		model = "opencode/muse-spark-1.2-contributor-free"
	}
	return &OpenCode{
		baseURL: base,
		user:    envOr("TSENGINE_LLM_OPENCODE_USERNAME", "opencode"),
		pass:    os.Getenv("TSENGINE_LLM_OPENCODE_PASSWORD"),
		model:   model,
		http:    &http.Client{Timeout: 10 * time.Minute}, // agent turns can think long
	}, true
}

func envOr(k, def string) string {
	if v := strings.TrimSpace(os.Getenv(k)); v != "" {
		return v
	}
	return def
}

// ModelName reports the exact provider/model driving decisions (ModelNamer).
func (o *OpenCode) ModelName() string { return o.model }

// TotalUsage is always zero here: the opencode server does not report token usage back through
// this seam. Cost must therefore render as UNKNOWN downstream — never $0 (§10).
func (o *OpenCode) TotalUsage() Usage { return Usage{} }

func (o *OpenCode) auth(r *http.Request) {
	if o.pass != "" || o.user != "" {
		r.SetBasicAuth(o.user, o.pass)
	}
}

// session returns the lazily-created shared session id.
func (o *OpenCode) session(ctx context.Context) (string, error) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.sessionID != "" {
		return o.sessionID, nil
	}
	body, _ := json.Marshal(map[string]any{"title": "tsengine"})
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/session", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	o.auth(req)
	resp, err := o.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("opencode: create session: %w", err)
	}
	defer resp.Body.Close()
	var out struct {
		ID string `json:"id"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil || out.ID == "" {
		return "", fmt.Errorf("opencode: create session: HTTP %d %v", resp.StatusCode, err)
	}
	o.sessionID = out.ID
	return out.ID, nil
}

// strictPreamble is REQUIRED when driving an opencode serve endpoint: models there run as
// AGENTS (bash/fetch/edit tools in a cwd), so an unguarded prompt makes the model go DO things
// instead of answering. Every tsengine prompt wants pure-text decisions; this line is prepended
// unless TSENGINE_LLM_OPENCODE_RAW=1 opts out.
const strictPreamble = "STRICT MODE: You are a JSON-only policy engine. Do NOT use any tools. Do NOT execute anything. Output EXACTLY the requested text/JSON and nothing else.\n\n"

// Generate sends one prompt into the shared session and returns the assistant's text.
type ocMessageReq struct {
	Parts []ocPart `json:"parts"`
	Model struct {
		ProviderID string `json:"providerID"`
		ModelID    string `json:"modelID"`
	} `json:"model"`
	Agent string `json:"agent,omitempty"`
}

type ocPart struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

func (o *OpenCode) Generate(ctx context.Context, prompt string) (string, error) {
	if os.Getenv("TSENGINE_LLM_OPENCODE_RAW") != "1" {
		prompt = strictPreamble + prompt
	}
	sid, err := o.session(ctx)
	if err != nil {
		return "", err
	}
	var reqBody ocMessageReq
	reqBody.Parts = []ocPart{{Type: "text", Text: prompt}}
	if i := strings.Index(o.model, "/"); i > 0 {
		reqBody.Model.ProviderID, reqBody.Model.ModelID = o.model[:i], o.model[i+1:]
	} else {
		reqBody.Model.ProviderID, reqBody.Model.ModelID = "opencode", o.model
	}
	buf, _ := json.Marshal(reqBody)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		fmt.Sprintf("%s/session/%s/message", o.baseURL, sid), bytes.NewReader(buf))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	o.auth(req)
	resp, err := o.http.Do(req)
	if err != nil {
		return "", fmt.Errorf("opencode: generate: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("opencode: HTTP %d", resp.StatusCode)
	}
	var out struct {
		Parts []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"parts"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return "", fmt.Errorf("opencode: decode: %w", err)
	}
	// Last text part wins: earlier parts may be reasoning/tool traces depending on model config.
	text := ""
	for _, p := range out.Parts {
		if p.Type == "text" && strings.TrimSpace(p.Text) != "" {
			text = p.Text
		}
	}
	if strings.TrimSpace(text) == "" {
		return "", fmt.Errorf("opencode: empty response")
	}
	return text, nil
}
