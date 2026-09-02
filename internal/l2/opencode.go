package l2

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

// opencode.go bridges the AI SECURITY ENGINEER's tool-calling seam (l2.Client) to a
// local `opencode serve` instance — the same keyless proxy the pentester uses, adapted
// to a DIFFERENT protocol contract. The pentester speaks text-JSON ReAct; the Lead
// expects native tool_calls. opencode offers neither an OpenAI-compat endpoint nor
// native function-calling (its /v1/chat/completions path serves an SPA catch-all), so
// this client implements tool-calling PROMPT-SIDE:
//
//   - tools are rendered into the prompt as a JSON catalog,
//   - the model replies {"tool":name,"args":{...}} or {"text":"..."},
//   - Generate parses that reply into Response.ToolCalls for the agent loop.
//
// Two disciplines make this trustworthy rather than hopeful:
//   - STRICT preamble: models behind opencode run as agents with their own tools;
//     without the JSON-only/no-tools instruction they go DO things instead of
//     answering (measured failure).
//   - FRESH session per Generate: the full conversation is already carried in the
//     prompt, so server-side session continuity only adds unbounded context growth.
//     A new session per call keeps each turn independent and deterministic.
//
// Usage is unknown through this seam → zeros → downstream renders cost as UNKNOWN,
// never $0 (§10). Model id rides Model() so results always name their brain.

type OpenCodeClient struct {
	baseURL   string
	user      string
	pass      string
	model     string
	ctxWindow int
	http      *http.Client
}

// NewOpenCodeClient builds the bridge. ctxWindow <= 0 defaults to 128_000 — a
// conservative guess, overridable via TSENGINE_LLM_OPENCODE_CTX because compaction
// triggers off it and a wrong guess degrades long triages silently.
func NewOpenCodeClient(baseURL, user, pass, model string) *OpenCodeClient {
	cw := 128_000
	if v := os.Getenv("TSENGINE_LLM_OPENCODE_CTX"); v != "" {
		if n := parseIntEnv(v); n > 0 {
			cw = n
		}
	}
	return &OpenCodeClient{
		baseURL:   strings.TrimRight(baseURL, "/"),
		user:      orStr(user, "opencode"),
		pass:      pass,
		model:     model,
		ctxWindow: cw,
		http:      &http.Client{Timeout: 15 * time.Minute},
	}
}

// OpenCodeClientFromEnv builds when TSENGINE_LLM_OPENCODE points at a serve URL.
func OpenCodeClientFromEnv() *OpenCodeClient {
	base := strings.TrimSpace(os.Getenv("TSENGINE_LLM_OPENCODE"))
	if base == "" {
		return nil
	}
	model := os.Getenv("TSENGINE_LLM_OPENCODE_MODEL")
	if model == "" {
		model = "opencode/hy3-free"
	}
	return NewOpenCodeClient(base, os.Getenv("TSENGINE_LLM_OPENCODE_USERNAME"), os.Getenv("TSENGINE_LLM_OPENCODE_PASSWORD"), model)
}

func (o *OpenCodeClient) Model() string      { return o.model }
func (o *OpenCodeClient) ContextWindow() int { return o.ctxWindow }

func (o *OpenCodeClient) auth(r *http.Request) { r.SetBasicAuth(o.user, o.pass) }

func (o *OpenCodeClient) postJSON(ctx context.Context, path string, body any) ([]byte, error) {
	buf, _ := json.Marshal(body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+path, bytes.NewReader(buf))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	o.auth(req)
	resp, err := o.http.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	var out bytes.Buffer
	if _, err := out.ReadFrom(resp.Body); err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("opencode: HTTP %d: %s", resp.StatusCode, truncateRunes(out.String(), 200))
	}
	return out.Bytes(), nil
}

func (o *OpenCodeClient) newSession(ctx context.Context) (string, error) {
	out, err := o.postJSON(ctx, "/session", map[string]any{"title": "tsengine-lead"})
	if err != nil {
		return "", fmt.Errorf("opencode: session: %w", err)
	}
	var s struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(out, &s); err != nil || s.ID == "" {
		return "", fmt.Errorf("opencode: session: no id in %s", truncateRunes(string(out), 120))
	}
	return s.ID, nil
}

const ocStrict = "STRICT MODE: You are a JSON-only decision engine. Do NOT use any tools yourself. Do NOT execute anything. Reply with EXACTLY one JSON object and nothing else.\n\n"

func (o *OpenCodeClient) renderTools(tools []ToolSchema) string {
	if len(tools) == 0 {
		return "No tools are available this turn."
	}
	var b strings.Builder
	b.WriteString("AVAILABLE TOOLS (you may call AT MOST ONE per turn):\n")
	for _, t := range tools {
		params, _ := json.Marshal(t.Params)
		fmt.Fprintf(&b, "- %s: %s\n  params: %s\n", t.Name, t.Description, params)
	}
	return b.String()
}

func (o *OpenCodeClient) renderHistory(history []Message) string {
	var b strings.Builder
	for _, m := range history {
		switch m.Role {
		case RoleUser:
			fmt.Fprintf(&b, "USER: %s\n", m.Content)
		case RoleAssistant:
			if len(m.ToolCalls) > 0 {
				for _, tc := range m.ToolCalls {
					args, _ := json.Marshal(tc.Args)
					fmt.Fprintf(&b, "ASSISTANT ACTION: {\"tool\":%q,\"args\":%s}\n", tc.Name, args)
				}
			}
			if strings.TrimSpace(m.Content) != "" {
				fmt.Fprintf(&b, "ASSISTANT: %s\n", m.Content)
			}
		case RoleTool:
			content := m.Content
			if len(content) > 1500 {
				content = content[:1500] + "…[truncated]"
			}
			fmt.Fprintf(&b, "TOOL_RESULT(%s): %s\n", m.ToolCallID, content)
		}
	}
	return b.String()
}

func (o *OpenCodeClient) Generate(ctx context.Context, system string, history []Message, tools []ToolSchema) (Response, error) {
	sid, err := o.newSession(ctx)
	if err != nil {
		return Response{}, err
	}
	prompt := ocStrict +
		"SYSTEM ROLE:\n" + system + "\n\n" +
		o.renderTools(tools) + "\nCONVERSATION:\n" + o.renderHistory(history) +
		"\nReply NOW with EXACTLY one JSON object:\n" +
		`{"tool":"<tool name from the list>","args":{...}}` + "\nor, to finish:\n" +
		`{"text":"<your final answer>"}` + "\n" +
		"If you intend to call finish_scan or similar terminal tools listed above, use their real name in \"tool\"."
	body := map[string]any{
		"parts": []map[string]string{{"type": "text", "text": prompt}},
		"model": map[string]string{"providerID": providerOf(o.model), "modelID": modelID(o.model)},
		"agent": os.Getenv("TSENGINE_LLM_OPENCODE_AGENT"),
	}
	delete(body, "agent") // default build agent; env opt-in later if a profile proves better
	out, err := o.postJSON(ctx, "/session/"+sid+"/message", body)
	if err != nil {
		return Response{}, fmt.Errorf("opencode: generate: %w", err)
	}
	var msg struct {
		Parts []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"parts"`
	}
	if err := json.Unmarshal(out, &msg); err != nil {
		return Response{}, fmt.Errorf("opencode: decode: %w", err)
	}
	text := ""
	for _, p := range msg.Parts {
		if p.Type == "text" && strings.TrimSpace(p.Text) != "" {
			text = p.Text
		}
	}
	if strings.TrimSpace(text) == "" {
		return Response{}, fmt.Errorf("opencode: empty response (model refused or produced only tool noise)")
	}

	// Parse the JSON-only contract: {"tool","args"} → ToolCalls; {"text"} → Text.
	cleaned := strings.TrimSpace(text)
	if strings.HasPrefix(cleaned, "```") {
		if i := strings.IndexByte(cleaned, '\n'); i >= 0 {
			cleaned = cleaned[i+1:]
		}
		cleaned = strings.TrimSuffix(strings.TrimSpace(cleaned), "```")
	}
	if i := strings.IndexByte(cleaned, '{'); i > 0 {
		cleaned = cleaned[i:]
	}
	if j := strings.LastIndexByte(cleaned, '}'); j >= 0 {
		cleaned = cleaned[:j+1]
	}
	if i := strings.IndexByte(cleaned, '{'); i > 0 {
		cleaned = cleaned[i:]
	}
	var parsed struct {
		Tool string         `json:"tool"`
		Args map[string]any `json:"args"`
		Text string         `json:"text"`
	}
	if err := json.Unmarshal([]byte(cleaned), &parsed); err == nil {
		if parsed.Tool != "" {
			if parsed.Args == nil {
				parsed.Args = map[string]any{}
			}
			return Response{
				ToolCalls:  []ToolCall{{ID: "call_1", Name: parsed.Tool, Args: parsed.Args}},
				StopReason: "tool_use",
			}, nil
		}
		if strings.TrimSpace(parsed.Text) != "" {
			return Response{Text: parsed.Text, StopReason: "stop"}, nil
		}
	}
	// Not our JSON contract — treat the whole reply as final text (the agent loop's
	// no-tool-call path handles prose by nudging; we never fabricate tool calls from prose).
	return Response{Text: text, StopReason: "stop"}, nil
}

func providerOf(model string) string {
	if i := strings.IndexByte(model, '/'); i > 0 {
		return model[:i]
	}
	return "opencode"
}

func modelID(model string) string {
	if i := strings.IndexByte(model, '/'); i >= 0 {
		return model[i+1:]
	}
	return model
}

func truncateRunes(s string, n int) string {
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n]) + "…"
}

func parseIntEnv(v string) int {
	n := 0
	for _, c := range v {
		if c < '0' || c > '9' {
			return 0
		}
		n = n*10 + int(c-'0')
	}
	return n
}

func orStr(v, def string) string {
	if strings.TrimSpace(v) != "" {
		return v
	}
	return def
}
