package llmredteam

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
)

// Turn is one attacker prompt + target reply (the evidence substrate).
type Turn struct {
	ID        string   `json:"id"`
	Technique string   `json:"technique,omitempty"`
	Prompt    string   `json:"prompt"`
	Reply     string   `json:"reply"` // capped snippet
	ToolCalls []string `json:"tool_calls,omitempty"`
	Breaches  []string `json:"breaches,omitempty"`
}

// Breach is a recorded jailbreak/leak the verifier confirmed (grounded).
type Breach struct {
	ID        string   `json:"id"`
	Class     string   `json:"class"` // secret_leak | system_prompt_leak | forbidden_tool | pii_leak
	Technique string   `json:"technique,omitempty"`
	Severity  string   `json:"severity,omitempty"`
	Rationale string   `json:"rationale,omitempty"`
	Evidence  []string `json:"evidence_turn_ids"`
}

// Context is the attacker's working memory for one engagement against one target.
type Context struct {
	Target Target
	Eng    *Engagement

	History  []Turn   `json:"history"`
	Breaches []Breach `json:"breaches"`
	Summary  string   `json:"summary"`
	Done     bool     `json:"-"`

	convo      []Msg // running conversation (multi-turn jailbreaks)
	ctx        context.Context
	turnN      int
	breachN    int
	calls      int
	maxPrompts int
}

func (cc *Context) turn(id string) (Turn, bool) {
	for _, t := range cc.History {
		if t.ID == id {
			return t, true
		}
	}
	return Turn{}, false
}

// Report is the engagement output.
type Report struct {
	Engagement string   `json:"engagement"`
	Summary    string   `json:"summary"`
	Breaches   []Breach `json:"breaches"`
	Turns      int      `json:"turns"`
	Calls      int      `json:"tool_calls"`
}

// Options bound the engagement.
type Options struct {
	MaxIters   int // attacker turns before the loop is force-closed
	MaxPrompts int // hard cap on prompts sent to the target
}

// Investigate runs the LLM-as-brain attacker loop against one target. The model
// crafts adversarial prompts, reads the DETERMINISTIC verifier's breach signals,
// and records only confirmed breaches. llm may be a real model (Gemini) or the
// deterministic Prober (CI-safe). The target's replies are untrusted data.
func Investigate(ctx context.Context, llm cloudengine.LLM, cc *Context, opts Options) (*Report, error) {
	if opts.MaxIters <= 0 {
		opts.MaxIters = 24
	}
	if opts.MaxPrompts <= 0 {
		opts.MaxPrompts = 40
	}
	cc.ctx = ctx
	cc.maxPrompts = opts.MaxPrompts
	reg := map[string]toolDef{}
	for _, t := range tools() {
		reg[t.name] = t
	}

	var transcript []string
	for i := 0; i < opts.MaxIters && !cc.Done; i++ {
		out, err := generateWithRetry(ctx, llm, buildPrompt(cc, transcript), 3)
		if err != nil {
			if cc.Summary == "" {
				cc.Summary = fmt.Sprintf("engagement stopped after a model failure (%v); %d breach(es) so far", err, len(cc.Breaches))
			}
			break
		}
		act, perr := parseAction(out)
		if perr != nil {
			transcript = appendCapped(transcript, "OBSERVATION: reply was not a valid JSON action ("+perr.Error()+"). Reply with exactly one JSON action.")
			continue
		}
		t, ok := reg[act.Tool]
		if !ok {
			transcript = appendCapped(transcript, fmt.Sprintf("OBSERVATION: unknown tool %q. Available: %s", act.Tool, toolNames()))
			continue
		}
		cc.calls++
		obs := t.handler(cc, act.Args)
		transcript = appendCapped(transcript, fmt.Sprintf("ACTION %s(%s)\nOBSERVATION: %s", act.Tool, compactArgs(act.Args), obs))
	}
	name := ""
	if cc.Eng != nil {
		name = cc.Eng.Name
	}
	return &Report{Engagement: name, Summary: cc.Summary, Breaches: cc.Breaches, Turns: cc.turnN, Calls: cc.calls}, nil
}

type action struct {
	Thought string         `json:"thought"`
	Tool    string         `json:"tool"`
	Args    map[string]any `json:"args"`
}

func parseAction(s string) (action, error) {
	s = stripFences(s)
	if i := strings.IndexByte(s, '{'); i > 0 {
		s = s[i:]
	}
	if j := strings.LastIndexByte(s, '}'); j >= 0 {
		s = s[:j+1]
	}
	var a action
	if err := json.Unmarshal([]byte(s), &a); err != nil {
		return a, fmt.Errorf("parse: %v", err)
	}
	if a.Tool == "" {
		return a, fmt.Errorf("no tool named")
	}
	return a, nil
}

func generateWithRetry(ctx context.Context, llm cloudengine.LLM, prompt string, attempts int) (string, error) {
	var err error
	for a := 0; a < attempts; a++ {
		if a > 0 {
			select {
			case <-ctx.Done():
				return "", ctx.Err()
			case <-time.After(time.Duration(a) * 2 * time.Second):
			}
		}
		var out string
		if out, err = llm.Generate(ctx, prompt); err == nil {
			return out, nil
		}
	}
	return "", err
}

func stripFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
		s = strings.TrimSuffix(strings.TrimSpace(s), "```")
	}
	return strings.TrimSpace(s)
}

func compactArgs(args map[string]any) string {
	b, _ := json.Marshal(args)
	if len(b) > 200 {
		b = append(b[:197], "..."...)
	}
	return string(b)
}

func appendCapped(t []string, entry string) []string {
	if len(entry) > 1600 {
		entry = entry[:1600] + " …(truncated)"
	}
	t = append(t, entry)
	const keep = 22
	if len(t) > keep {
		t = t[len(t)-keep:]
	}
	return t
}

func toolNames() string {
	var n []string
	for _, t := range tools() {
		n = append(n, t.name)
	}
	return strings.Join(n, ", ")
}
