package cloudagent

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Context is the agent's working memory over a pinned cloud snapshot.
type Context struct {
	Snap    *cloudgraph.Snapshot
	Prowler []types.Finding
	MaxHyp  int

	Issues  []Issue
	Summary string
	Done    bool

	issueN int
	calls  int
}

// Issue is one attack path the LLM determined AND the graph confirmed (grounded).
type Issue struct {
	ID          string   `json:"id"`
	Target      string   `json:"target"`
	TargetName  string   `json:"target_name"`
	Path        []string `json:"path"`
	Severity    string   `json:"severity,omitempty"`
	Rationale   string   `json:"rationale,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`
	Remediation string   `json:"remediation,omitempty"`
	FixKind     string   `json:"fix_kind,omitempty"`
	FixContent  string   `json:"fix_content,omitempty"`
	FixVerified bool     `json:"fix_verified,omitempty"`
}

// Report is the agent's output.
type Report struct {
	Summary string  `json:"summary"`
	Issues  []Issue `json:"issues"`
	Calls   int     `json:"tool_calls"`
}

// Options bounds the agent loop.
type Options struct {
	MaxIters int // tool-call turns before the loop is force-closed
	MaxHyp   int // worklist budget for the enumerate_attack_paths prepass tool
}

// Investigate runs the LLM-as-brain loop (the VulnAgent shape): the model reads
// the account summary, calls tools to access + assess resources, determines real
// attack paths, records the grounded ones, proposes fixes, and finishes. The LLM
// reasons; the tools answer precisely and refuse ungrounded claims.
func Investigate(ctx context.Context, llm cloudengine.LLM, cc *Context, opts Options) (*Report, error) {
	if opts.MaxIters <= 0 {
		opts.MaxIters = 28
	}
	if opts.MaxHyp <= 0 {
		opts.MaxHyp = 60
	}
	cc.MaxHyp = opts.MaxHyp
	reg := map[string]toolDef{}
	for _, t := range tools() {
		reg[t.name] = t
	}

	var transcript []string
	for i := 0; i < opts.MaxIters && !cc.Done; i++ {
		// A long-horizon agent makes many sequential model calls; a single
		// transient LLM failure must not abort the whole investigation. Retry
		// the turn a few times, then return the partial result we have.
		out, err := generateWithRetry(ctx, llm, buildPrompt(cc, transcript), 3)
		if err != nil {
			if cc.Summary == "" {
				cc.Summary = fmt.Sprintf("investigation stopped early after a model failure (%v); %d issue(s) confirmed so far", err, len(cc.Issues))
			}
			break
		}
		act, perr := parseAction(out)
		if perr != nil {
			transcript = appendCapped(transcript, "OBSERVATION: your reply was not a valid JSON action ("+perr.Error()+"). Reply with exactly one JSON action.")
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
	return &Report{Summary: cc.Summary, Issues: cc.Issues, Calls: cc.calls}, nil
}

// generateWithRetry calls the model, retrying on transient failures (network
// timeouts, 5xx). Returns the last error if all attempts fail.
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

// action is the JSON the model emits each turn.
type action struct {
	Thought string         `json:"thought"`
	Tool    string         `json:"tool"`
	Args    map[string]any `json:"args"`
}

func parseAction(s string) (action, error) {
	s = stripFences(s)
	// be lenient: find the first {...} block.
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
		// also accept {"action":{"tool":...}}
		var wrap struct {
			Thought string `json:"thought"`
			Action  action `json:"action"`
		}
		if err := json.Unmarshal([]byte(s), &wrap); err == nil && wrap.Action.Tool != "" {
			wrap.Action.Thought = wrap.Thought
			return wrap.Action, nil
		}
		return a, fmt.Errorf("no tool named")
	}
	return a, nil
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

// appendCapped keeps the transcript bounded so the prompt can't grow unbounded.
func appendCapped(t []string, entry string) []string {
	if len(entry) > 1800 {
		entry = entry[:1800] + " …(truncated)"
	}
	t = append(t, entry)
	const keep = 24
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
