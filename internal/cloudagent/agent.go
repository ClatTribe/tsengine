package cloudagent

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/agentloop"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Context is the agent's working memory over a pinned cloud snapshot.
type Context struct {
	Snap    *cloudgraph.Snapshot
	Prowler []types.Finding
	MaxHyp  int

	// Bridges are grounded CROSS-SURFACE entry-point hints (G2): footholds discovered on OTHER
	// surfaces (e.g. a leaked AWS key in a code repo) that correlate into THIS cloud account. They
	// tell the cloud specialist where an external attacker already has a foothold so it prioritizes
	// verifying paths FROM that principal/resource — the code→cloud wedge. Each is derived from a real
	// correlation chain (§10); the agent still must confirm every recorded issue in the graph, so a
	// bridge only widens where it LOOKS, it can never fabricate a path.
	Bridges []string

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
	// Ledger, when set, records every ReAct step into the replayable agent decision
	// ledger. Nil-safe (a nil recorder is a no-op).
	Ledger *ledger.Recorder
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
		out, err := agentloop.GenerateWithRetry(ctx, llm, buildPrompt(cc, transcript), 3)
		if err != nil {
			if cc.Summary == "" {
				cc.Summary = fmt.Sprintf("investigation stopped early after a model failure (%v); %d issue(s) confirmed so far", err, len(cc.Issues))
			}
			break
		}
		act, perr := agentloop.ParseAction(out)
		if perr != nil {
			opts.Ledger.Note("reply was not a valid JSON action: " + perr.Error())
			transcript = agentloop.AppendCapped(transcript, "OBSERVATION: your reply was not a valid JSON action ("+perr.Error()+"). Reply with exactly one JSON action.")
			continue
		}
		t, ok := reg[act.Tool]
		if !ok {
			opts.Ledger.Note(fmt.Sprintf("unknown tool %q", act.Tool))
			transcript = agentloop.AppendCapped(transcript, fmt.Sprintf("OBSERVATION: unknown tool %q. Available: %s", act.Tool, toolNames()))
			continue
		}
		cc.calls++
		obs := t.handler(cc, act.Args)
		opts.Ledger.Record(act.Thought, act.Tool, act.Args, obs)
		transcript = agentloop.AppendCapped(transcript, fmt.Sprintf("ACTION %s(%s)\nOBSERVATION: %s", act.Tool, agentloop.CompactArgs(act.Args), obs))
	}
	return &Report{Summary: cc.Summary, Issues: cc.Issues, Calls: cc.calls}, nil
}

func toolNames() string {
	var n []string
	for _, t := range tools() {
		n = append(n, t.name)
	}
	return strings.Join(n, ", ")
}
