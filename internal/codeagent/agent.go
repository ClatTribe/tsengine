// Package codeagent is the AI Code Security Engineer as an LLM AGENT — the code-half twin of
// internal/cloudagent (the VulnAgent shape, CLAUDE.md §10). Cloud has a depth specialist that reasons over
// the IAM/reachability graph; CODE had none — the L2 Lead read code findings as unified-issue DIGESTS and
// could not open a source file, trace a tainted value from source to sink, or compute a leaked secret's
// blast radius. This is that missing specialist: the model is the brain, and deterministic tools over the
// repository source (read_source, grep_code, trace_secret) are its HANDS. It refuses to record an assessment
// the source doesn't support (evidence grounding, §10 — the anti-hallucination guard): every recorded issue
// must cite a real file:line the SourceProvider actually produced.
//
// The SourceProvider is the honest boundary (like cloudagent's posted snapshot): in tests it's an in-memory
// map; in prod it's backed by the connected repo (GitHub file-contents API / a stored scan checkout). The
// agent + tools + grounding are pure and testable; the live source fetch is the credential-gated half.
package codeagent

import (
	"context"
	"fmt"
	"strings"

	"github.com/ClatTribe/tsengine/internal/agentloop"
	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// GrepHit is one match from a source search.
type GrepHit struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Text string `json:"text"`
}

// SourceProvider is the agent's read-only access to the repository under investigation — its "hands" over
// the code. All methods are deterministic; a real (non-empty) return is what grounds a recorded issue. The
// context is honored (§15/§5.2-C3): a cancelled scan cancels in-flight live fetches.
type SourceProvider interface {
	// ReadFile returns the lines [startLine,endLine] (1-indexed, inclusive) of path, or the whole file when
	// endLine<=0. An unknown path returns an error (so the agent cannot cite source that doesn't exist).
	ReadFile(ctx context.Context, path string, startLine, endLine int) (string, error)
	// Grep returns up to maxHits matches of a plain substring (case-sensitive) across the tree.
	Grep(ctx context.Context, pattern string, maxHits int) ([]GrepHit, error)
	// Files lists the known source paths (for orientation).
	Files() []string
}

// Context is the agent's working memory over the code findings + the repo source.
type Context struct {
	Findings []types.Finding // the code findings under investigation (semgrep/gitleaks/trivy — file:line endpoints)
	Source   SourceProvider  // read-only access to the repo (the grounding oracle)
	Repo     string          // display name of the repository

	Issues  []CodeIssue
	Summary string
	Done    bool

	ctx    context.Context // the investigation context — threaded to Source so live fetches are cancellable
	issueN int
	calls  int
}

// CodeIssue is one finding the agent DETERMINED (exploitable or not) AND grounded in real source it read.
type CodeIssue struct {
	ID          string   `json:"id"`
	FindingID   string   `json:"finding_id"` // the L1 finding this assesses
	Title       string   `json:"title"`
	Severity    string   `json:"severity,omitempty"` // the agent's re-assessed severity (may differ from the tool's)
	Exploitable bool     `json:"exploitable"`        // the grounded determination (is it actually reachable/exploitable)
	Rationale   string   `json:"rationale,omitempty"`
	Evidence    []string `json:"evidence,omitempty"`     // cited "path:line" locations the agent read (grounding)
	BlastRadius string   `json:"blast_radius,omitempty"` // what it reaches (a secret's usage, the data a sink touches)
	FixLocation string   `json:"fix_location,omitempty"` // where the fix belongs (often a DIFFERENT layer than the finding)
	Fix         string   `json:"fix,omitempty"`
}

// Report is the agent's output.
type Report struct {
	Summary string      `json:"summary"`
	Issues  []CodeIssue `json:"issues"`
	Calls   int         `json:"tool_calls"`
}

// Options bounds the agent loop.
type Options struct {
	MaxIters int              // tool-call turns before the loop is force-closed
	Ledger   *ledger.Recorder // optional: records every ReAct step (nil-safe)
}

// Investigate runs the LLM-as-brain loop over the code: the model reads the finding list, opens source with
// read_source, traces flows with grep_code / trace_secret, determines whether each finding is really
// exploitable + its blast radius + the right fix location, records the grounded ones, and finishes. The LLM
// reasons; the tools answer precisely and REFUSE to let it record an issue the source doesn't support.
func Investigate(ctx context.Context, llm cloudengine.LLM, cc *Context, opts Options) (*Report, error) {
	if opts.MaxIters <= 0 {
		opts.MaxIters = 24
	}
	cc.ctx = ctx // threaded to the SourceProvider so live fetches honor the scan deadline/cancel
	reg := map[string]toolDef{}
	for _, t := range tools() {
		reg[t.name] = t
	}

	var transcript []string
	for i := 0; i < opts.MaxIters && !cc.Done; i++ {
		out, err := agentloop.GenerateWithRetry(ctx, llm, buildPrompt(cc, transcript), 3)
		if err != nil {
			if cc.Summary == "" {
				cc.Summary = fmt.Sprintf("code investigation stopped early after a model failure (%v); %d issue(s) grounded so far", err, len(cc.Issues))
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
