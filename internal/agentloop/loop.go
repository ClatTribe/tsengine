// Package agentloop holds the shared ReAct machinery for the LLM depth specialists (cloudagent, codeagent):
// the one-JSON-action protocol, the lenient action parser, the transient-failure retry, and the bounded
// transcript. Both agents drive a model over the same cloudengine.LLM interface and differ only in their
// TOOLS and working memory — so this pure, dependency-light spine is factored out here to be fixed once
// rather than mirror-copied (the review flagged the two verbatim copies as a drift risk). No agent-specific
// state lives here.
package agentloop

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/llmretry"
)

// Action is the single JSON action a model emits each turn: a thought, the tool to call, and its args.
type Action struct {
	Thought string         `json:"thought"`
	Tool    string         `json:"tool"`
	Args    map[string]any `json:"args"`
}

// GenerateWithRetry calls the model, retrying transient failures (network/5xx) with a linear backoff, and
// failing fast on a permanent fault (bad request / auth) that won't succeed on retry. Honors ctx cancel.
func GenerateWithRetry(ctx context.Context, llm cloudengine.LLM, prompt string, attempts int) (string, error) {
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
		if !llmretry.IsTransient(err) {
			return "", err
		}
	}
	return "", err
}

// ParseAction extracts the single JSON action from a model reply, leniently: it strips code fences, finds the
// first {…} block, and also accepts a {"action":{…}} wrapper. Returns an error when no tool is named.
func ParseAction(s string) (Action, error) {
	s = StripFences(s)
	if i := strings.IndexByte(s, '{'); i > 0 {
		s = s[i:]
	}
	if j := strings.LastIndexByte(s, '}'); j >= 0 {
		s = s[:j+1]
	}
	var a Action
	if err := json.Unmarshal([]byte(s), &a); err != nil {
		return a, fmt.Errorf("parse: %v", err)
	}
	if a.Tool == "" {
		var wrap struct {
			Thought string `json:"thought"`
			Action  Action `json:"action"`
		}
		if err := json.Unmarshal([]byte(s), &wrap); err == nil && wrap.Action.Tool != "" {
			wrap.Action.Thought = wrap.Thought
			return wrap.Action, nil
		}
		return a, fmt.Errorf("no tool named")
	}
	return a, nil
}

// StripFences removes a leading ```lang fence and trailing ``` from a model reply.
func StripFences(s string) string {
	s = strings.TrimSpace(s)
	if strings.HasPrefix(s, "```") {
		if i := strings.IndexByte(s, '\n'); i >= 0 {
			s = s[i+1:]
		}
		s = strings.TrimSuffix(strings.TrimSpace(s), "```")
	}
	return strings.TrimSpace(s)
}

// transcriptEntryCap bounds one transcript entry; transcriptEntryTail is how much of the END is
// preserved verbatim, because a tool result's actionable half (what is left to do, what to call
// next) is written last.
const (
	transcriptEntryCap  = 1800
	transcriptEntryTail = 700
)

// CompactArgs renders an action's args as compact JSON, truncated for the transcript.
func CompactArgs(args map[string]any) string {
	b, _ := json.Marshal(args)
	if len(b) > 200 {
		b = append(b[:197], "..."...)
	}
	return string(b)
}

// AppendCapped adds an entry to a transcript, truncating an over-long entry and keeping only the most recent
// entries so the prompt can't grow unbounded over a long-horizon run.
func AppendCapped(t []string, entry string) []string {
	// HEAD+TAIL, not head-only (the webagent precedent, browser.go/dispatch.go). A tool
	// observation puts its most ACTIONABLE content LAST: the coverage disclosure naming which
	// crown jewels nobody examined, the "REMAINING: N still unexamined" countdown, the
	// "Consider propose_fix(ai-001)" hint. A head-only cut destroys precisely those and leaves
	// the bulk listing that the agent least needs. Measured live on a 908-resource account: the
	// prepass observation was cut at "COVERAGE: this prepass is a BOUNDED wor …(truncated)", so
	// the agent never saw the jewels it was being told to check — the disclosure was computed,
	// rendered, and then thrown away one layer later.
	if len(entry) > transcriptEntryCap {
		head := transcriptEntryCap - transcriptEntryTail
		entry = entry[:head] +
			fmt.Sprintf(" …[%d bytes elided]… ", len(entry)-head-transcriptEntryTail) +
			entry[len(entry)-transcriptEntryTail:]
	}
	t = append(t, entry)
	const keep = 24
	if len(t) > keep {
		t = t[len(t)-keep:]
	}
	return t
}
