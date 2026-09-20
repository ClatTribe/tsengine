package webagent

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// scriptedLLM returns the queued (reply, err) pairs in order, then repeats the last reply forever.
type scriptedLLM struct {
	steps []step
	i     int
}
type step struct {
	reply string
	err   error
}

func (s *scriptedLLM) Generate(_ context.Context, _ string) (string, error) {
	st := s.steps[s.i]
	if s.i < len(s.steps)-1 {
		s.i++
	}
	return st.reply, st.err
}

func finishAction(summary string) string {
	return `{"thought":"done","tool":"finish","args":{"summary":"` + summary + `"}}`
}

// A transient throttle in the middle of an engagement must NOT end it: the loop notes the hiccup and
// keeps going to a clean finish. This is Finding 1 — before the fix a single model_error broke the
// whole run and the autopsy read it as a capability miss.
func TestInvestigate_ContinuesThroughTransientThrottle(t *testing.T) {
	old := retryBackoffUnit
	retryBackoffUnit = time.Millisecond
	defer func() { retryBackoffUnit = old }()

	// The first turn's generateWithRetry burns its 3 internal attempts on a transient (HTTP 503 —
	// the real client format), the outer loop continues, and the next turn finishes cleanly.
	llm := &scriptedLLM{steps: []step{
		{err: errors.New("opencode: HTTP 503")},
		{err: errors.New("opencode: HTTP 503")},
		{err: errors.New("opencode: HTTP 503")},
		{reply: finishAction("clean")},
	}}
	cc := &Context{Target: "http://127.0.0.1:1"}
	rep, err := Investigate(context.Background(), llm, cc, Options{MaxIters: 10, MaxRequests: 5})
	if err != nil {
		t.Fatalf("Investigate returned error: %v", err)
	}
	if rep.Coverage.StopReason != "completed" {
		t.Fatalf("stop reason = %q, want completed (a transient must not end the run)", rep.Coverage.StopReason)
	}
}

// A PERMANENT error (401) must fail fast — no retries, run ends model_error. Before the root-cause
// fix a 5xx was ALSO (wrongly) permanent; that regression is covered by llmretry's own test.
func TestInvestigate_FailsFastOnPermanent(t *testing.T) {
	old := retryBackoffUnit
	retryBackoffUnit = time.Millisecond
	defer func() { retryBackoffUnit = old }()

	llm := &scriptedLLM{steps: []step{{err: errors.New("opencode: HTTP 401")}}}
	cc := &Context{Target: "http://127.0.0.1:1"}
	rep, err := Investigate(context.Background(), llm, cc, Options{MaxIters: 10, MaxRequests: 5})
	if err != nil {
		t.Fatalf("Investigate returned error: %v", err)
	}
	if rep.Coverage.StopReason != "model_error" {
		t.Fatalf("stop reason = %q, want model_error (permanent must fail fast)", rep.Coverage.StopReason)
	}
	if !strings.Contains(cc.Summary, "401") {
		t.Fatalf("summary should name the permanent failure, got %q", cc.Summary)
	}
}
