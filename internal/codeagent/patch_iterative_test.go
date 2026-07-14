package codeagent

import (
	"context"
	"strings"
	"testing"
)

type funcLLM func(ctx context.Context, prompt string) (string, error)

func (f funcLLM) Generate(ctx context.Context, prompt string) (string, error) { return f(ctx, prompt) }

func block(content string) string {
	return "=== FILE: m.js ===\n" + content + "\n=== END FILE ===\n"
}

// TestProposePatchIterative_RefinesOnFailure: a first (incomplete) fix fails the verifier; the loop
// threads the failure into a refine attempt that passes. This is the whole point — recover a fix the
// single-shot path would have reported as broken.
func TestProposePatchIterative_RefinesOnFailure(t *testing.T) {
	calls := 0
	llm := funcLLM(func(_ context.Context, prompt string) (string, error) {
		calls++
		if calls == 1 {
			return block("partial"), nil
		}
		if !strings.Contains(prompt, "VERIFIER OUTPUT (why your last patch failed)") {
			t.Errorf("attempt %d should be a refine prompt", calls)
		}
		if !strings.Contains(prompt, "exploit still succeeded") {
			t.Errorf("refine prompt must carry the verifier's real feedback, got: %q", prompt[:80])
		}
		return block("complete"), nil
	})
	verify := func(_ context.Context, p Patch) VerifyOutcome {
		if len(p.Files) == 1 && p.Files[0].Content == "complete" {
			return VerifyOutcome{Fixed: true}
		}
		return VerifyOutcome{Fixed: false, Feedback: "the exploit still succeeded on the patched file"}
	}
	p, attempts, confirmed, err := ProposePatchIterative(context.Background(), llm,
		Finding{Class: "prototype_pollution"}, []SourceFile{{Path: "m.js", Content: "orig"}}, verify, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !confirmed {
		t.Error("want confirmed=true after refine")
	}
	if attempts != 2 {
		t.Errorf("want 2 attempts (fail→refine→pass), got %d", attempts)
	}
	if len(p.Files) != 1 || p.Files[0].Content != "complete" {
		t.Errorf("want the refined 'complete' patch, got %+v", p.Files)
	}
}

// TestProposePatchIterative_NilVerifierSingleShot: no verifier → exactly one attempt, unconfirmed.
func TestProposePatchIterative_NilVerifierSingleShot(t *testing.T) {
	calls := 0
	llm := funcLLM(func(_ context.Context, _ string) (string, error) { calls++; return block("x"), nil })
	_, attempts, confirmed, err := ProposePatchIterative(context.Background(), llm,
		Finding{Class: "xss"}, []SourceFile{{Path: "m.js", Content: "o"}}, nil, 5)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 1 || calls != 1 {
		t.Errorf("nil verifier must be single-shot, got attempts=%d calls=%d", attempts, calls)
	}
	if confirmed {
		t.Error("nil verifier can't confirm a fix")
	}
}

// TestProposePatchIterative_ExhaustsAttempts: verifier never satisfied → attempts==max, unconfirmed,
// returns the last patch (never a fabricated success).
func TestProposePatchIterative_ExhaustsAttempts(t *testing.T) {
	llm := funcLLM(func(_ context.Context, _ string) (string, error) { return block("nope"), nil })
	verify := func(_ context.Context, _ Patch) VerifyOutcome {
		return VerifyOutcome{Fixed: false, Feedback: "still broken"}
	}
	_, attempts, confirmed, err := ProposePatchIterative(context.Background(), llm,
		Finding{Class: "sqli"}, []SourceFile{{Path: "m.js", Content: "o"}}, verify, 3)
	if err != nil {
		t.Fatal(err)
	}
	if attempts != 3 || confirmed {
		t.Errorf("want attempts=3 confirmed=false, got attempts=%d confirmed=%v", attempts, confirmed)
	}
}
