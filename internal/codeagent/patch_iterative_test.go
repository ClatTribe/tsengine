package codeagent

import (
	"context"
	"errors"
	"strings"
	"testing"
)

type refineLLM struct {
	outs    []string
	prompts []string
	err     error
}

func (s *refineLLM) Generate(_ context.Context, p string) (string, error) {
	s.prompts = append(s.prompts, p)
	if s.err != nil {
		return "", s.err
	}
	if len(s.prompts) <= len(s.outs) {
		return s.outs[len(s.prompts)-1], nil
	}
	return s.outs[len(s.outs)-1], nil
}

func patchOut(body string) string {
	return "=== FILE: app.js ===\n" + body + "\n=== END FILE ===\n"
}

func srcs() []SourceFile {
	return []SourceFile{{Path: "app.js", Content: "// vulnerable"}}
}

func finding() Finding {
	return Finding{Class: "prototype-pollution", Endpoint: "/merge", Detail: "__proto__ payload reached merge()"}
}

// THE POINT of the loop: the first fix closes one vector, the verifier rejects it, and the SECOND
// attempt — informed by the verifier's real output — succeeds. A single-shot proposer stops at the
// incomplete fix and reports nothing wrong.
func TestProposePatchIterative_RefinesAfterVerifierRejection(t *testing.T) {
	llm := &refineLLM{outs: []string{
		patchOut("if (k === '__proto__') return;"),                                   // blocks __proto__ only
		patchOut("if (['__proto__','constructor','prototype'].includes(k)) return;"), // covers all vectors
	}}
	calls := 0
	verify := func(_ context.Context, p Patch) VerifyOutcome {
		calls++
		if strings.Contains(p.Files[0].Content, "constructor") {
			return VerifyOutcome{Fixed: true}
		}
		return VerifyOutcome{Feedback: "exploit still succeeded via constructor.prototype"}
	}

	p, attempts, confirmed, err := ProposePatchIterative(context.Background(), llm, finding(), srcs(), verify, 3)
	if err != nil {
		t.Fatal(err)
	}
	if !confirmed || attempts != 2 {
		t.Fatalf("want confirmed on attempt 2, got confirmed=%v attempts=%d", confirmed, attempts)
	}
	if calls != 2 {
		t.Errorf("verifier should run once per attempt, ran %d times", calls)
	}
	if !strings.Contains(p.Files[0].Content, "constructor") {
		t.Errorf("returned patch should be the successful one: %q", p.Files[0].Content)
	}
	// The refine prompt must carry the verifier's REAL output — that is what makes attempt 2 informed.
	if !strings.Contains(llm.prompts[1], "constructor.prototype") {
		t.Errorf("second prompt must thread the verifier feedback:\n%s", llm.prompts[1])
	}
	// ...and must NOT leak an instance-specific hint (overfit-free, §14.2).
	if strings.Contains(llm.prompts[1], "includes(k)") {
		t.Error("the refine prompt must not hand back the expected answer")
	}
}

// GROUNDING: the verifier disposes, not the model. A model that never produces a working fix must
// never be reported as confirmed, however many attempts it burns.
func TestProposePatchIterative_NeverConfirmsWithoutTheVerifier(t *testing.T) {
	llm := &refineLLM{outs: []string{patchOut("// still broken")}}
	verify := func(context.Context, Patch) VerifyOutcome {
		return VerifyOutcome{Feedback: "exploit still succeeded"}
	}
	_, attempts, confirmed, err := ProposePatchIterative(context.Background(), llm, finding(), srcs(), verify, 3)
	if err != nil {
		t.Fatal(err)
	}
	if confirmed {
		t.Fatal("a never-fixed patch must NOT be reported as confirmed — the model cannot grade itself")
	}
	if attempts != 3 {
		t.Errorf("should exhaust maxAttempts, got %d", attempts)
	}
}

// A nil verifier means nothing was disposed. Claiming "confirmed" there would assert a fix nobody checked.
func TestProposePatchIterative_NilVerifierNeverClaimsConfirmed(t *testing.T) {
	llm := &refineLLM{outs: []string{patchOut("// a fix")}}
	p, attempts, confirmed, err := ProposePatchIterative(context.Background(), llm, finding(), srcs(), nil, 5)
	if err != nil {
		t.Fatal(err)
	}
	if confirmed {
		t.Fatal("with no verifier there is nothing to confirm")
	}
	if attempts != 1 {
		t.Errorf("a nil verifier should not loop, got %d attempts", attempts)
	}
	if len(p.Files) != 1 {
		t.Errorf("should still return the proposed patch, got %+v", p.Files)
	}
}

// A patch may only rewrite files that were supplied — it must not invent new ones or escape the
// build context. Shared with ProposePatch via keepSupplied.
func TestProposePatchIterative_DropsUnsuppliedFiles(t *testing.T) {
	// A VALID relative path that was simply not supplied. (An absolute/traversal path is rejected
	// earlier by ParsePatch's own guard, so it would never reach keepSupplied — this exercises the
	// second layer: a well-formed path for a file outside the build context we handed over.)
	out := patchOut("// fixed") + "=== FILE: not-supplied.js ===\nmalicious()\n=== END FILE ===\n"
	llm := &refineLLM{outs: []string{out}}
	p, _, _, err := ProposePatchIterative(context.Background(), llm, finding(), srcs(), nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range p.Files {
		if f.Path != "app.js" {
			t.Errorf("a patch must not touch an unsupplied file, got %q", f.Path)
		}
	}
}

func TestProposePatchIterative_GuardsAndErrors(t *testing.T) {
	if _, _, _, err := ProposePatchIterative(context.Background(), nil, finding(), srcs(), nil, 1); err == nil {
		t.Error("a nil LLM must error with configuration guidance")
	}
	// maxAttempts below 1 is floored, not treated as "never try".
	llm := &refineLLM{outs: []string{patchOut("// fix")}}
	if _, attempts, _, err := ProposePatchIterative(context.Background(), llm, finding(), srcs(), nil, 0); err != nil || attempts != 1 {
		t.Errorf("maxAttempts=0 should floor to 1, got attempts=%d err=%v", attempts, err)
	}
	// A generate error stops the loop rather than silently retrying.
	bad := &refineLLM{err: errors.New("upstream 503")}
	if _, _, confirmed, err := ProposePatchIterative(context.Background(), bad, finding(), srcs(), nil, 3); err == nil || confirmed {
		t.Error("a model error must surface, not be retried into a false success")
	}
}
