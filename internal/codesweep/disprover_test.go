package codesweep

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/codelocalize"
)

// scriptedLLM returns canned replies in order; records prompts for the
// poisoned-judge assertion.
type scriptedLLM struct {
	replies []string
	prompts *[]string
	err     error
}

func (s *scriptedLLM) Generate(_ context.Context, prompt string) (string, error) {
	if s.prompts != nil {
		*s.prompts = append(*s.prompts, prompt)
	}
	if s.err != nil {
		return "", s.err
	}
	if len(s.replies) == 0 {
		return "", context.DeadlineExceeded
	}
	r := s.replies[0]
	s.replies = s.replies[1:]
	return r, nil
}

func TestDisprove_CleanDowngrades(t *testing.T) {
	llm := &scriptedLLM{replies: []string{`{"verdict":"clean","rationale":"input is cast to int before use"}`}}
	v, err := Disprove(context.Background(), llm, Candidate{Task: Task{CWE: "CWE-78", Path: "a.py"}, Evidence: []string{"a.py:10"}}, "code")
	if err != nil || v.Verdict != "clean" {
		t.Fatalf("want clean, got %+v err=%v", v, err)
	}
}

func TestDisprove_VulnerableBecomesAbstain(t *testing.T) {
	llm := &scriptedLLM{replies: []string{`{"verdict":"vulnerable","rationale":"confirmed"}`}}
	v, _ := Disprove(context.Background(), llm, Candidate{}, "code")
	if v.Verdict != "abstain" {
		t.Fatalf("an agreeing reviewer adds nothing — recorded as abstain, got %q", v.Verdict)
	}
}

func TestDisprove_ParseFailureIsError(t *testing.T) {
	llm := &scriptedLLM{replies: []string{`not json at all`}}
	if _, err := Disprove(context.Background(), llm, Candidate{}, "code"); err == nil {
		t.Fatal("unparsable reply must surface as error so the caller fails OPEN")
	}
}

func TestApplyDisprover_FailsOpenAndRecordsDowngrades(t *testing.T) {
	repo := codelocalize.Repo{{Path: "a.py", Content: strings.Repeat("x = 1\n", 500) + "os.system(input)\n"}}
	res := Result{Candidates: []Candidate{
		{Task: Task{CWE: "CWE-78", Path: "a.py", SinkLines: []int{501}}, Vulnerable: true, Evidence: []string{"a.py:501"}},
	}}
	llm := &scriptedLLM{replies: []string{
		`{"verdict":"clean","rationale":"input() is not attacker controlled here"}`,
		`garbage reply`,
	}}
	got := ApplyDisprover(context.Background(), llm, &res, repo, 400)
	if got.Downgraded != 1 || got.Kept != 0 {
		t.Fatalf("downgraded=%d kept=%d errors=%d", got.Downgraded, got.Kept, got.Errors)
	}
	if res.Candidates[0].Vulnerable {
		t.Error("the disproved candidate must be downgraded")
	}
	if !strings.Contains(strings.Join(res.Candidates[0].Evidence, ";"), "disprover-downgraded") {
		t.Error("the downgrade must stay in the audit trail on the candidate")
	}
}

func TestApplyDisprover_PromptCarriesRawEvidenceNotTheStory(t *testing.T) {
	var prompts []string
	llm := &scriptedLLM{replies: []string{`{"verdict":"vulnerable","rationale":"ok"}`}, prompts: &prompts}
	cand := Candidate{
		Task:       Task{CWE: "CWE-78", Path: "a.py"},
		Vulnerable: true,
		Rationale:  "THE FINDERS STORY must never reach the judge",
		Evidence:   []string{"a.py:1"},
	}
	repo := codelocalize.Repo{{Path: "a.py", Content: "import os\nos.system(x)\n"}}
	ApplyDisprover(context.Background(), llm, &Result{Candidates: []Candidate{cand}}, repo, 100)
	if len(prompts) == 0 {
		t.Fatal("no prompt captured")
	}
	if strings.Contains(prompts[0], "FINDERS STORY") {
		t.Error("poisoned-judge violation: the finder's rationale reached the disprover prompt")
	}
	if !strings.Contains(prompts[0], "ADVERSARIAL REVIEWER") {
		t.Errorf("prompt must frame the brain as adversarial reviewer:\n%s", prompts[0][:200])
	}
}
