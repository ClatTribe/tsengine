package platformapi

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

type stubLLM struct {
	reply  string
	calls  int
	prompt string
}

func (s *stubLLM) Generate(_ context.Context, p string) (string, error) {
	s.calls++
	s.prompt = p
	return s.reply, nil
}

// The gap this closes: a scanner finding with no CWE gets no control mapping at all, because the
// crosswalk keys on CWE. So the attributed class must be one the crosswalk actually maps.
func TestCWEAttribution_FillsAMappableClass(t *testing.T) {
	llm := &stubLLM{reply: "CWE-89"}
	fs := []types.Finding{{ID: "f1", Title: "SQL injection in the search parameter", Tool: "grype"}}

	out, _ := attributeWith(llm, fs, 10)
	if len(out[0].CWE) == 0 || out[0].CWE[0] != "CWE-89" {
		t.Fatalf("a mappable class was not attributed: %+v", out[0].CWE)
	}
}

// A class outside the crosswalk must be DISCARDED, not annotated: it cannot produce a control
// mapping, so attributing it would add an unusable annotation with a veneer of authority.
func TestCWEAttribution_UnmappableClassIsDiscarded(t *testing.T) {
	llm := &stubLLM{reply: "CWE-99999"}
	fs := []types.Finding{{ID: "f1", Title: "something odd", Tool: "grype"}}

	out, _ := attributeWith(llm, fs, 10)
	if len(out[0].CWE) != 0 {
		t.Errorf("a class the crosswalk cannot map was annotated anyway: %+v", out[0].CWE)
	}
}

// A CWE the scanner already set is never overwritten: the scanner looked at the actual code, the
// model is reading its summary, and trading specific evidence for generic is the wrong direction.
func TestCWEAttribution_ScannerCWEIsNotOverwritten(t *testing.T) {
	llm := &stubLLM{reply: "CWE-89"}
	fs := []types.Finding{{ID: "f1", Title: "x", CWE: []string{"CWE-79"}}}

	out, _ := attributeWith(llm, fs, 10)
	if out[0].CWE[0] != "CWE-79" {
		t.Errorf("the scanner's own classification was replaced: %+v", out[0].CWE)
	}
	if llm.calls != 0 {
		t.Errorf("a classified finding must not cost a model call, got %d", llm.calls)
	}
}

// The bound is real: it is what keeps a noisy scan from becoming an unbounded inference bill.
func TestCWEAttribution_RespectsTheBound(t *testing.T) {
	llm := &stubLLM{reply: "CWE-89"}
	fs := make([]types.Finding, 10)
	for i := range fs {
		fs[i] = types.Finding{ID: "f", Title: "SQL injection"}
	}
	if _, _ = attributeWith(llm, fs, 3); llm.calls != 3 {
		t.Errorf("bound not honoured: %d model calls for max=3", llm.calls)
	}
}

// No model → the findings pass through untouched. This is also how the Free plan's AI gate reaches
// this tier, so it must be a no-op rather than an error.
func TestCWEAttributor_NoModelIsANoOp(t *testing.T) {
	fs := []types.Finding{{ID: "f1", Title: "SQL injection"}}
	out := Deps{}.CWEAttributor()(context.Background(), "t1", fs)
	if len(out) != 1 || len(out[0].CWE) != 0 {
		t.Errorf("attribution ran without a model: %+v", out)
	}
}

// The prompt must carry the finding's own text — attribution from nothing is guessing.
func TestCWEAttribution_PromptCarriesTheFinding(t *testing.T) {
	llm := &stubLLM{reply: "none"}
	_, _ = attributeWith(llm, []types.Finding{{ID: "f1", Title: "unsafe deserialization of user input"}}, 5)
	if !strings.Contains(llm.prompt, "unsafe deserialization") {
		t.Errorf("the model was asked to classify without the finding's text: %q", llm.prompt)
	}
}
