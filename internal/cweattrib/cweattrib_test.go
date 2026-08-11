package cweattrib

import (
	"context"
	"errors"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

type fakeLLM struct {
	out  string
	err  error
	call int
}

func (f *fakeLLM) Generate(_ context.Context, _ string) (string, error) {
	f.call++
	return f.out, f.err
}

var allowed = []string{"CWE-79", "CWE-89", "CWE-22", "CWE-798"}

func unclassified() types.Finding {
	return types.Finding{
		ID: "f1", Tool: "semgrep", RuleID: "string-formatted-query",
		Title: "Query built with a formatted string", Endpoint: "internal/store/users.go:14",
	}
}

func TestAttribute_FillsAMissingClass(t *testing.T) {
	a := Attributor{LLM: &fakeLLM{out: "CWE-89"}, Allowed: allowed}
	got := a.Attribute(context.Background(), unclassified())
	if got.CWE != "CWE-89" {
		t.Errorf("cwe = %q, want CWE-89 (reason: %s)", got.CWE, got.Reason)
	}
}

// The guard that makes a model safe here: a class with no crosswalk entry cannot become a control
// mapping, so attributing it would add an unusable annotation that LOOKS authoritative.
func TestAttribute_OutsideTheCrosswalkIsDiscarded(t *testing.T) {
	a := Attributor{LLM: &fakeLLM{out: "CWE-1337"}, Allowed: allowed}
	got := a.Attribute(context.Background(), unclassified())
	if got.CWE != "" {
		t.Errorf("cwe = %q, want empty — an id outside the closed set must never be attributed", got.CWE)
	}
	if got.Reason == "" {
		t.Error("a discard must say why, so the decision is auditable")
	}
}

// Refusing to guess is correct behaviour, not a failure — it is what stops licence conflicts and cost
// findings from acquiring a fake weakness class.
func TestAttribute_DeclineIsRespected(t *testing.T) {
	for _, out := range []string{"NONE", "none", "This is not a technical weakness", "n/a"} {
		a := Attributor{LLM: &fakeLLM{out: out}, Allowed: allowed}
		if got := a.Attribute(context.Background(), unclassified()); got.CWE != "" {
			t.Errorf("output %q attributed %q, want a decline", out, got.CWE)
		}
	}
}

// "not CWE-89, it's a policy issue" must read as a decline, not as CWE-89. The decline check runs
// before the id extraction precisely for this.
func TestAttribute_NegatedClassIsNotAttributed(t *testing.T) {
	a := Attributor{LLM: &fakeLLM{out: "This is not CWE-89, it is a business policy discrepancy — NONE"}, Allowed: allowed}
	if got := a.Attribute(context.Background(), unclassified()); got.CWE != "" {
		t.Errorf("attributed %q from a negation, want empty", got.CWE)
	}
}

// A scanner's own classification is authoritative — the model must never overwrite it.
func TestAttribute_NeverOverwritesAScannerClass(t *testing.T) {
	f := unclassified()
	f.CWE = []string{"CWE-22"}
	llm := &fakeLLM{out: "CWE-89"}
	got := Attributor{LLM: llm, Allowed: allowed}.Attribute(context.Background(), f)
	if got.CWE != "" {
		t.Errorf("proposed %q for an already-classified finding", got.CWE)
	}
	if llm.call != 0 {
		t.Error("an already-classified finding should not cost a model call at all")
	}
}

// Transport failure is not a classification and must never look like one.
func TestAttribute_ModelErrorIsNotAClassification(t *testing.T) {
	a := Attributor{LLM: &fakeLLM{err: errors.New("429 rate limited")}, Allowed: allowed}
	got := a.Attribute(context.Background(), unclassified())
	if got.CWE != "" {
		t.Errorf("attributed %q despite a transport error", got.CWE)
	}
}

// No allowed set means unconstrained attribution, which is the exact failure this package prevents —
// so it disables itself rather than falling back to trusting the model.
func TestAttribute_NoAllowedSetDisablesAttribution(t *testing.T) {
	llm := &fakeLLM{out: "CWE-89"}
	got := Attributor{LLM: llm, Allowed: nil}.Attribute(context.Background(), unclassified())
	if got.CWE != "" {
		t.Errorf("attributed %q with no closed set — must disable instead", got.CWE)
	}
	if llm.call != 0 {
		t.Error("should not call the model when attribution is disabled")
	}
}

func TestFill_OnlyTouchesUnclassifiedAndRespectsTheCap(t *testing.T) {
	llm := &fakeLLM{out: "CWE-89"}
	in := []types.Finding{
		{ID: "a", Title: "no class"},
		{ID: "b", Title: "already classified", CWE: []string{"CWE-22"}},
		{ID: "c", Title: "no class"},
		{ID: "d", Title: "no class"},
	}
	out, results := Attributor{LLM: llm, Allowed: allowed}.Fill(context.Background(), in, 2)

	if llm.call != 2 {
		t.Errorf("model called %d times, want 2 — the cap bounds the inference spend", llm.call)
	}
	if len(results) != 2 {
		t.Errorf("got %d decisions, want 2", len(results))
	}
	if len(out[1].CWE) != 1 || out[1].CWE[0] != "CWE-22" {
		t.Errorf("the pre-classified finding was modified: %v", out[1].CWE)
	}
	if len(out[0].CWE) == 0 {
		t.Error("the first unclassified finding should have been attributed")
	}
	// Past the cap, findings are left exactly as they are today — never half-annotated.
	if len(out[3].CWE) != 0 {
		t.Errorf("finding past the cap was attributed: %v", out[3].CWE)
	}
}
