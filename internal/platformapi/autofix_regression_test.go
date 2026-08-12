package platformapi

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/codeagent"
)

// The regression test is only worth having if it REACHES a customer. This package has shipped
// benchmarked engines that no request could call before (tsbench cvepatch graded codeagent.ProposePatch
// while the autofix endpoint used its own prompt), so the wiring is the part that has historically been
// wrong, not the engine.

// Absence must read as absence. A caller rendering an empty test panel would teach the reader that a
// test exists and is trivial — the opposite of what happened.
func TestAutofixRegressionPayload_AbsentIsNilNotEmpty(t *testing.T) {
	if got := regressionPayload(codeagent.RegressionTest{}); got != nil {
		t.Errorf("no test produced should render as nil, got %+v — an empty object invites a UI to show a "+
			"blank test panel, which reads as 'there is a test and it is trivial'", got)
	}
	// A path with no content is not a test either.
	half := codeagent.RegressionTest{File: codeagent.PatchedFile{Path: "t_test.go", Content: "   "}}
	if got := regressionPayload(half); got != nil {
		t.Errorf("a path with empty content rendered as a test: %+v", got)
	}
}

// A real one must carry both halves — a path with no content cannot be committed, and content with no
// path cannot be placed.
func TestAutofixRegressionPayload_PresentCarriesPathAndContent(t *testing.T) {
	reg := codeagent.RegressionTest{
		File: codeagent.PatchedFile{Path: "tests/test_search.py", Content: "assert search(\"'\") == []"},
		Note: "unrun",
	}
	got := regressionPayload(reg)
	if got == nil {
		t.Fatal("a genuine test rendered as absent")
	}
	if got["path"] != "tests/test_search.py" {
		t.Errorf("path lost: %+v", got)
	}
	if got["content"] == "" {
		t.Errorf("content lost: %+v", got)
	}
}
