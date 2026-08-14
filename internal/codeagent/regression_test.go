package codeagent

import (
	"context"
	"strings"
	"testing"
)

type fixedLLM struct{ out string }

func (f fixedLLM) Generate(context.Context, string) (string, error) { return f.out, nil }

func sqliFinding() Finding {
	return Finding{
		Class: "sqli", Endpoint: "acme/app/search.py:41",
		Detail: "Request value concatenated into the query.",
	}
}

func appliedFix() Patch {
	return Patch{Files: []PatchedFile{{
		Path: "acme/app/search.py", Content: "def search(q):\n    return db.execute('SELECT * FROM o WHERE q=?', [q])\n",
	}}}
}

// THE ONE THAT MATTERS: a test with no assertion runs, passes, and proves nothing. Shipping it would
// tell every future reader the vulnerability is covered.
func TestRegression_RejectsATestThatAssertsNothing(t *testing.T) {
	llm := fixedLLM{out: "=== FILE: tests/test_search.py\ndef test_search():\n    search(\"' OR 1=1\")\n=== END FILE ==="}
	got, err := ProposeRegressionTest(context.Background(), llm, sqliFinding(), appliedFix(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Empty() {
		t.Errorf("FALSE ASSURANCE: shipped a test with no assertion — it will pass forever and claim this "+
			"vulnerability is pinned:\n%s", got.File.Content)
	}
}

// A test that never mentions what was fixed is testing something else, however plausible it reads.
func TestRegression_RejectsATestAboutSomethingElse(t *testing.T) {
	llm := fixedLLM{out: "=== FILE: tests/test_login.py\ndef test_login():\n    assert login('a','b') is True\n=== END FILE ==="}
	got, _ := ProposeRegressionTest(context.Background(), llm, sqliFinding(), appliedFix(), nil)
	if !got.Empty() {
		t.Errorf("shipped a test that never references the patched file or the finding:\n%s", got.File.Content)
	}
}

// The real thing must survive, or the gate is just a blocker.
func TestRegression_AcceptsATestThatExercisesTheAttack(t *testing.T) {
	llm := fixedLLM{out: "=== FILE: tests/test_search.py\n" +
		"from acme.app.search import search\n\n" +
		"def test_search_rejects_injection():\n" +
		"    rows = search(\"' OR 1=1 --\")\n" +
		"    assert rows == []\n=== END FILE ==="}
	got, err := ProposeRegressionTest(context.Background(), llm, sqliFinding(), appliedFix(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if got.Empty() {
		t.Fatal("rejected a genuine regression test — the gate is too strict to be useful")
	}
	if !strings.Contains(strings.ToUpper(got.Note), "HAS NOT BEEN RUN") {
		t.Errorf("the note must say the test is unrun — we cannot execute a customer's suite, and implying "+
			"otherwise is the false assurance this guards against. Got: %q", got.Note)
	}
	if !strings.Contains(got.Note, "FAIL") {
		t.Error("the note must tell the reviewer to run it against the PRE-FIX commit and expect a failure — " +
			"that is the only way they can tell a real regression test from a green one")
	}
}

// No fix means nothing to pin. A test for a still-present vulnerability would land RED in the customer's
// CI, which is a different deliverable and not one anybody asked for.
func TestRegression_NoFixMeansNoTest(t *testing.T) {
	llm := fixedLLM{out: "=== FILE: tests/t.py\ndef test_x():\n    assert search('x') == []\n=== END FILE ==="}
	got, err := ProposeRegressionTest(context.Background(), llm, sqliFinding(), Patch{}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Empty() {
		t.Error("proposed a test when no fix was applied — it would fail in the customer's CI on arrival")
	}
}

// An unparseable or empty model response degrades to no test, never to an error that loses the fix.
func TestRegression_GarbageDegradesToNothing(t *testing.T) {
	for _, out := range []string{"", "I could not write a test.", "```\nnonsense\n```"} {
		got, err := ProposeRegressionTest(context.Background(), fixedLLM{out: out}, sqliFinding(), appliedFix(), nil)
		if err != nil {
			t.Errorf("garbage output errored instead of degrading: %v", err)
		}
		if !got.Empty() {
			t.Errorf("produced a test from %q: %+v", out, got.File)
		}
	}
}

// Without a model there is nothing honest to return.
func TestRegression_NoModelIsAnError(t *testing.T) {
	if _, err := ProposeRegressionTest(context.Background(), nil, sqliFinding(), appliedFix(), nil); err == nil {
		t.Error("expected an error with no LLM configured")
	}
}
