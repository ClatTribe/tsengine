package bench

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/codeagent"
)

// anchorLLM records the prompt it was given and returns a rewrite that clears the anchor.
type anchorLLM struct {
	seen  []string
	reply string
}

func (l *anchorLLM) Generate(_ context.Context, prompt string) (string, error) {
	l.seen = append(l.seen, prompt)
	return l.reply, nil
}

func anchorInstance() CVEPatchInstance {
	return CVEPatchInstance{
		ID: "t-1", CVE: "CVE-0000-0001", Lang: "python", Class: "sqli",
		Endpoint:  "app/db.py:query",
		Detail:    "user input concatenated into SQL",
		VulnFiles: []VFile{{Path: "app/db.py", Content: "def query(name):\n    cur.execute(\"SELECT * FROM t WHERE n='\" + name + \"'\")\n"}},
		GoldFiles: []string{"app/db.py"},
		GoldAnchors: map[string][]string{
			"app/db.py": {`cur.execute("SELECT * FROM t WHERE n='" + name + "'")`},
		},
	}
}

// TestGoldAnchorsDoNotInfluenceThePrompt is the anti-leak guard, and its FIRST version was
// wrong in a way worth recording: it asserted the anchor STRING never appears in the prompt.
// That can never hold — an anchor is a line of the vulnerable source, and the engineer must be
// shown the source to fix it. The test failed permanently while the code was fine.
//
// The property that actually matters is INFLUENCE, not presence: the anchors are the scorer's
// answer key, so they must not change what the engineer is asked. Building the prompt with the
// anchors present and with them stripped must produce byte-identical input — if it does, the
// answer key provably cannot be steering the engineer, whatever text it happens to share with
// the source.
func TestGoldAnchorsDoNotInfluenceThePrompt(t *testing.T) {
	withAnchors := anchorInstance()
	withoutAnchors := anchorInstance()
	withoutAnchors.GoldAnchors = nil

	a := &anchorLLM{reply: ""}
	b := &anchorLLM{reply: ""}
	_ = RunCVEPatchBench(context.Background(), []CVEPatchInstance{withAnchors}, a)
	_ = RunCVEPatchBench(context.Background(), []CVEPatchInstance{withoutAnchors}, b)

	if len(a.seen) == 0 || len(b.seen) == 0 {
		t.Fatal("the engineer was never prompted — this guard cannot see its subject")
	}
	if a.seen[0] != b.seen[0] {
		t.Errorf("the prompt CHANGED when the scorer's answer key was present — the benchmark would\n"+
			"be steering the engineer with the answer and then grading it on that answer.\n"+
			"  with anchors: %d bytes\n  without:      %d bytes", len(a.seen[0]), len(b.seen[0]))
	}
}

// TestAnchorsClearedIsStricterThanLocalized pins the point of the anchor signal: a patch that
// edits the right FILE while leaving the vulnerable line intact must score localized (it did
// touch the file) and NOT cleared (it did not touch the bug). If both moved together the anchor
// metric would be a second copy of Localized and worth nothing.
func TestAnchorsClearedIsStricterThanLocalized(t *testing.T) {
	in := anchorInstance()
	// A rewrite of the right file that adds a comment and leaves the vulnerable line untouched.
	untouched := "=== FILE: app/db.py\n# reviewed\ndef query(name):\n    cur.execute(\"SELECT * FROM t WHERE n='\" + name + \"'\")\n=== END FILE ===\n"
	got := RunCVEPatchBench(context.Background(), []CVEPatchInstance{in}, &anchorLLM{reply: untouched})
	if len(got) != 1 {
		t.Fatalf("expected 1 result, got %d", len(got))
	}
	r := got[0]
	if !r.Localized {
		t.Error("setup wrong: the patch does rewrite the gold file, so Localized must be true")
	}
	if r.AnchorsTotal != 1 {
		t.Fatalf("expected 1 anchor in the denominator, got %d", r.AnchorsTotal)
	}
	if r.AnchorsCleared != 0 {
		t.Errorf("the vulnerable line is still present verbatim, yet the anchor counted as cleared —\nthe signal is not measuring what it claims (cleared=%d)", r.AnchorsCleared)
	}

	// And the real fix must clear it, or the metric is unachievable rather than strict.
	fixed := "=== FILE: app/db.py\ndef query(name):\n    cur.execute(\"SELECT * FROM t WHERE n=%s\", (name,))\n=== END FILE ===\n"
	got2 := RunCVEPatchBench(context.Background(), []CVEPatchInstance{in}, &anchorLLM{reply: fixed})
	if got2[0].AnchorsCleared != 1 {
		t.Errorf("a genuine fix that removes the vulnerable line did NOT clear the anchor (cleared=%d/%d)",
			got2[0].AnchorsCleared, got2[0].AnchorsTotal)
	}
}

var _ codeagent.LLM = (*anchorLLM)(nil)

// TestAnchorsInUntouchedGoldFilesAreNotCredited closes a hole the first version of the anchor
// test could not see. Its fixture rewrote the single gold file in every case, so the "was this
// file actually rewritten?" condition was never exercised — a mutation removing it passed.
//
// The property: a real fix often spans several files. An anchor in a gold file the engineer
// NEVER TOUCHED is trivially "absent from the rewrite" (there is no rewrite), so crediting it
// would score an engineer for code it never wrote — inflating the metric exactly where the work
// was skipped.
func TestAnchorsInUntouchedGoldFilesAreNotCredited(t *testing.T) {
	in := anchorInstance()
	in.VulnFiles = append(in.VulnFiles, VFile{
		Path: "app/other.py", Content: "def helper(raw):\n    return eval(raw)  # second vulnerable site\n",
	})
	in.GoldFiles = append(in.GoldFiles, "app/other.py")
	in.GoldAnchors["app/other.py"] = []string{"return eval(raw)  # second vulnerable site"}

	// The engineer fixes only the FIRST file and never emits the second.
	onlyFirst := "=== FILE: app/db.py\ndef query(name):\n    cur.execute(\"SELECT * FROM t WHERE n=%s\", (name,))\n=== END FILE ===\n"
	got := RunCVEPatchBench(context.Background(), []CVEPatchInstance{in}, &anchorLLM{reply: onlyFirst})
	r := got[0]

	if r.AnchorsTotal != 2 {
		t.Fatalf("both gold files' anchors belong in the denominator, got total=%d", r.AnchorsTotal)
	}
	if r.AnchorsCleared != 1 {
		t.Errorf("only ONE of the two vulnerable sites was rewritten, but %d anchors were credited —\n"+
			"an anchor in a file the engineer never emitted is absent because there is no rewrite,\n"+
			"not because the vulnerability was fixed", r.AnchorsCleared)
	}
}
