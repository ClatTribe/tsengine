package bench

import (
	"context"
	"testing"
)

// scriptedPatchLLM returns a fixed patch response (valid FILE-block format) so the harness scoring
// is validated deterministically — no proxy/model needed for CI.
type scriptedPatchLLM struct{ out string }

func (m scriptedPatchLLM) Generate(_ context.Context, _ string) (string, error) { return m.out, nil }

func TestCVEPatchBench_ScoresProducedAndLocalized(t *testing.T) {
	inst := []CVEPatchInstance{{
		ID: "demo-CVE-0000-0001", CVE: "CVE-0000-0001", Class: "sqli", Endpoint: "/login",
		Detail: "unparameterized query", Lang: "php",
		VulnFiles: []VFile{{Path: "app/login.php", Content: "<?php $q=\"SELECT * WHERE u='$u'\";"}},
		GoldFiles: []string{"app/login.php"}, // the real fix touched this file
	}}
	// engineer rewrites the gold file → produced + localized.
	llm := scriptedPatchLLM{out: "=== FILE: app/login.php ===\n<?php $stmt=$db->prepare('SELECT ..');\n=== END FILE ===\n"}
	rs := RunCVEPatchBench(context.Background(), inst, llm)
	if len(rs) != 1 {
		t.Fatalf("want 1 result, got %d", len(rs))
	}
	if !rs[0].Produced {
		t.Error("want produced=true")
	}
	if !rs[0].Localized {
		t.Error("want localized=true (rewrote the gold file)")
	}
	if rs[0].Fixed != JudgeUnknown {
		t.Errorf("fixed must stay unknown until a judge/oracle runs, got %q (§10: never self-assert a fix)", rs[0].Fixed)
	}
	s := ComputeCVEPatchStats(rs)
	if s.Produced != 1 || s.Localized != 1 || s.Fixed != 0 || s.Judged != 0 {
		t.Errorf("stats wrong: %+v", s)
	}
}

func TestCVEPatchBench_NoPatchAndWrongFile(t *testing.T) {
	inst := []CVEPatchInstance{
		{ID: "no-patch", Class: "xss", VulnFiles: []VFile{{Path: "a.php", Content: "x"}}, GoldFiles: []string{"a.php"}},
		{ID: "wrong-file", Class: "xss", VulnFiles: []VFile{{Path: "a.php", Content: "x"}}, GoldFiles: []string{"b.php"}},
	}
	// first: empty output → no patch; second: rewrites a.php but gold is b.php → produced, NOT localized.
	// a single scripted LLM can't differ per-instance, so run them separately.
	empty := RunCVEPatchBench(context.Background(), inst[:1], scriptedPatchLLM{out: "no vulnerability here"})
	if empty[0].Produced {
		t.Error("empty model output must score no_patch")
	}
	wrong := RunCVEPatchBench(context.Background(), inst[1:], scriptedPatchLLM{out: "=== FILE: a.php ===\nfixed\n=== END FILE ===\n"})
	if !wrong[0].Produced {
		t.Error("want produced=true")
	}
	if wrong[0].Localized {
		t.Error("rewrote a.php but gold is b.php → must NOT be localized")
	}
}
