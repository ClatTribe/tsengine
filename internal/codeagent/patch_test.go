package codeagent

import (
	"context"
	"strings"
	"testing"
)

type fakeLLM struct {
	reply string
	seen  string
}

func (f *fakeLLM) Generate(_ context.Context, prompt string) (string, error) {
	f.seen = prompt
	return f.reply, nil
}

// TestProposePatch_ProducesAppliedFiles: the engineer returns whole-file replacements, restricted to the
// files actually supplied (it can't invent new files or escape the build context), with provenance.
func TestProposePatch_ProducesAppliedFiles(t *testing.T) {
	llm := &fakeLLM{reply: "Fixed by parameterising:\n" +
		"=== FILE: app/login.php ===\n<?php $stmt=$db->prepare('SELECT ..'); // fixed\n=== END FILE ===\n" +
		"=== FILE: app/notsupplied.php ===\n<?php // should be dropped\n=== END FILE ===\n"}
	sources := []SourceFile{
		{Path: "app/login.php", Content: "<?php $q=\"SELECT * WHERE u='$u'\"; // vulnerable"},
		{Path: "app/index.php", Content: "<?php echo 'home';"},
	}
	p, err := ProposePatch(context.Background(), llm, Finding{Class: "sqli", Endpoint: "/login"}, sources)
	if err != nil {
		t.Fatalf("propose: %v", err)
	}
	if p.Raw == "" {
		t.Errorf("raw model output (provenance) missing: %+v", p)
	}
	if len(p.Files) != 1 || p.Files[0].Path != "app/login.php" {
		t.Fatalf("only the supplied file should be kept, got %+v", p.Files)
	}
	if !strings.Contains(p.Files[0].Content, "prepare") {
		t.Error("patched content should carry the fix")
	}
	// The prompt must carry the finding + the source (grounded), and be generic (no per-challenge hint).
	if !strings.Contains(llm.seen, "class: sqli") || !strings.Contains(llm.seen, "vulnerable") {
		t.Error("prompt must include the finding class + the real source")
	}
}

// TestProposePatch_EmptyAndNoLLM: an engineer that can't fix returns an empty patch (→ no_patch, never a
// fake fix); a nil LLM is a hard error (never silently "no patch").
func TestProposePatch_EmptyAndNoLLM(t *testing.T) {
	llm := &fakeLLM{reply: "I cannot safely fix this without more context."}
	p, err := ProposePatch(context.Background(), llm, Finding{Class: "xss", Endpoint: "/x"}, []SourceFile{{Path: "a.php", Content: "x"}})
	if err != nil || !p.Empty() {
		t.Errorf("no fix → empty patch, no error; got files=%d err=%v", len(p.Files), err)
	}
	if _, err := ProposePatch(context.Background(), nil, Finding{}, nil); err == nil {
		t.Error("a nil LLM must be a hard error (the engineer has no brain)")
	}
}

// TestParsePatch covers the format directly: multi-file, no-blocks, traversal, unterminated.
func TestParsePatch(t *testing.T) {
	out := "=== FILE: app/login.php ===\n<?php // fixed\n=== END FILE ===\n=== FILE: app/util.php ===\n<?php echo 'safe';\n=== END FILE ===\n"
	files, err := ParsePatch(out)
	if err != nil || len(files) != 2 || files[0].Path != "app/login.php" || files[1].Path != "app/util.php" {
		t.Fatalf("parse wrong: files=%+v err=%v", files, err)
	}
	if f, err := ParsePatch("no fix here"); err != nil || len(f) != 0 {
		t.Errorf("no-blocks must be (nil,nil), got %v/%v", f, err)
	}
	if _, err := ParsePatch("=== FILE: ../../etc/passwd ===\nx\n=== END FILE ==="); err == nil {
		t.Error("traversal path must be rejected")
	}
	if _, err := ParsePatch("=== FILE: a.php ===\nunterminated"); err == nil {
		t.Error("unterminated block must error")
	}
}

// ── THE PROMPT MUST FIT BOTH SHAPES OF THE JOB ───────────────────────────────────────────────────

// The framing was overfit to the offensive-agent case: "a penetration test proved a vulnerability in
// the WEB APPLICATION below" and "the homepage must still respond". Most real fixes are library CVEs —
// a traversal in an archive extractor, a prototype pollution in a merge helper — with no pentest, no
// web app and no homepage, judged by the project's own test suite. Protecting a homepage that does not
// exist steers the model toward request-level patches for defects that live in a function.
func TestPatchPrompt_DoesNotAssumeAWebApp(t *testing.T) {
	p := buildPatchPrompt(
		Finding{Class: "CWE-22", Endpoint: "example/archiver", Detail: "Path traversal in tar extraction."},
		[]SourceFile{{Path: "extract.go", Content: "package main\n"}},
	)
	low := strings.ToLower(p)
	for _, overfit := range []string{"homepage", "web application", "penetration test"} {
		if strings.Contains(low, overfit) {
			t.Errorf("the prompt assumes a web-app pentest (%q) — wrong for a library CVE, which is most "+
				"of the real work:\n%s", overfit, p)
		}
	}
}

// What replaced it has to be stronger, not just vaguer: the benchmark oracle for a real patch is the
// project's build and test suite, so the model must be told that breaking them is a failed patch.
func TestPatchPrompt_SaysBreakingTestsIsAFailedPatch(t *testing.T) {
	p := strings.ToLower(buildPatchPrompt(Finding{Class: "CWE-89"}, []SourceFile{{Path: "a.go", Content: "x"}}))
	if !strings.Contains(p, "test") {
		t.Error("the prompt never mentions tests, which is what actually judges a real-world patch")
	}
	if !strings.Contains(p, "build") {
		t.Error("the prompt never mentions the build")
	}
}

// And the properties that were already right must survive: root-cause fixing, minimal changes, and the
// file-block output format the parser depends on.
func TestPatchPrompt_KeepsWhatWasAlreadyCorrect(t *testing.T) {
	p := buildPatchPrompt(
		Finding{Class: "sqli", Endpoint: "/search", Detail: "boolean differential confirmed"},
		[]SourceFile{{Path: "app.py", Content: "q = 'SELECT '+x"}},
	)
	for _, want := range []string{"ROOT CAUSE", "=== FILE:", "=== END FILE ===", "as few files as possible"} {
		if !strings.Contains(p, want) {
			t.Errorf("the prompt lost %q, which the parser or the fix quality depends on", want)
		}
	}
	// The evidence and the source still have to reach the model.
	if !strings.Contains(p, "boolean differential confirmed") || !strings.Contains(p, "SELECT ") {
		t.Error("the prompt dropped the evidence or the source")
	}
}
