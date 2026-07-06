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
func (f *fakeLLM) Model() string { return "fake-model" }

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
	if p.Model != "fake-model" || p.Raw == "" {
		t.Errorf("provenance missing: %+v", p)
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
