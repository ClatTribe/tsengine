package fixcheck

import "testing"

func find(r Report, name string) Check {
	for _, c := range r.Checks {
		if c.Name == name {
			return c
		}
	}
	return Check{}
}

// A patch that echoes the file back unchanged is a no-op and must FAIL (and block).
func TestNoOpPatchBlocks(t *testing.T) {
	src := "package x\nfunc f() { q(userInput) }\n"
	r := Checks(Finding{Endpoint: "x.go:2"}, []File{{Path: "x.go", Original: src, Patched: src}})
	if find(r, "non_trivial").Status != Fail {
		t.Fatalf("no-op should fail non_trivial, got %v", find(r, "non_trivial").Status)
	}
	if !r.Blocking {
		t.Error("a no-op patch must block")
	}
}

// Whitespace-only changes are still a no-op.
func TestWhitespaceOnlyIsNoOp(t *testing.T) {
	orig := "package x\nfunc f() { q(a) }\n"
	patched := "package x\nfunc f() { q(a) }   \n\n"
	r := Checks(Finding{Endpoint: "x.go:2"}, []File{{Path: "x.go", Original: orig, Patched: patched}})
	if find(r, "non_trivial").Status != Fail {
		t.Errorf("whitespace-only change should be a no-op, got %v", find(r, "non_trivial").Status)
	}
}

// A patch that edits elsewhere and leaves the cited line verbatim FAILS the cited-line check.
func TestMisdirectedPatchFailsCitedLine(t *testing.T) {
	orig := "package x\nfunc f() { db.Query(\"SELECT \"+id) }\nfunc g() {}\n"
	// changed g(), left the vulnerable line 2 exactly as-is
	patched := "package x\nfunc f() { db.Query(\"SELECT \"+id) }\nfunc g() { log() }\n"
	r := Checks(Finding{Endpoint: "x.go:2"}, []File{{Path: "x.go", Original: orig, Patched: patched}})
	if find(r, "changes_cited_line").Status != Fail {
		t.Fatalf("misdirected patch should fail cited-line, got %v (%s)",
			find(r, "changes_cited_line").Status, find(r, "changes_cited_line").Message)
	}
	if !r.Blocking {
		t.Error("a patch that misses the cited line must block")
	}
}

// A real fix that rewrites the cited line PASSES cited-line and non-trivial.
func TestRealFixPasses(t *testing.T) {
	orig := "package x\nfunc f() { db.Query(\"SELECT \"+id) }\n"
	patched := "package x\nfunc f() { db.Query(\"SELECT ?\", id) }\n"
	r := Checks(Finding{Endpoint: "x.go:2"}, []File{{Path: "x.go", Original: orig, Patched: patched}})
	if find(r, "non_trivial").Status != Pass {
		t.Errorf("non_trivial: %v", find(r, "non_trivial"))
	}
	if find(r, "changes_cited_line").Status != Pass {
		t.Errorf("changes_cited_line: %v", find(r, "changes_cited_line"))
	}
	if find(r, "syntax_valid").Status != Pass {
		t.Errorf("syntax_valid: %v", find(r, "syntax_valid"))
	}
	if r.Blocking {
		t.Error("a sound fix must not block")
	}
}

// A patched Go file that no longer parses FAILS syntax and blocks.
func TestBrokenGoSyntaxBlocks(t *testing.T) {
	orig := "package x\nfunc f() { q(a) }\n"
	patched := "package x\nfunc f() { q(a) " // missing braces
	r := Checks(Finding{Endpoint: "x.go:2"}, []File{{Path: "x.go", Original: orig, Patched: patched}})
	if find(r, "syntax_valid").Status != Fail {
		t.Fatalf("broken Go should fail syntax, got %v", find(r, "syntax_valid").Status)
	}
	if !r.Blocking {
		t.Error("a patch that breaks Go syntax must block")
	}
}

// A non-Go language is NOT CHECKED for syntax — never silently passed as valid.
func TestNonGoSyntaxNotChecked(t *testing.T) {
	orig := "def f():\n    q(a)\n"
	patched := "def f():\n    q(b)\n"
	r := Checks(Finding{Endpoint: "app.py:2"}, []File{{Path: "app.py", Original: orig, Patched: patched}})
	if find(r, "syntax_valid").Status != NotChecked {
		t.Errorf("python syntax should be NotChecked, got %v", find(r, "syntax_valid").Status)
	}
	if r.Blocking {
		t.Error("a NotChecked must never block")
	}
}

// No cited line → the cited-line check is NotChecked, not a pass or a fail.
func TestNoCitedLineNotChecked(t *testing.T) {
	r := Checks(Finding{Endpoint: ""}, []File{{Path: "x.go", Original: "package x\n", Patched: "package x\nfunc f(){}\n"}})
	if find(r, "changes_cited_line").Status != NotChecked {
		t.Errorf("no cited line should be NotChecked, got %v", find(r, "changes_cited_line").Status)
	}
}

// The honest-scope note is always present.
func TestNoteAlwaysPresent(t *testing.T) {
	r := Checks(Finding{}, nil)
	if r.Note == "" {
		t.Error("the soundness-not-closure note must always be present")
	}
}
