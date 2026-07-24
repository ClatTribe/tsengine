package codelocalize

import (
	"context"
	"testing"
)

func TestMatchToken_WordBoundary(t *testing.T) {
	cases := []struct {
		hay, tok string
		want     bool
	}{
		{"result := ecosystem(x)", "system(", false}, // mid-word — must NOT match
		{"os.system(cmd)", "system(", true},          // real call — must match
		{"please reselect your plan", "select ", false},
		{"select * from t", "select ", true},
		{"myhttp.get(u)", "http.get(", false},
		{"resp := http.get(u)", "http.get(", true},
		{"path/../etc", "../", true}, // symbol-leading token, no boundary needed
		{"innerhtml = x", "innerhtml", true},
		{"theinnerhtmlfield", "innerhtml", false},
	}
	for _, c := range cases {
		if got := matchToken(c.hay, c.tok); got != c.want {
			t.Errorf("matchToken(%q,%q)=%v want %v", c.hay, c.tok, got, c.want)
		}
	}
}

// A file whose only "sink" tokens are incidental substrings inside longer identifiers/prose must NOT be
// ranked — the precision property that stops false positives on real code.
func TestHeuristicLocalize_IncidentalSubstringsDoNotScore(t *testing.T) {
	repo := Repo{
		{Path: "marketing/copy.go", Content: "// help users reselect a plan across our ecosystem(really)\nconst tagline = \"select the best\"\n"},
		{Path: "svc/exec.go", Content: "func run(r *http.Request) {\n c := r.FormValue(\"c\")\n exec.Command(\"sh\", \"-c\", c).Run()\n}"},
	}
	res, _ := HeuristicLocalizer{}.Localize(context.Background(), Query{CWE: []string{"CWE-78"}}, repo)
	if len(res.Ranked) != 1 || res.Ranked[0].Path != "svc/exec.go" {
		t.Fatalf("only the real command-injection sink should rank; got %v", res.TopPaths(5))
	}
}

// The precision guard must NOT cost recall: the built-in corpus still localizes perfectly.
func TestHeuristicLocalize_RecallStillPerfectAfterBoundaryGuard(t *testing.T) {
	repo := Repo{sqliSink(), xssSink(), cleanFile()}
	res, _ := HeuristicLocalizer{}.Localize(context.Background(), Query{CWE: []string{"CWE-89"}}, repo)
	if len(res.Ranked) == 0 || res.Ranked[0].Path != "app/users.go" {
		t.Fatalf("recall regressed after boundary guard: %v", res.TopPaths(5))
	}
}
