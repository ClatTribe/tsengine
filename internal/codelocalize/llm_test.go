package codelocalize

import (
	"context"
	"fmt"
	"strings"
	"testing"
)

type mockLLM struct {
	out string
	err error
}

func (m mockLLM) Generate(context.Context, string) (string, error) { return m.out, m.err }

func TestLLMLocalize_GroundsProposalsAndPromotesMissedSink(t *testing.T) {
	repo := Repo{sqliSink(), xssSink(), cleanFile()} // app/users.go, web/render.js, util/math.go
	// The heuristic for CWE-89 sees only app/users.go. The model proposes the XSS-sink file first
	// (groundable via `innerhtml`, a real token the CWE-89 table doesn't score), then a CLEAN file and a
	// GHOST path (both must be refused), then the real SQLi file.
	mock := mockLLM{out: `Here are the likely sinks:
[
 {"path":"web/render.js","why":"reflects req.query into innerHTML"},
 {"path":"util/math.go","why":"looks arithmetic"},
 {"path":"ghost/missing.go","why":"invented"},
 {"path":"app/users.go","why":"string-concat SQL"}
]`}
	res, err := LLMLocalizer{LLM: mock}.Localize(context.Background(), Query{CWE: []string{"CWE-89"}}, repo)
	if err != nil {
		t.Fatal(err)
	}
	if res.Engine != "llm+heuristic" {
		t.Fatalf("engine=%q", res.Engine)
	}
	paths := res.TopPaths(10)
	if len(paths) == 0 || paths[0] != "web/render.js" {
		t.Fatalf("model should promote the missed sink first, got %v", paths)
	}
	// clean + ghost must be refused (§10: no invented / no-evidence file).
	for _, p := range paths {
		if p == "util/math.go" {
			t.Errorf("clean file was not refused: %v", paths)
		}
		if p == "ghost/missing.go" {
			t.Errorf("hallucinated path was not refused: %v", paths)
		}
	}
	// monotonic recall: the heuristic hit is still present.
	found := false
	for _, p := range paths {
		if p == "app/users.go" {
			found = true
		}
	}
	if !found {
		t.Fatalf("heuristic hit dropped after merge (recall regressed): %v", paths)
	}
}

func TestLLMLocalize_NilModelIsHeuristic(t *testing.T) {
	repo := Repo{sqliSink(), cleanFile()}
	q := Query{CWE: []string{"CWE-89"}}
	llm, _ := LLMLocalizer{LLM: nil}.Localize(context.Background(), q, repo)
	heur, _ := HeuristicLocalizer{}.Localize(context.Background(), q, repo)
	if llm.Engine != "heuristic" {
		t.Fatalf("nil model must yield the heuristic engine, got %q", llm.Engine)
	}
	if strings.Join(llm.TopPaths(9), ",") != strings.Join(heur.TopPaths(9), ",") {
		t.Fatal("nil model ranking must equal the heuristic ranking")
	}
}

func TestLLMLocalize_ModelErrorFallsBack(t *testing.T) {
	repo := Repo{sqliSink(), cleanFile()}
	res, err := LLMLocalizer{LLM: mockLLM{err: fmt.Errorf("boom")}}.Localize(context.Background(), Query{CWE: []string{"CWE-89"}}, repo)
	if err != nil {
		t.Fatal(err)
	}
	if res.Engine != "heuristic" {
		t.Fatalf("model error must degrade to heuristic, got %q", res.Engine)
	}
	if res.Ranked[0].Path != "app/users.go" {
		t.Fatalf("heuristic ranking should stand, got %v", res.TopPaths(5))
	}
	joined := strings.Join(res.Trace, " ")
	if !strings.Contains(joined, "unavailable") {
		t.Fatalf("trace should note the model was unavailable: %v", res.Trace)
	}
}

func TestParseProposals(t *testing.T) {
	if ps := parseProposals("no json here"); ps != nil {
		t.Errorf("expected nil, got %v", ps)
	}
	ps := parseProposals("prefix [{\"path\":\"a.go\",\"why\":\"x\"},{\"path\":\"\",\"why\":\"skip\"}] suffix")
	if len(ps) != 1 || ps[0].Path != "a.go" {
		t.Fatalf("parseProposals=%v (empty-path entry should be dropped)", ps)
	}
}
