package codeagent

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// scriptedLLM returns queued responses in order, ignoring the prompt — so a test drives the agent through a
// deterministic tool sequence without a live model.
type scriptedLLM struct {
	replies []string
	i       int
}

func (s *scriptedLLM) Generate(_ context.Context, _ string) (string, error) {
	if s.i >= len(s.replies) {
		return `{"tool":"finish","args":{"summary":"done"}}`, nil
	}
	r := s.replies[s.i]
	s.i++
	return r, nil
}

// a SQLi handler that concatenates a request param into a query — genuinely exploitable.
func sqliRepo() *MapSource {
	return NewMapSource(map[string]string{
		"api/handler.go": `package api
func Search(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query().Get("q")
	rows, _ := db.Query("SELECT * FROM users WHERE name = '" + q + "'")
	_ = rows
}`,
	})
}

// TestCodeAgent_GroundedExploitableAssessment: the agent opens the source, confirms the tainted request param
// reaches the SQL sink, and records an EXPLOITABLE issue grounded in a real path:line it read.
func TestCodeAgent_GroundedExploitableAssessment(t *testing.T) {
	cc := &Context{
		Repo:   "acme/api",
		Source: sqliRepo(),
		Findings: []types.Finding{
			{ID: "f1", Tool: "semgrep", Severity: types.SeverityHigh, Endpoint: "api/handler.go:4", Title: "SQL string concatenation"},
		},
	}
	llm := &scriptedLLM{replies: []string{
		`{"thought":"see the findings","tool":"list_findings","args":{}}`,
		`{"thought":"open the sink","tool":"read_source","args":{"path":"api/handler.go","line":4}}`,
		`{"thought":"confirm the param is user input","tool":"grep_code","args":{"pattern":"Query().Get"}}`,
		`{"thought":"tainted q reaches the query — exploitable","tool":"record_issue","args":{"finding_id":"f1","exploitable":true,"severity":"high","rationale":"user-controlled q is concatenated into the SQL","evidence":["api/handler.go:4"],"blast_radius":"reads the users table","fix_location":"api/handler.go:4","fix":"use a parameterized query"}}`,
		`{"thought":"done","tool":"finish","args":{"summary":"1 exploitable SQLi confirmed at source"}}`,
	}}

	rep, err := Investigate(context.Background(), llm, cc, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Issues) != 1 {
		t.Fatalf("want 1 grounded issue, got %d", len(rep.Issues))
	}
	is := rep.Issues[0]
	if is.FindingID != "f1" || !is.Exploitable || is.FixLocation == "" || len(is.Evidence) == 0 {
		t.Errorf("issue not fully grounded: %+v", is)
	}
	if rep.Summary == "" {
		t.Error("summary should be set by finish")
	}
}

// TestCodeAgent_GroundingRequiresRealLine: citing a REAL file at a NONEXISTENT line is refused — the §10
// guard verifies the cited line exists, not merely the file (the review found the file-only hole).
func TestCodeAgent_GroundingRequiresRealLine(t *testing.T) {
	cc := &Context{Source: sqliRepo(), Findings: []types.Finding{{ID: "f1"}}}
	// sqliRepo's file has ~6 lines; line 4 exists, line 9999 does not.
	if ok, _ := cc.evidenceGrounded([]string{"api/handler.go:4"}); !ok {
		t.Error("a real file:line must ground")
	}
	if ok, _ := cc.evidenceGrounded([]string{"api/handler.go:9999"}); ok {
		t.Error("a real file at a NONEXISTENT line must NOT ground (file-only is not enough)")
	}
	// a malformed/overflow line suffix is a bad citation → not grounded, and crucially NEVER crashes or
	// produces a negative line (the reason for the safe strconv parse).
	if ok, _ := cc.evidenceGrounded([]string{"api/handler.go:99999999999999999999"}); ok {
		t.Error("an overflow/malformed line suffix must not ground")
	}
	// a bare path (no line) still grounds on a real file with content.
	if ok, _ := cc.evidenceGrounded([]string{"api/handler.go"}); !ok {
		t.Error("a bare path to a real non-empty file must ground")
	}
}

// TestCodeAgent_RefusesUngroundedRecord: record_issue WITHOUT readable evidence is rejected — the agent
// cannot assert exploitability from the finding text alone (§10 anti-hallucination). A later grounded record
// succeeds, proving the guard blocks only the ungrounded attempt.
func TestCodeAgent_RefusesUngroundedRecord(t *testing.T) {
	cc := &Context{
		Repo:     "acme/api",
		Source:   sqliRepo(),
		Findings: []types.Finding{{ID: "f1", Tool: "semgrep", Severity: types.SeverityHigh, Endpoint: "api/handler.go:4"}},
	}
	llm := &scriptedLLM{replies: []string{
		// ungrounded: no evidence at all → REJECTED.
		`{"tool":"record_issue","args":{"finding_id":"f1","exploitable":true,"rationale":"looks bad"}}`,
		// ungrounded: cites a file that doesn't exist → REJECTED.
		`{"tool":"record_issue","args":{"finding_id":"f1","exploitable":true,"evidence":["nope/ghost.go:9"]}}`,
		// now grounded → accepted.
		`{"tool":"record_issue","args":{"finding_id":"f1","exploitable":true,"evidence":["api/handler.go:4"]}}`,
		`{"tool":"finish","args":{"summary":"done"}}`,
	}}

	rep, err := Investigate(context.Background(), llm, cc, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Issues) != 1 {
		t.Fatalf("only the GROUNDED record should have been accepted, got %d issues", len(rep.Issues))
	}
	// an unknown finding_id is also refused.
	cc2 := &Context{Source: sqliRepo(), Findings: cc.Findings}
	got := tRecordIssue(cc2, map[string]any{"finding_id": "ghost", "evidence": []any{"api/handler.go:4"}})
	if len(cc2.Issues) != 0 {
		t.Errorf("unknown finding_id must be refused, recorded: %s", got)
	}
}
