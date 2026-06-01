package cloudagent

import (
	"os"
	"path/filepath"
	"testing"
)

func TestReport_Score(t *testing.T) {
	rep := &Report{Issues: []Issue{
		{ID: "ai-001", Target: "pii"},
		{ID: "ai-002", Target: "admin"},
		{ID: "ai-003", Target: "not-real"}, // an invented target (shouldn't happen given grounding, but score it)
	}}
	// answer key: two real targets, one (fin) the agent missed.
	s := rep.Score([]string{"pii", "admin", "fin"})
	if s.RealFound != 2 || s.RealTotal != 3 {
		t.Errorf("found/total = %d/%d, want 2/3", s.RealFound, s.RealTotal)
	}
	if s.FalseIssues != 1 {
		t.Errorf("false issues = %d, want 1 (not-real)", s.FalseIssues)
	}
	if len(s.Missed) != 1 || s.Missed[0] != "fin" {
		t.Errorf("missed = %v, want [fin]", s.Missed)
	}
	if s.Pass {
		t.Error("should not pass (missed a target + invented one)")
	}

	// a clean report passes.
	clean := &Report{Issues: []Issue{{Target: "pii"}, {Target: "admin"}}}
	if cs := clean.Score([]string{"pii", "admin"}); !cs.Pass || cs.Recall != 1.0 {
		t.Errorf("clean report should pass at recall 1.0, got %+v", cs)
	}
}

func TestExportRemediations(t *testing.T) {
	rep := &Report{Issues: []Issue{
		{ID: "ai-001", FixKind: "iam_policy", FixContent: `{"Statement":[]}`},
		{ID: "ai-002", FixKind: "aws_cli", FixContent: "aws ec2 revoke-security-group-ingress ..."},
		{ID: "ai-003"}, // no fix → skipped
	}}
	dir := t.TempDir()
	n, err := ExportRemediations(rep, dir)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	if n != 2 {
		t.Fatalf("exported %d, want 2", n)
	}
	if _, err := os.Stat(filepath.Join(dir, "ai-001.json")); err != nil {
		t.Errorf("ai-001.json missing: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "ai-002.sh")); err != nil {
		t.Errorf("ai-002.sh missing: %v", err)
	}
}
