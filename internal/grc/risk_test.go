package grc

import (
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestCandidateRisks_GroupsAndGrounds(t *testing.T) {
	now := time.Date(2026, 6, 25, 0, 0, 0, 0, time.UTC)
	findings := []types.Finding{
		{ID: "f1", Tool: "sqlmap", Severity: types.SeverityCritical, CWE: []string{"CWE-89"}},
		{ID: "f2", Tool: "nuclei", Severity: types.SeverityHigh, CWE: []string{"CWE-79"}}, // same Injection category
		{ID: "f3", Tool: "trivy", Severity: types.SeverityHigh, CWE: []string{"CWE-1104"}},
		{ID: "f4", Tool: "x", Severity: types.SeverityMedium, CWE: []string{"CWE-89"}}, // below floor → ignored
		{ID: "f5", Tool: "x", Severity: types.SeverityLow},                             // ignored
	}
	got := CandidateRisks("t1", findings, now)

	if len(got) != 2 {
		t.Fatalf("want 2 candidate risks (Injection, Vulnerable dependencies), got %d: %+v", len(got), got)
	}
	// Deterministic order (sorted by category): "Injection" < "Vulnerable dependencies".
	inj := got[0]
	if inj.Category != "Injection" {
		t.Fatalf("first risk category = %q, want Injection", inj.Category)
	}
	// Grounding: cites exactly the contributing finding ids (f1,f2), never the below-floor ones.
	if len(inj.FindingIDs) != 2 || inj.FindingIDs[0] != "f1" || inj.FindingIDs[1] != "f2" {
		t.Fatalf("injection risk should cite [f1 f2], got %v", inj.FindingIDs)
	}
	// Impact = worst severity in the cluster (critical → 5).
	if inj.Impact != 5 {
		t.Errorf("injection impact = %d, want 5 (critical present)", inj.Impact)
	}
	// HITL: a candidate is Proposed, open, and carries NO treatment/owner until a human decides.
	if !inj.Proposed || inj.Status != platform.RiskOpen || inj.Treatment != "" || inj.Owner != "" {
		t.Errorf("candidate must be proposed+open+undecided, got %+v", inj)
	}
	if inj.ID != "risk-injection" {
		t.Errorf("deterministic id = %q, want risk-injection", inj.ID)
	}
}

func TestCandidateRisks_DeterministicReseed(t *testing.T) {
	now := time.Now()
	fs := []types.Finding{{ID: "f1", Severity: types.SeverityHigh, CWE: []string{"CWE-89"}}}
	a := CandidateRisks("t1", fs, now)
	b := CandidateRisks("t1", fs, now)
	if len(a) != 1 || len(b) != 1 || a[0].ID != b[0].ID {
		t.Fatalf("re-seeding must produce the same stable id, got %q vs %q", a[0].ID, b[0].ID)
	}
}

func TestRiskScoreAndLevel(t *testing.T) {
	cases := []struct {
		l, i  int
		score int
		level string
	}{
		{5, 5, 25, "critical"},
		{4, 5, 20, "critical"},
		{3, 4, 12, "high"},
		{2, 3, 6, "medium"},
		{1, 1, 1, "low"},
		{0, 9, 5, "low"}, // clamped: 1×5
	}
	for _, c := range cases {
		r := platform.Risk{Likelihood: c.l, Impact: c.i}
		if r.Score() != c.score {
			t.Errorf("Score(%d,%d)=%d want %d", c.l, c.i, r.Score(), c.score)
		}
		if r.Level() != c.level {
			t.Errorf("Level(%d,%d)=%q want %q", c.l, c.i, r.Level(), c.level)
		}
	}
}

func TestSummarize(t *testing.T) {
	risks := []platform.Risk{
		{ID: "a", Likelihood: 5, Impact: 5, Status: platform.RiskOpen, Proposed: true},
		{ID: "b", Likelihood: 2, Impact: 2, Status: platform.RiskAccepted},
		{ID: "c", Likelihood: 3, Impact: 4, Status: platform.RiskTreating},
	}
	s := Summarize(risks)
	if s.Total != 3 || s.Open != 1 || s.Accepted != 1 || s.Treating != 1 || s.Proposed != 1 {
		t.Fatalf("summary tallies wrong: %+v", s)
	}
	if s.TopRiskID != "a" { // highest score (25), not closed
		t.Errorf("top risk = %q, want a", s.TopRiskID)
	}
	if s.ByLevel["critical"] != 1 {
		t.Errorf("by_level critical = %d, want 1", s.ByLevel["critical"])
	}
}
