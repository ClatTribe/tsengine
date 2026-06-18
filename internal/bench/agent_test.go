package bench

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestScoreAgent_PerfectRun(t *testing.T) {
	obj := &AgentObjectives{
		Target: "t",
		Objectives: []AgentObjective{
			{ID: "o1", Category: "sqli", Endpoint: "/login", MustVerify: true},
			{ID: "o2", Category: "idor", Endpoint: "/api/orders/", MustVerify: true},
			{ID: "o3", Category: "xss", Endpoint: "/search"},
		},
		Decoys: []AgentObjective{{ID: "d1", Category: "xss", Endpoint: "/static/"}},
	}
	scan := &types.Scan{FindingsEnriched: []types.Finding{
		{RuleID: "r1", CWE: []string{"CWE-89"}, Endpoint: "/login", VerificationStatus: types.VerificationVerified},
		{RuleID: "r2", CWE: []string{"CWE-639"}, Endpoint: "/api/orders/5", VerificationStatus: types.VerificationVerified},
		{RuleID: "r3", CWE: []string{"CWE-79"}, Endpoint: "/search?q=", VerificationStatus: types.VerificationCorroborated},
	}}

	rep := ScoreAgent(obj, scan)
	if !rep.Pass {
		t.Fatalf("want pass, got fail: %s", rep.Reason)
	}
	if rep.Score.DetectionRate != 1.0 {
		t.Errorf("detection_rate: want 1.0, got %v", rep.Score.DetectionRate)
	}
	if rep.Score.Verified != 2 || rep.Score.MustVerifyMet != 2 {
		t.Errorf("verified/must-verify wrong: %+v", rep.Score)
	}
	if rep.Score.Completed != 3 { // 2 verified + 1 corroborated = all grounded
		t.Errorf("completed: want 3, got %d", rep.Score.Completed)
	}
	if rep.Score.FalsePositives != 0 {
		t.Errorf("unexpected FP: %+v", rep.Score)
	}
	if rep.Competitors.Leaderboard == "" {
		t.Error("missing default competitor cite")
	}
	if out := RenderAgent(rep); !strings.Contains(out, "competitors:") || !strings.Contains(out, "XBOW") {
		t.Errorf("report must cite competitors, got:\n%s", out)
	}
}

func TestScoreAgent_MissFPAndUnverified(t *testing.T) {
	obj := &AgentObjectives{
		Target: "t",
		Objectives: []AgentObjective{
			{ID: "o1", Category: "sqli", Endpoint: "/login", MustVerify: true},
			{ID: "o2", Category: "ssrf", Endpoint: "/fetch", MustVerify: true},
		},
		Decoys: []AgentObjective{{ID: "d1", Category: "redirect", Endpoint: "/out"}},
	}
	scan := &types.Scan{FindingsEnriched: []types.Finding{
		// o1 found but only pattern_match → must-verify not met
		{RuleID: "r1", CWE: []string{"CWE-89"}, Endpoint: "/login", VerificationStatus: types.VerificationPatternMatch},
		// o2 (ssrf /fetch) absent → missed
		// decoy flagged → false positive
		{RuleID: "r9", CWE: []string{"CWE-601"}, Endpoint: "/out", VerificationStatus: types.VerificationPatternMatch},
	}}

	rep := ScoreAgent(obj, scan)
	if rep.Pass {
		t.Fatalf("want fail, got pass")
	}
	if rep.Score.Found != 1 {
		t.Errorf("found: want 1, got %d", rep.Score.Found)
	}
	if rep.Score.FalsePositives != 1 || len(rep.Score.FlaggedDecoys) != 1 {
		t.Errorf("FP: want 1, got %+v", rep.Score)
	}
	if len(rep.Score.Missed) != 1 || rep.Score.Missed[0] != "o2" {
		t.Errorf("missed: want [o2], got %v", rep.Score.Missed)
	}
	if len(rep.Score.UnverifiedMust) != 1 || rep.Score.UnverifiedMust[0] != "o1" {
		t.Errorf("unverified must-verify: want [o1], got %v", rep.Score.UnverifiedMust)
	}
}

func TestScoreAgent_RuleIDMatchAndRawFallback(t *testing.T) {
	obj := &AgentObjectives{
		Target:     "t",
		Objectives: []AgentObjective{{ID: "o1", RuleID: "nuclei::sqli-error-based", MustVerify: false}},
	}
	// No enriched findings → scorer falls back to raw.
	scan := &types.Scan{FindingsRaw: []types.Finding{
		{RuleID: "nuclei::sqli-error-based", Endpoint: "/x", VerificationStatus: types.VerificationCorroborated},
	}}
	rep := ScoreAgent(obj, scan)
	if !rep.Pass || rep.Score.Found != 1 {
		t.Fatalf("rule-id match over raw fallback failed: %+v (%s)", rep.Score, rep.Reason)
	}
}

func TestLoadAgentObjectives_Example(t *testing.T) {
	o, err := LoadAgentObjectives("../../fixtures/agent/objectives.example.json")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if len(o.Objectives) == 0 || o.Competitors.Leaderboard == "" {
		t.Errorf("example fixture malformed: %+v", o)
	}
}
