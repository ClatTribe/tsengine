package l2

import (
	"context"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// fullDeps wires every L2 service so the catalog is at its maximum width —
// the worst case for the ≤12 cap.
func fullDeps() Deps {
	return Deps{
		Target:      webTarget(),
		L1Findings:  sampleFindings(),
		ThreatIntel: nil, // L2-3 fills externalTools; nil here is fine for L2-2
		Compliance:  nil,
		Prober:      nil,
		HTTP:        nil,
	}
}

func TestBuildCatalog_StaysUnderCapWithReportTools(t *testing.T) {
	c := BuildCatalog(fullDeps())
	if err := c.Validate(); err != nil {
		t.Fatalf("catalog must satisfy the ≤%d cap: %v", MaxCatalog, err)
	}
	// The committed L2 report tools are present.
	for _, name := range []string{"create_vulnerability_report", "update_finding", "record_hypothesis"} {
		if _, ok := c.find(name); !ok {
			t.Errorf("catalog should include %q", name)
		}
	}
}

func emit(t *testing.T, c Catalog, st *State, args map[string]any) ToolResult {
	t.Helper()
	tool, ok := c.find("create_vulnerability_report")
	if !ok {
		t.Fatal("create_vulnerability_report missing")
	}
	res, err := tool.Handler(context.Background(), args, st)
	if err != nil {
		t.Fatalf("handler: %v", err)
	}
	return res
}

func TestCreateReport_EmitsGroundedFinding(t *testing.T) {
	c := BuildCatalog(fullDeps())
	st := &State{Phase: PhaseInvestigate}
	res := emit(t, c, st, map[string]any{
		"title":                "Account takeover via SQLi",
		"severity":             "critical",
		"evidence_finding_ids": []string{"f-001"},
		"kill_chain":           "inject → dump creds → login",
		"plain_english":        "An attacker can read your database through the search box.",
		"remediation":          "Use parameterized queries.",
		"cwe":                  []string{"CWE-89"},
	})
	if res.Err {
		t.Fatalf("unexpected error: %s", res.Content)
	}
	if len(st.Findings) != 1 {
		t.Fatalf("want 1 emitted report, got %d", len(st.Findings))
	}
	f := st.Findings[0]
	if f.ID != "l2-001" || f.Tool != "l2" || f.Severity != types.SeverityCritical {
		t.Errorf("bad report header: %+v", f)
	}
	if f.L2 == nil || f.L2.KillChain == "" || f.L2.Remediation == "" {
		t.Fatalf("L2 narrative not stored: %+v", f.L2)
	}
	if len(f.L2.EvidenceIDs) != 1 || f.L2.EvidenceIDs[0] != "f-001" {
		t.Errorf("evidence not grounded: %v", f.L2.EvidenceIDs)
	}
	if f.L2.Verification != types.VerificationPatternMatch {
		t.Errorf("fresh report should be pattern_match, got %q", f.L2.Verification)
	}
}

func TestCreateReport_RejectsUngroundedEvidence(t *testing.T) {
	c := BuildCatalog(fullDeps())
	st := &State{}
	// Citing a non-existent L1 finding = invented evidence → rejected.
	res := emit(t, c, st, map[string]any{
		"title": "made up", "severity": "high",
		"evidence_finding_ids": []string{"f-999"},
		"plain_english":        "x",
	})
	if !res.Err {
		t.Error("citing an unknown finding id must be rejected (never invent)")
	}
	if len(st.Findings) != 0 {
		t.Error("no report should be emitted on ungrounded evidence")
	}
}

func TestCreateReport_RejectsMissingEvidenceAndBadSeverity(t *testing.T) {
	c := BuildCatalog(fullDeps())
	st := &State{}
	if res := emit(t, c, st, map[string]any{"title": "x", "severity": "high", "plain_english": "y"}); !res.Err {
		t.Error("missing evidence_finding_ids must be rejected")
	}
	if res := emit(t, c, st, map[string]any{
		"title": "x", "severity": "spicy", "evidence_finding_ids": []string{"f-001"}, "plain_english": "y",
	}); !res.Err {
		t.Error("invalid severity must be rejected")
	}
}

func TestUpdateFinding_RevisesInPlace(t *testing.T) {
	c := BuildCatalog(fullDeps())
	st := &State{}
	emit(t, c, st, map[string]any{
		"title": "SQLi", "severity": "high",
		"evidence_finding_ids": []string{"f-001"}, "plain_english": "orig",
	})
	uf, _ := c.find("update_finding")
	res, err := uf.Handler(context.Background(), map[string]any{
		"id": "l2-001", "severity": "critical", "plain_english": "clearer", "verified_by": []string{"send_request"},
	}, st)
	if err != nil || res.Err {
		t.Fatalf("update failed: %v %q", err, res.Content)
	}
	f := st.Findings[0]
	if f.Severity != types.SeverityCritical {
		t.Errorf("severity not updated: %q", f.Severity)
	}
	if f.L2.PlainEnglish != "clearer" || f.Description != "clearer" {
		t.Errorf("plain_english not synced: L2=%q desc=%q", f.L2.PlainEnglish, f.Description)
	}
	if len(f.L2.VerifiedBy) != 1 || f.L2.VerifiedBy[0] != "send_request" {
		t.Errorf("verified_by not recorded: %v", f.L2.VerifiedBy)
	}
}

func TestUpdateFinding_UnknownId(t *testing.T) {
	c := BuildCatalog(fullDeps())
	uf, _ := c.find("update_finding")
	res, _ := uf.Handler(context.Background(), map[string]any{"id": "l2-404", "severity": "low"}, &State{})
	if !res.Err {
		t.Error("updating an unknown id should error")
	}
}

func TestRecordHypothesis_PersistsAndSurvivesCompaction(t *testing.T) {
	c := BuildCatalog(fullDeps())
	st := &State{Phase: PhaseInvestigate}
	rh, _ := c.find("record_hypothesis")
	if _, err := rh.Handler(context.Background(), map[string]any{
		"statement": "f-001 SQLi may chain to account takeover",
		"next_step": "probe f-001 with sqlmap",
	}, st); err != nil {
		t.Fatalf("record_hypothesis: %v", err)
	}
	if len(st.Hypotheses) != 1 {
		t.Fatalf("hypothesis not persisted: %d", len(st.Hypotheses))
	}
	// The whole §2.7 justification: it must survive compaction.
	summary := compactionSummary(5, st)
	if !strings.Contains(summary, "account takeover") {
		t.Errorf("hypothesis should survive compaction in the summary:\n%s", summary)
	}
}
