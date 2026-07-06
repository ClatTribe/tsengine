package bench

import (
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/correlate"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// scenario: a leaked key in code + a public cloud bucket (both closeable); one benign decoy that must be
// left alone. After the correct remediation both real findings are gone (the decoy remains — it's noise).
func leakedKeyScenario() DefenseScenario {
	before := []types.Finding{
		{ID: "f-secret", RuleID: "gitleaks::aws-key", Endpoint: "repo/config.py:12", Severity: types.SeverityHigh, Tool: "gitleaks"},
		{ID: "f-bucket", RuleID: "prowler::s3-public", Endpoint: "arn:aws:s3:::acme-pii", Severity: types.SeverityHigh, Tool: "prowler"},
		{ID: "f-decoy", RuleID: "semgrep::info-header", Endpoint: "repo/app.py:3", Severity: types.SeverityLow, Tool: "semgrep"},
	}
	after := []types.Finding{ // correct remediation removed the two real vulns; the low decoy remains
		{ID: "f-decoy", RuleID: "semgrep::info-header", Endpoint: "repo/app.py:3", Severity: types.SeverityLow, Tool: "semgrep"},
	}
	return DefenseScenario{
		ID: "leaked-key-to-cloud", Before: before, After: after,
		Decoys: []string{"semgrep::info-header|repo/app.py:3"},
	}
}

func actionFor(id, findingID string) platform.Action {
	return platform.Action{ID: id, FindingID: findingID, Kind: platform.ActOpenPR}
}

// TestScoreDefense_FullRemediationCapture: a SUT that proposes a fix for BOTH closeable findings closes
// everything closeable → RemediationRate 1.0, no decoy actions, nothing invented.
func TestScoreDefense_FullRemediationCapture(t *testing.T) {
	sc := leakedKeyScenario()
	proposed := []platform.Action{actionFor("a1", "f-secret"), actionFor("a2", "f-bucket")}
	s := ScoreDefense(sc, proposed, nil)
	if s.Closeable != 2 {
		t.Fatalf("closeable should be the 2 vulns gone Before→After, got %d", s.Closeable)
	}
	if s.Captured != 2 || s.RemediationRate != 1.0 {
		t.Errorf("both fixes should verify FIXED against the oracle, got captured=%d rate=%.2f", s.Captured, s.RemediationRate)
	}
	if s.DecoyActions != 0 || len(s.Invented) != 0 {
		t.Errorf("clean run should action no decoy + invent nothing, got decoy=%d invented=%v", s.DecoyActions, s.Invented)
	}
	if !s.Pass() {
		t.Errorf("a complete remediation with no expected paths should PASS: %s", RenderDefenseScore(s))
	}
}

// TestScoreDefense_PartialAndIneffective: a SUT that fixes only one vuln scores 0.5; a SUT that proposes a
// fix for a finding still present post-fix is counted as an ineffective fix, not a capture.
func TestScoreDefense_PartialAndIneffective(t *testing.T) {
	sc := leakedKeyScenario()

	// Only the secret is remediated → 1 of 2 closeable.
	half := ScoreDefense(sc, []platform.Action{actionFor("a1", "f-secret")}, nil)
	if half.Captured != 1 || half.RemediationRate != 0.5 {
		t.Errorf("one of two fixes → rate 0.5, got captured=%d rate=%.2f", half.Captured, half.RemediationRate)
	}
	if half.Pass() {
		t.Error("a partial remediation must not PASS")
	}

	// Propose a fix for the DECOY (still present in After) → ineffective fix + a decoy action, no capture.
	bad := ScoreDefense(sc, []platform.Action{actionFor("a3", "f-decoy")}, nil)
	if bad.Captured != 0 {
		t.Errorf("fixing a non-closeable finding is not a capture, got %d", bad.Captured)
	}
	if bad.DecoyActions != 1 {
		t.Errorf("actioning a decoy must be counted, got %d", bad.DecoyActions)
	}
	if bad.IneffectiveFixes != 1 {
		t.Errorf("a fix whose finding is still present post-fix is ineffective, got %d", bad.IneffectiveFixes)
	}
}

// TestScoreDefense_GroundingCatchesInvented: a recorded finding that exists in neither Before nor After is
// an invented (hallucinated) finding — the §10 anti-hallucination bar, XBOW's no-FP standard.
func TestScoreDefense_GroundingCatchesInvented(t *testing.T) {
	sc := leakedKeyScenario()
	recorded := []types.Finding{
		{RuleID: "gitleaks::aws-key", Endpoint: "repo/config.py:12"}, // real (in Before) → fine
		{RuleID: "made::up", Endpoint: "nowhere"},                    // invented → must be flagged
	}
	s := ScoreDefense(sc, nil, recorded)
	if len(s.Invented) != 1 || s.Invented[0] != "made::up|nowhere" {
		t.Errorf("the invented finding must be flagged, got %v", s.Invented)
	}
	if s.Pass() {
		t.Error("a run that invents a finding must never PASS")
	}
}

// TestMatchesPath: the cross-surface path signature matcher — an entry surface + a cloud target + an
// optional bridging entity, matched loosely against produced chains.
func TestMatchesPath(t *testing.T) {
	chains := []correlate.Chain{{Steps: []correlate.Step{
		{AssetType: "repository", Title: "leaked AWS key", ViaEntity: "aws_key AKIAEXAMPLE"},
		{AssetType: "cloud_account", Title: "admin role reachable", CrownJewel: true},
	}}}
	if !matchesPath(PathSig{EntrySurface: "repository", CloudTarget: "admin role", ViaEntity: "aws_key"}, chains) {
		t.Error("the code→cloud chain should match the expected signature")
	}
	if matchesPath(PathSig{EntrySurface: "repository", CloudTarget: "database"}, chains) {
		t.Error("a signature naming a different cloud target must NOT match")
	}
	if matchesPath(PathSig{EntrySurface: "api", CloudTarget: "admin role"}, chains) {
		t.Error("a signature naming a different entry surface must NOT match")
	}
}

// TestDefenseLedger_RoundTripAndAblation: append substrate + agent runs, reload, and confirm the summary
// keeps the two modes separate so the agent-lift delta is legible (the ablation is the whole point).
func TestDefenseLedger_RoundTripAndAblation(t *testing.T) {
	path := t.TempDir() + "/defense-ledger.jsonl"
	subScore := DefenseScore{ScenarioID: "s1", Closeable: 2, Captured: 1, RemediationRate: 0.5}
	agtScore := DefenseScore{ScenarioID: "s1", Closeable: 2, Captured: 2, RemediationRate: 1.0}
	if err := AppendDefenseLedger(path, DefenseEntryFromScore(subScore, "s1", "substrate")); err != nil {
		t.Fatal(err)
	}
	if err := AppendDefenseLedger(path, DefenseEntryFromScore(agtScore, "s1", "agent")); err != nil {
		t.Fatal(err)
	}
	// A missing mode must be rejected (the ablation is meaningless without it).
	if err := AppendDefenseLedger(path, DefenseLedgerEntry{ScenarioID: "s1"}); err == nil {
		t.Error("an entry with no mode must be rejected")
	}
	entries, err := LoadDefenseLedger(path)
	if err != nil || len(entries) != 2 {
		t.Fatalf("want 2 reloaded entries, got %d (%v)", len(entries), err)
	}
	byMode := SummarizeDefenseLedger(entries)
	if byMode["substrate"].BestRate["s1"] != 0.5 || byMode["agent"].BestRate["s1"] != 1.0 {
		t.Errorf("modes must stay separate: substrate=%.2f agent=%.2f",
			byMode["substrate"].BestRate["s1"], byMode["agent"].BestRate["s1"])
	}
	md := RenderDefenseLedgerMarkdown(entries)
	if !strings.Contains(md, "Agent lift") || !strings.Contains(md, "+50%") {
		t.Errorf("the rendered scoreboard must show the +50%% agent lift, got:\n%s", md)
	}
}
