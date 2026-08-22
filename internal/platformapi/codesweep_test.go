package platformapi

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/asset"
	"github.com/ClatTribe/tsengine/internal/codesweep"
	"github.com/ClatTribe/tsengine/internal/consensus"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func cand(vuln bool, sev string) codesweep.Candidate {
	return codesweep.Candidate{
		Task:       codesweep.Task{Path: "internal/api/handler.go", CWE: "CWE-89"},
		Vulnerable: vuln, Severity: sev, Title: "SQL built by string concatenation",
		Rationale: "the query is assembled from the request parameter",
		Evidence:  []string{"internal/api/handler.go:42"},
	}
}

// A model reading source and arguing a weakness exists is NOT a verified finding. In this codebase
// "verified" means a predicate RAN, and nothing here executed anything — so the rung must be
// pattern_match, the same as an unconfirmed scanner regex.
func TestSweepFindings_NeverClaimsVerified(t *testing.T) {
	fs := sweepFindings(codesweep.Result{Candidates: []codesweep.Candidate{cand(true, "high")}, Planned: 1, Ran: 1}, "acme/api", time.Now())
	if len(fs) != 1 {
		t.Fatalf("expected one finding, got %d", len(fs))
	}
	if fs[0].VerificationStatus == types.VerificationVerified {
		t.Fatal("an LLM proposal was recorded as verified — nothing executed to prove it")
	}
	if fs[0].VerificationStatus != types.VerificationPatternMatch {
		t.Errorf("unexpected rung %q", fs[0].VerificationStatus)
	}
	// The reader sees the text, not the enum, so the limit has to be in the text too.
	if !strings.Contains(fs[0].Description, "not by a scanner") {
		t.Errorf("the description must say what produced this: %q", fs[0].Description)
	}
}

// A candidate the sweep judged NOT vulnerable must not become a finding. Recording the negatives
// would turn a clean sweep into a wall of alerts.
func TestSweepFindings_NonVulnerableIsNotRecorded(t *testing.T) {
	fs := sweepFindings(codesweep.Result{Candidates: []codesweep.Candidate{cand(false, "high")}, Planned: 1, Ran: 1}, "acme/api", time.Now())
	if len(fs) != 0 {
		t.Errorf("a non-vulnerable candidate was recorded: %+v", fs)
	}
}

// A CAPPED sweep must declare the cap. Rendered as a result list, a partial sweep reads as "we
// looked at your repository" when we looked at part of it.
func TestSweepFindings_PartialSweepDeclaresItsCoverage(t *testing.T) {
	fs := sweepFindings(codesweep.Result{Planned: 200, Ran: 40}, "acme/api", time.Now())
	if len(fs) != 1 {
		t.Fatalf("a partial sweep with no candidates must still disclose: %+v", fs)
	}
	if !strings.HasPrefix(fs[0].RuleID, asset.CoverageRulePrefix) {
		t.Errorf("the disclosure must carry the coverage namespace, got %q", fs[0].RuleID)
	}
	if fs[0].Severity != types.SeverityInfo {
		t.Errorf("a coverage disclosure asserts an absence of testing, so it is informational: %q", fs[0].Severity)
	}
	if !strings.Contains(fs[0].Description, "40 of 200") {
		t.Errorf("the disclosure must state the real numbers: %q", fs[0].Description)
	}
}

// A COMPLETE sweep must NOT emit the disclosure: announcing a gap that does not exist is the same
// overclaim pointed the other way, and it would fire on every full sweep.
func TestSweepFindings_CompleteSweepDeclaresNothing(t *testing.T) {
	fs := sweepFindings(codesweep.Result{Candidates: []codesweep.Candidate{cand(true, "high")}, Planned: 12, Ran: 12}, "acme/api", time.Now())
	for _, f := range fs {
		if strings.HasPrefix(f.RuleID, asset.CoverageRulePrefix) {
			t.Errorf("a fully-run sweep declared a coverage gap: %+v", f)
		}
	}
}

// The evidence the disposer verified must travel with the finding — it is what distinguishes this
// from an unanchored model claim.
func TestSweepFindings_CarriesTheVerifiedLocation(t *testing.T) {
	fs := sweepFindings(codesweep.Result{Candidates: []codesweep.Candidate{cand(true, "high")}, Planned: 1, Ran: 1}, "acme/api", time.Now())
	if !strings.Contains(fs[0].ToolArgs["evidence"], "handler.go:42") {
		t.Errorf("the confirmed location was dropped: %+v", fs[0].ToolArgs)
	}
}

// stubJurorLLM answers every juror prompt the same way, which is enough to drive the majority.
type stubJurorLLM struct {
	fp    bool
	calls int
}

func (s *stubJurorLLM) Generate(_ context.Context, _ string) (string, error) {
	s.calls++
	if s.fp {
		return `{"false_positive": true, "rationale": "the pattern does not apply here"}`, nil
	}
	return `{"false_positive": false, "rationale": "the sink is reachable from the handler"}`, nil
}

// The panel may drop a candidate, and this is the ONE place a consensus vote legitimately removes
// something: a sweep candidate is one model's proposal, not a tool-grounded finding, so a panel
// disagreeing is a second opinion on an opinion rather than an LLM overruling a scanner.
func TestPanelReview_DropsWhatTheMajorityRejects(t *testing.T) {
	llm := &stubJurorLLM{fp: true}
	kept, dropped := panelReview(context.Background(), llm, []codesweep.Candidate{cand(true, "high")})
	if len(dropped) != 1 || len(kept) != 0 {
		t.Errorf("a unanimously-rejected candidate survived: kept=%d dropped=%d", len(kept), len(dropped))
	}
	// RECOVERABLE, not just counted. §2.5 requires a dismissal to be auditable and overridable, and
	// this one is a panel of language models deleting a candidate finding — reporting only a number
	// would make an unreviewable deletion look like a tidy result.
	d := dropped[0]
	if d.Path == "" || d.Title == "" {
		t.Errorf("the drop must name what was removed: %+v", d)
	}
	if len(d.Rationales) == 0 {
		t.Error("the jurors' reasoning was discarded — consensus.Decision.Rationales exists to be the audit trail")
	}
	if d.Votes == 0 {
		t.Error("the vote must be recorded: a 2-1 removal and a unanimous one are different grounds for trusting it")
	}
	if llm.calls != len(consensus.Personas) {
		t.Errorf("expected one call per persona, got %d", llm.calls)
	}
}

// A panel that agrees the finding is real keeps it.
func TestPanelReview_KeepsWhatTheMajorityConfirms(t *testing.T) {
	kept, dropped := panelReview(context.Background(), &stubJurorLLM{fp: false}, []codesweep.Candidate{cand(true, "high")})
	if len(dropped) != 0 || len(kept) != 1 {
		t.Errorf("a confirmed candidate was dropped: kept=%d dropped=%d", len(kept), len(dropped))
	}
}

// FAIL OPEN. Every juror erroring is not evidence the finding is false — a deadlocked or broken
// panel must never be the reason a real weakness disappears.
func TestPanelReview_JurorFailureKeepsTheCandidate(t *testing.T) {
	kept, dropped := panelReview(context.Background(), brokenLLM{}, []codesweep.Candidate{cand(true, "high")})
	if len(dropped) != 0 || len(kept) != 1 {
		t.Errorf("a broken panel dropped a candidate: kept=%d dropped=%d", len(kept), len(dropped))
	}
}

type brokenLLM struct{}

func (brokenLLM) Generate(context.Context, string) (string, error) {
	return "", errBroken
}

var errBroken = fmt.Errorf("juror unavailable")
