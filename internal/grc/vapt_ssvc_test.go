package grc

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func ssvcFinding(id string, sev types.Severity, s *types.SSVC) types.Finding {
	return types.Finding{
		ID: id, RuleID: "grype::" + id, Tool: "grype", Severity: sev, Title: "CVE " + id,
		VerificationStatus: "corroborated", ThreatIntel: &types.ThreatIntel{CVSS: 8.0, SSVC: s},
	}
}

// THE BUG THIS CLOSES IN THE PLAN. CISA saying exploitation is ACTIVE is the same claim KEV makes,
// from the same authority, for a CVE it has not catalogued. Without an SSVC rung, such a finding
// ranked BELOW one with a merely published PoC — absence of evidence in our KEV feed read as
// evidence of absence.
func TestRoadmap_SSVCActiveOutranksAMerePublicExploit(t *testing.T) {
	active := ssvcFinding("f-ssvc", types.SeverityHigh, &types.SSVC{Exploitation: "active"})
	pocOnly := types.Finding{
		ID: "f-poc", RuleID: "grype::poc", Tool: "grype", Severity: types.SeverityHigh,
		Title: "Other", VerificationStatus: "corroborated",
		ThreatIntel: &types.ThreatIntel{Exploits: []string{"exploitdb:EDB-1"}},
	}
	steps := BuildRoadmap([]types.Finding{pocOnly, active}, nil)
	if steps[0].Findings[0] != "f-ssvc" {
		t.Fatalf("CISA-active finding should lead a mere published PoC, got order %v then %v",
			steps[0].Findings, steps[1].Findings)
	}
	if !containsSubstr(steps[0].Why, "ACTIVE") {
		t.Errorf("the reason must cite CISA's assessment, got %v", steps[0].Why)
	}
}

// KEV still outranks SSVC-active: it carries a federal remediation mandate and a stricter
// cataloguing bar. Same ordering internal/threatinformed uses for probes (KEV +100 > SSVC +75).
func TestRoadmap_KEVStillOutranksSSVCActive(t *testing.T) {
	kev := types.Finding{ID: "f-kev", RuleID: "r1", Tool: "grype", Severity: types.SeverityHigh,
		Title: "kev", VerificationStatus: "corroborated",
		ThreatIntel: &types.ThreatIntel{KEV: &types.KEVStatus{Listed: true}}}
	steps := BuildRoadmap([]types.Finding{ssvcFinding("f-ssvc", types.SeverityHigh,
		&types.SSVC{Exploitation: "active"}), kev}, nil)
	if steps[0].Findings[0] != "f-kev" {
		t.Fatalf("KEV should still lead SSVC-active, got %v", steps[0].Findings)
	}
}

// Automatable separates two findings nothing else can. It is the tiebreak, and it is a stated reason.
func TestRoadmap_AutomatableBreaksTheTie(t *testing.T) {
	plain := ssvcFinding("f-plain", types.SeverityHigh, &types.SSVC{Automatable: "no"})
	auto := ssvcFinding("f-auto", types.SeverityHigh, &types.SSVC{Automatable: "yes"})
	steps := BuildRoadmap([]types.Finding{plain, auto}, nil)
	if steps[0].Findings[0] != "f-auto" {
		t.Fatalf("automatable should break the tie, got %v", steps[0].Findings)
	}
	if !containsSubstr(steps[0].Why, "automatable") {
		t.Errorf("automatable must be a stated reason, got %v", steps[0].Why)
	}
}

// Recorded VERBATIM and surfaced in both media — including the NO, which is the half that
// discriminates between two findings with identical CVSS and neither on KEV.
func TestReports_RenderSSVCIncludingTheNegative(t *testing.T) {
	yes := ssvcFinding("f-1", types.SeverityCritical,
		&types.SSVC{Exploitation: "active", Automatable: "yes", TechnicalImpact: "total"})
	no := ssvcFinding("f-2", types.SeverityLow, &types.SSVC{Automatable: "no"})
	r := ReportFromFindings([]types.Finding{yes, no}, []string{"img"}, "Acme", time.Now().UTC(), nil)

	if r.Summary.Automatable != 1 {
		t.Errorf("automatable count = %d, want 1", r.Summary.Automatable)
	}
	for name, out := range map[string]string{"markdown": RenderVAPTMarkdown(r), "html": RenderVAPTHTML(r)} {
		for _, want := range []string{"automatable (CISA SSVC)", "not automatable (CISA SSVC)",
			"1 automatable"} {
			if !strings.Contains(out, want) {
				t.Errorf("%s missing %q", name, want)
			}
		}
		if !strings.Contains(strings.ToLower(out), "exploitation: active") {
			t.Errorf("%s missing the SSVC exploitation state", name)
		}
	}
}

// "none" is the ABSENCE of a signal. Recording it would put a reassuring word on every unassessed
// CVE — and we never compute an SSVC decision, only carry CISA's points.
func TestReport_SSVCNoneIsNotRendered(t *testing.T) {
	r := ReportFromFindings([]types.Finding{ssvcFinding("f-1", types.SeverityLow,
		&types.SSVC{Exploitation: "none"})}, []string{"img"}, "Acme", time.Now().UTC(), nil)
	if r.Findings[0].SSVCExploitation != "" {
		t.Errorf("exploitation:none should not be carried, got %q", r.Findings[0].SSVCExploitation)
	}
	if strings.Contains(RenderVAPTMarkdown(r), "SSVC exploitation") {
		t.Error("an unassessed CVE must not carry an exploitation claim")
	}
}

// A finding with no SSVC at all renders nothing — and the summary line stays absent.
func TestReport_NoSSVCRendersNothing(t *testing.T) {
	r := ReportFromFindings([]types.Finding{{ID: "f-1", RuleID: "r", Tool: "t",
		Severity: types.SeverityLow, Title: "x"}}, []string{"img"}, "Acme", time.Now().UTC(), nil)
	for _, out := range []string{RenderVAPTMarkdown(r), RenderVAPTHTML(r)} {
		if strings.Contains(out, "SSVC") || strings.Contains(out, "automatable") {
			t.Error("a finding without SSVC data must not mention it")
		}
	}
}
