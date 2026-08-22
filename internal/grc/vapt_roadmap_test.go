package grc

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func sca(id, pkg, installed, fixed string, sev types.Severity) types.Finding {
	return types.Finding{
		ID: id, RuleID: "grype::" + id, Tool: "grype", Severity: sev, Title: "CVE in " + pkg,
		VerificationStatus: "corroborated",
		ToolArgs:           map[string]string{"pkg": pkg, "installed_version": installed, "fixed_version": fixed},
	}
}

// Four CVEs in one package are ONE upgrade, not four jobs — and the step must say so.
func TestBuildRoadmap_GroupsOnePackageIntoOneStep(t *testing.T) {
	f := []types.Finding{
		sca("f-1", "lodash", "4.17.0", "4.17.19", types.SeverityMedium),
		sca("f-2", "lodash", "4.17.0", "4.17.21", types.SeverityHigh),
		sca("f-3", "lodash", "4.17.0", "4.17.5", types.SeverityLow),
	}
	steps := BuildRoadmap(f, nil)
	if len(steps) != 1 {
		t.Fatalf("want 1 step for one package, got %d", len(steps))
	}
	s := steps[0]
	if s.Closes != 3 || len(s.Findings) != 3 {
		t.Errorf("step should close all 3 findings, got Closes=%d ids=%v", s.Closes, s.Findings)
	}
	if s.Severity != "high" {
		t.Errorf("step severity should be the group's worst, got %q", s.Severity)
	}
	// The upgrade target must clear the WHOLE group — the highest fixed version, compared
	// numerically (4.17.21 > 4.17.5, which a lexical compare gets wrong).
	if !strings.Contains(s.Title, "4.17.21") {
		t.Errorf("title should name the highest fixed version, got %q", s.Title)
	}
}

// THE ordering claim: evidence of real exploitability outranks severity. A high we have an exploit
// for must come before a critical nobody has demonstrated.
func TestBuildRoadmap_ProvenExploitOutranksHigherSeverity(t *testing.T) {
	critical := types.Finding{
		ID: "f-crit", RuleID: "nuclei::rce", Tool: "nuclei", Severity: types.SeverityCritical,
		Title: "Theoretical RCE", VerificationStatus: "corroborated",
	}
	provenHigh := types.Finding{
		ID: "f-high", RuleID: "webagent::sqli", Tool: "web-investigate", Severity: types.SeverityHigh,
		Title: "SQLi", VerificationStatus: "verified",
		Description: "injectable\n[Exploitation PoC — boolean] 1=1 vs 1=2 differential confirmed.",
	}
	steps := BuildRoadmap([]types.Finding{critical, provenHigh}, nil)
	if steps[0].Findings[0] != "f-high" {
		t.Fatalf("proven high should lead the plan; order was %v/%v", steps[0].Findings, steps[1].Findings)
	}
	if !containsSubstr(steps[0].Why, "exploitation-proven") {
		t.Errorf("the reason must be stated, got %v", steps[0].Why)
	}
	if steps[0].Order != 1 || steps[1].Order != 2 {
		t.Errorf("orders should be 1,2 got %d,%d", steps[0].Order, steps[1].Order)
	}
}

// Unconfirmed (pattern-match-only) work goes LAST whatever its severity — chasing a possible false
// positive ahead of proven work is how a remediation week is wasted.
func TestBuildRoadmap_UnconfirmedGoesLastAndSaysWhy(t *testing.T) {
	unconfirmedCrit := types.Finding{
		ID: "f-u", RuleID: "nuclei::maybe", Tool: "nuclei", Severity: types.SeverityCritical,
		Title: "Possible RCE", VerificationStatus: "pattern_match",
	}
	confirmedLow := types.Finding{
		ID: "f-c", RuleID: "nuclei::hsts", Tool: "nuclei", Severity: types.SeverityLow,
		Title: "HSTS missing", VerificationStatus: "corroborated",
	}
	steps := BuildRoadmap([]types.Finding{unconfirmedCrit, confirmedLow}, nil)
	last := steps[len(steps)-1]
	if last.Findings[0] != "f-u" {
		t.Fatalf("unconfirmed critical should be last, got %v", last.Findings)
	}
	if !last.Validate {
		t.Error("unconfirmed step should be flagged for validation")
	}
	if !containsSubstr(last.Why, "validate it is real") {
		t.Errorf("must say why it is deprioritised, got %v", last.Why)
	}
}

// KEV/ransomware are recorded facts and must both drive the order and be quoted as the reason.
func TestBuildRoadmap_KEVAndRansomwareAreStatedReasons(t *testing.T) {
	due := time.Date(2021, 12, 24, 0, 0, 0, 0, time.UTC)
	kev := types.Finding{
		ID: "f-kev", RuleID: "grype::CVE-2021-44228", Tool: "grype", Severity: types.SeverityHigh,
		Title: "Log4Shell", VerificationStatus: "corroborated",
		ThreatIntel: &types.ThreatIntel{WeaponRank: "excellent",
			KEV: &types.KEVStatus{Listed: true, Ransomware: true, DueDate: due}},
	}
	plain := types.Finding{
		ID: "f-plain", RuleID: "nuclei::x", Tool: "nuclei", Severity: types.SeverityHigh,
		Title: "Other", VerificationStatus: "corroborated",
	}
	steps := BuildRoadmap([]types.Finding{plain, kev}, nil)
	if steps[0].Findings[0] != "f-kev" {
		t.Fatalf("KEV/ransomware finding should lead at equal severity, got %v", steps[0].Findings)
	}
	for _, want := range []string{"ransomware-linked", "actively exploited", "2021-12-24", "Metasploit"} {
		if !containsSubstr(steps[0].Why, want) {
			t.Errorf("reason %q missing from %v", want, steps[0].Why)
		}
	}
}

// THE REFUSAL. An effort/time estimate would be the most quotable number in the report and the
// least grounded; the plan must say so rather than quietly omitting it.
func TestRenderRoadmap_MakesNoEffortEstimate(t *testing.T) {
	steps := BuildRoadmap([]types.Finding{sca("f-1", "lodash", "4.17.0", "4.17.21", types.SeverityHigh)}, nil)
	md := RenderRoadmapMarkdown(steps)

	if !strings.Contains(md, "No effort or time estimates are given") {
		t.Error("the refusal must be stated, not merely enacted")
	}
	// Scan the STEPS ONLY. Scanning the whole document would let the disclaimer paragraph — which
	// necessarily contains the words "effort" and "time" — satisfy or excuse the check, giving a
	// test that cannot fail once the disclaimer exists.
	body := md
	if i := strings.Index(md, "### 1."); i >= 0 {
		body = md[i:]
	} else {
		t.Fatal("no step rendered — the scan below would be vacuous")
	}
	for _, bad := range []string{"hour", "day", "week", "effort", "story point", "sprint", "estimate"} {
		if strings.Contains(strings.ToLower(body), bad) {
			t.Errorf("a step appears to estimate effort (%q) — nothing grounds that", bad)
		}
	}
}

func TestRenderRoadmap_EmptyRendersNothing(t *testing.T) {
	if RenderRoadmapMarkdown(nil) != "" {
		t.Error("no steps should render no section, not an empty heading")
	}
}

// A prepared fix is a FACT (it exists, awaiting approval), not an effort estimate — it is allowed
// to inform the plan and must be surfaced.
func TestBuildRoadmap_SurfacesPreparedFix(t *testing.T) {
	f := []types.Finding{sca("f-1", "lodash", "4.17.0", "4.17.21", types.SeverityHigh)}
	steps := BuildRoadmap(f, map[string]bool{"f-1": true})
	if !steps[0].FixReady {
		t.Fatal("prepared fix not surfaced on the step")
	}
	if !containsSubstr(steps[0].Why, "already prepared") {
		t.Errorf("prepared fix should be a stated reason, got %v", steps[0].Why)
	}
}

func containsSubstr(hay []string, needle string) bool {
	for _, h := range hay {
		if strings.Contains(h, needle) {
			return true
		}
	}
	return false
}

// For a dependency CVE the customer's fix is a version bump, NOT the CWE-class advice. Rendering
// "never deserialize untrusted input" against a Log4Shell upgrade step is guidance for the
// library's author and the wrong instruction for the reader.
func TestBuildRoadmap_PackageStepSaysUpgradeNotClassAdvice(t *testing.T) {
	f := []types.Finding{{
		ID: "f-1", RuleID: "grype::CVE-2021-44228", Tool: "grype", Severity: types.SeverityCritical,
		Title: "Log4Shell", CWE: []string{"CWE-94"}, VerificationStatus: "corroborated",
		ToolArgs: map[string]string{"pkg": "log4j-core", "installed_version": "2.14.1", "fixed_version": "2.17.1"},
	}}
	act := BuildRoadmap(f, nil)[0].Action
	// Names current → target ("log4j-core@2.14.1 to 2.17.1"), which is what the reader needs.
	if !strings.Contains(act, "Upgrade log4j-core@2.14.1 to 2.17.1") {
		t.Errorf("package step should instruct the upgrade, got %q", act)
	}
	if strings.Contains(act, "deserialize") {
		t.Errorf("package step gave CWE-class advice instead of the upgrade: %q", act)
	}
}

// With no upstream fix, say so — never invent an upgrade target.
func TestBuildRoadmap_PackageWithNoFixSaysSo(t *testing.T) {
	f := []types.Finding{{
		ID: "f-1", RuleID: "grype::CVE-9", Tool: "grype", Severity: types.SeverityHigh, Title: "x",
		ToolArgs: map[string]string{"pkg": "leftpad", "installed_version": "1.0.0"},
	}}
	act := BuildRoadmap(f, nil)[0].Action
	if !strings.Contains(act, "No upstream fix is published") {
		t.Errorf("should state the absence of a fix, got %q", act)
	}
}
