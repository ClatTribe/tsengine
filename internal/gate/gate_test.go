package gate

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/reachability"
	"github.com/ClatTribe/tsengine/internal/report"
)

var now = time.Date(2026, 6, 4, 12, 0, 0, 0, time.UTC)

func TestDefaultPolicy_BlocksHighAndVerifiedAndReachable(t *testing.T) {
	findings := []Finding{
		{ID: "1", Title: "info note", Severity: "low", Source: "scan"},                       // ok
		{ID: "2", Title: "XSS", Severity: "high", Source: "web", Verified: true},             // fails: high + verified
		{ID: "3", Title: "CVE in dep", Severity: "critical", Source: "sca", Reachable: true}, // fails: reachable
		{ID: "4", Title: "CVE in unused dep", Severity: "critical", Source: "sca"},           // critical BUT unreachable → NOT gated (reachability wins)
	}
	r := Evaluate(findings, DefaultPolicy(), nil, now)
	if r.Passed {
		t.Fatalf("default policy should FAIL with high/verified/reachable findings: %+v", r)
	}
	// neither the low finding nor the UNREACHABLE critical CVE may be a violation.
	for _, v := range r.Violations {
		if v.Title == "info note" {
			t.Error("a low-severity finding was wrongly gated")
		}
		if v.Title == "CVE in unused dep" {
			t.Error("an UNREACHABLE critical CVE was gated — defeats reachability triage")
		}
	}
	if r.Gated != 4 {
		t.Errorf("gated = %d, want 4 (all evaluated)", r.Gated)
	}
	if len(r.Violations) != 2 {
		t.Errorf("want exactly 2 violations (verified web + reachable sca); got %d", len(r.Violations))
	}
}

func TestPass_WhenAllBelowThreshold(t *testing.T) {
	findings := []Finding{
		{ID: "1", Title: "a", Severity: "low", Source: "scan"},
		{ID: "2", Title: "b", Severity: "medium", Source: "scan"},
	}
	p := Policy{FailOnSeverity: "high", FailOnVerified: true, FailOnReachableSCA: true, MaxNewFindings: -1}
	r := Evaluate(findings, p, nil, now)
	if !r.Passed {
		t.Fatalf("should PASS: only low+medium; got %+v", r)
	}
}

func TestReachableGatesEvenAtLowSeverity(t *testing.T) {
	// a reachable dependency CVE labeled "low" still fails when FailOnReachableSCA —
	// reachability outranks the severity label (the whole point).
	findings := []Finding{{ID: "1", Title: "CVE-x", Severity: "low", Source: "sca", Reachable: true}}
	p := Policy{FailOnSeverity: "critical", FailOnReachableSCA: true, MaxNewFindings: -1}
	r := Evaluate(findings, p, nil, now)
	if r.Passed {
		t.Fatalf("reachable low-sev CVE should fail FailOnReachableSCA: %+v", r)
	}
	if !strings.Contains(r.Violations[0].Reason, "reachable") {
		t.Errorf("reason should cite reachability: %q", r.Violations[0].Reason)
	}
}

func TestBaseline_NewOnly_IgnoresExistingDebt(t *testing.T) {
	existing := Finding{ID: "1", Title: "old high", Severity: "high", Source: "scan"}
	fresh := Finding{ID: "2", Title: "new high", Severity: "high", Source: "scan"}
	baseline := map[string]bool{Fingerprint(existing): true}

	p := Policy{FailOnSeverity: "high", NewOnly: true, MaxNewFindings: -1}
	r := Evaluate([]Finding{existing, fresh}, p, baseline, now)
	if r.Passed {
		t.Fatalf("the NEW high finding should fail: %+v", r)
	}
	if r.Existing != 1 || r.New != 1 {
		t.Errorf("expected 1 existing + 1 new; got existing=%d new=%d", r.Existing, r.New)
	}
	// with only the existing finding, new-only must PASS (no new risk)
	r2 := Evaluate([]Finding{existing}, p, baseline, now)
	if !r2.Passed {
		t.Errorf("pre-existing debt under new-only should PASS: %+v", r2)
	}
}

func TestMaxNewFindings(t *testing.T) {
	fs := []Finding{
		{ID: "1", Title: "a", Severity: "low", Source: "scan"},
		{ID: "2", Title: "b", Severity: "low", Source: "scan"},
		{ID: "3", Title: "c", Severity: "low", Source: "scan"},
	}
	// no severity gate, but cap new findings at 2 → 3 new fails
	p := Policy{FailOnSeverity: "", MaxNewFindings: 2}
	r := Evaluate(fs, p, nil, now)
	if r.Passed {
		t.Fatalf("3 new > 2 allowed should FAIL: %+v", r)
	}
	if !strings.Contains(r.Violations[len(r.Violations)-1].Reason, "too many new") {
		t.Errorf("expected a too-many-new violation: %+v", r.Violations)
	}
}

func TestWaiver_SuppressesUntilExpiry(t *testing.T) {
	f := Finding{ID: "1", Title: "accepted high", Severity: "high", Source: "scan"}
	fp := Fingerprint(f)
	p := Policy{
		FailOnSeverity: "high", MaxNewFindings: -1,
		Waivers: []Waiver{{Fingerprint: fp, Reason: "risk accepted", Expires: "2026-12-31T00:00:00Z"}},
	}
	// active waiver → suppressed → PASS
	if r := Evaluate([]Finding{f}, p, nil, now); !r.Passed || r.Waived != 1 {
		t.Fatalf("active waiver should suppress: %+v", r)
	}
	// after expiry → not suppressed → FAIL
	later := time.Date(2027, 1, 1, 0, 0, 0, 0, time.UTC)
	if r := Evaluate([]Finding{f}, p, nil, later); r.Passed {
		t.Fatalf("expired waiver must not suppress: %+v", r)
	}
}

func TestFromReport_And_FromReachability(t *testing.T) {
	rep := &report.Report{
		Kind: "Web Application Penetration Test", Target: "http://x",
		Findings: []report.Finding{
			{ID: "web-1", Title: "SQL Injection", Severity: "high", Status: "verified"},
			{ID: "web-2", Title: "Open Redirect", Severity: "medium", Status: "pattern_match"},
		},
	}
	gf := FromReport(rep)
	if len(gf) != 2 || gf[0].Source != "web" || !gf[0].Verified {
		t.Fatalf("FromReport wrong: %+v", gf)
	}

	tr := []reachability.TriageResult{
		{Finding: reachability.SCAFinding{ID: "CVE-1", CVE: "CVE-2026-1", Package: "x/y", Severity: "high"}, Priority: "reachable"},
		{Finding: reachability.SCAFinding{ID: "CVE-2", CVE: "CVE-2026-2", Package: "a/b", Severity: "critical"}, Priority: "unused"},
	}
	sf := FromReachability(tr)
	if len(sf) != 2 || sf[0].Source != "sca" || !sf[0].Reachable || sf[1].Reachable {
		t.Fatalf("FromReachability wrong: %+v", sf)
	}

	// end-to-end: gate the combined set with the default policy → fails (reachable + verified high)
	all := append(gf, sf...)
	r := Evaluate(all, DefaultPolicy(), nil, now)
	if r.Passed {
		t.Errorf("combined set should fail default policy: %+v", r)
	}
	gh := RenderGitHub(r)
	if !strings.Contains(gh, "::error") || !strings.Contains(gh, "::notice::tsengine gate FAILED") {
		t.Errorf("github annotations malformed:\n%s", gh)
	}
}
