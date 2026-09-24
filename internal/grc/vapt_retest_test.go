package grc

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// vapt_retest_test.go covers the exploit re-test surfacing (#1): the "did the fix hold?" verdict on
// the document the customer forwards. It must state closed / still-exploitable / unverifiable
// distinctly, and NEVER let an unverifiable re-test read as a confirmed fix.

func retestReport(t *testing.T) *VAPTReport {
	t.Helper()
	fs := []types.Finding{
		{ID: "f1", RuleID: "web::sqli", Endpoint: "https://app.test/a", Severity: types.SeverityHigh,
			Title: "SQLi", VerificationStatus: "verified"},
		{ID: "f2", RuleID: "web::idor", Endpoint: "https://app.test/b", Severity: types.SeverityHigh,
			Title: "IDOR", VerificationStatus: "verified"},
		{ID: "f3", RuleID: "web::xss", Endpoint: "https://app.test/c", Severity: types.SeverityMedium,
			Title: "XSS", VerificationStatus: "verified"},
	}
	return ReportFromFindings(fs, []string{"app.test"}, "Acme", time.Now().UTC(), nil)
}

func TestApplyRetests_CountsAndStampsPerFinding(t *testing.T) {
	r := retestReport(t)
	ApplyRetests(r, []RetestOutcome{
		{Key: "web::sqli|https://app.test/a", Status: "closed_with_proof", Evidence: "no longer succeeds", At: time.Now()},
		{Key: "web::idor|https://app.test/b", Status: "still_exploitable", Evidence: "still returns victim data", At: time.Now()},
		{Key: "web::xss|https://app.test/c", Status: "unverifiable", Evidence: "prober off", At: time.Now()},
	})
	if r.Summary.ExploitRetestClosed != 1 || r.Summary.ExploitRetestStillExploitable != 1 || r.Summary.ExploitRetestUnverifiable != 1 {
		t.Fatalf("summary counts wrong: %+v", r.Summary)
	}
	if r.Summary.ExploitRetestedAt.IsZero() {
		t.Error("ExploitRetestedAt not stamped")
	}
	byID := map[string]string{}
	for _, f := range r.Findings {
		byID[f.ID] = f.ExploitRetest
	}
	if byID["f1"] != "closed_with_proof" || byID["f2"] != "still_exploitable" || byID["f3"] != "unverifiable" {
		t.Fatalf("per-finding verdicts not stamped: %+v", byID)
	}
}

// An unverifiable re-test must NEVER be counted or worded as a confirmed fix — the false all-clear
// the whole chain refuses. An unknown status likewise falls to unverifiable, never to closed.
func TestApplyRetests_UnverifiableIsNeverClosed(t *testing.T) {
	r := retestReport(t)
	ApplyRetests(r, []RetestOutcome{
		{Key: "web::sqli|https://app.test/a", Status: "unverifiable"},
		{Key: "web::idor|https://app.test/b", Status: "some_new_status_we_dont_know"},
	})
	if r.Summary.ExploitRetestClosed != 0 {
		t.Fatalf("an unverifiable/unknown re-test was counted as closed: %+v", r.Summary)
	}
	if r.Summary.ExploitRetestUnverifiable != 2 {
		t.Fatalf("want 2 unverifiable, got %d", r.Summary.ExploitRetestUnverifiable)
	}
	md := RenderVAPTMarkdown(r)
	if strings.Contains(md, "fix proven closed") && r.Summary.ExploitRetestClosed == 0 {
		t.Error("report claims a fix proven closed when zero exploits were re-run clean")
	}
}

// The markdown deliverable states each verdict, in the words that make the claim honest: a closed
// exploit says "no longer succeeds", a still-exploitable one says "STILL succeeds / not closed".
func TestRenderVAPTMarkdown_StatesTheRetestVerdicts(t *testing.T) {
	r := retestReport(t)
	ApplyRetests(r, []RetestOutcome{
		{Key: "web::sqli|https://app.test/a", Status: "closed_with_proof", Evidence: "re-run: 403"},
		{Key: "web::idor|https://app.test/b", Status: "still_exploitable", Evidence: "re-run: victim row returned"},
	})
	md := RenderVAPTMarkdown(r)
	for _, want := range []string{"no longer succeeds", "STILL succeeds", "re-run: 403", "re-run: victim row returned"} {
		if !strings.Contains(md, want) {
			t.Errorf("report markdown missing %q", want)
		}
	}
	// The summary line distinguishes the exploit re-attack from the re-scan roll-up.
	if !strings.Contains(md, "Exploit re-test:") {
		t.Error("summary missing the distinct exploit re-test line")
	}
}

// No re-tests → nothing rendered and no counts (a report over an engagement that was never re-tested
// must not imply it was).
func TestApplyRetests_NoOpWhenEmpty(t *testing.T) {
	r := retestReport(t)
	ApplyRetests(r, nil)
	if r.Summary.ExploitRetestClosed+r.Summary.ExploitRetestStillExploitable+r.Summary.ExploitRetestUnverifiable != 0 {
		t.Fatal("empty re-test set produced counts")
	}
	if strings.Contains(RenderVAPTMarkdown(r), "Exploit re-test:") {
		t.Error("report mentions exploit re-test with no verdicts")
	}
}
