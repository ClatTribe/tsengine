package prbot

import (
	"strconv"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestFileLine(t *testing.T) {
	cases := map[string][2]interface{}{
		"src/app.go:42":  {"src/app.go", 42},
		"a.go:7:13":      {"a.go", 7}, // col suffix ignored
		"config/x.yml:3": {"config/x.yml", 3},
		"https://x/y":    {"", 0}, // not a file:line → no PR comment
		"nofileorline":   {"", 0},
	}
	for in, want := range cases {
		p, l, ok := FileLine(in)
		if want[0] == "" {
			if ok {
				t.Errorf("FileLine(%q) should not parse, got %q:%d", in, p, l)
			}
			continue
		}
		if !ok || p != want[0] || l != want[1] {
			t.Errorf("FileLine(%q) = %q,%d,%v; want %v,%v", in, p, l, ok, want[0], want[1])
		}
	}
}

func TestBuild_OnlyChangedLinesGetComments(t *testing.T) {
	findings := []types.Finding{
		{RuleID: "semgrep::sqli", Severity: types.SeverityHigh, Endpoint: "app.go:10", Title: "SQL injection"},
		{RuleID: "semgrep::xss", Severity: types.SeverityMedium, Endpoint: "app.go:99", Title: "XSS"}, // not in diff
		{RuleID: "gitleaks::aws", Severity: types.SeverityCritical, Endpoint: "config.yml:3", Title: "AWS key"},
		{RuleID: "nuclei::x", Severity: types.SeverityHigh, Endpoint: "https://site/x"}, // not a file:line
	}
	changed := []ChangedFile{
		{Path: "app.go", Lines: map[int]bool{10: true, 11: true}},
		{Path: "./config.yml", Lines: map[int]bool{3: true}},
	}
	r := Build(findings, changed, types.SeverityHigh)

	// Only the two findings on changed lines become comments (app.go:99 + the URL finding excluded).
	if len(r.Comments) != 2 {
		t.Fatalf("want 2 comments (only changed lines), got %d: %+v", len(r.Comments), r.Comments)
	}
	// A critical (≥ the high block floor) on a changed line → the check fails.
	if r.Conclusion != "failure" {
		t.Errorf("a critical finding on a changed line should fail the check, got %q", r.Conclusion)
	}
	// Comments are sorted by path then line.
	if r.Comments[0].Path != "app.go" || r.Comments[0].Line != 10 {
		t.Errorf("comments should be sorted by path/line, got %+v", r.Comments)
	}
	if !strings.Contains(r.Comments[0].Body, "SQL injection") {
		t.Errorf("comment body should describe the finding, got %q", r.Comments[0].Body)
	}
}

func TestBuild_Conclusions(t *testing.T) {
	changed := []ChangedFile{{Path: "a.go", Lines: map[int]bool{5: true}}}

	// No findings on changed lines → success (green).
	clean := Build([]types.Finding{{Severity: types.SeverityHigh, Endpoint: "a.go:99"}}, changed, types.SeverityHigh)
	if clean.Conclusion != "success" {
		t.Errorf("no findings on the diff → success, got %q", clean.Conclusion)
	}
	if !strings.Contains(clean.Summary, "no new security findings") {
		t.Errorf("clean summary wrong: %q", clean.Summary)
	}

	// A medium on a changed line, block floor = high → neutral (present but non-blocking).
	med := Build([]types.Finding{{Severity: types.SeverityMedium, Endpoint: "a.go:5", RuleID: "r"}}, changed, types.SeverityHigh)
	if med.Conclusion != "neutral" {
		t.Errorf("a below-floor finding → neutral (non-blocking), got %q", med.Conclusion)
	}

	// Same medium, block floor = medium → failure.
	medBlock := Build([]types.Finding{{Severity: types.SeverityMedium, Endpoint: "a.go:5", RuleID: "r"}}, changed, types.SeverityMedium)
	if medBlock.Conclusion != "failure" {
		t.Errorf("lowering the block floor to medium should fail, got %q", medBlock.Conclusion)
	}
}

func TestBuild_DedupesSameRuleSameLine(t *testing.T) {
	changed := []ChangedFile{{Path: "a.go", Lines: map[int]bool{5: true}}}
	findings := []types.Finding{
		{Severity: types.SeverityHigh, Endpoint: "a.go:5", RuleID: "sqli"},
		{Severity: types.SeverityHigh, Endpoint: "a.go:5", RuleID: "sqli"}, // exact dup (re-run / two tools)
		{Severity: types.SeverityHigh, Endpoint: "a.go:5", RuleID: "xss"},  // different rule, same line → kept
	}
	r := Build(findings, changed, types.SeverityHigh)
	if len(r.Comments) != 2 {
		t.Fatalf("the duplicate (same rule+line) should collapse to 2 comments, got %d", len(r.Comments))
	}
}

func TestBuild_CapsAndRollsUp(t *testing.T) {
	old := MaxComments
	MaxComments = 3
	defer func() { MaxComments = old }()

	changed := []ChangedFile{{Path: "a.go", Lines: map[int]bool{}}}
	var findings []types.Finding
	for i := 1; i <= 10; i++ {
		changed[0].Lines[i] = true
		sev := types.SeverityLow
		if i <= 2 {
			sev = types.SeverityCritical // 2 criticals must survive the cap (most severe kept)
		}
		findings = append(findings, types.Finding{Severity: sev, Endpoint: "a.go:" + strconv.Itoa(i), RuleID: "r" + strconv.Itoa(i)})
	}
	r := Build(findings, changed, types.SeverityHigh)
	if len(r.Comments) != 3 {
		t.Fatalf("comments should be capped at MaxComments=3, got %d", len(r.Comments))
	}
	// The 2 criticals must be among the kept (cap keeps the most severe).
	crit := 0
	for _, c := range r.Comments {
		if c.Severity == types.SeverityCritical {
			crit++
		}
	}
	if crit != 2 {
		t.Errorf("the cap must keep the most-severe comments (2 criticals), got %d", crit)
	}
	// The check still fails (a critical is present) and the summary rolls up the dropped 7.
	if r.Conclusion != "failure" {
		t.Errorf("a capped-but-present critical should still fail the check, got %s", r.Conclusion)
	}
	if !strings.Contains(r.Summary, "7 more") {
		t.Errorf("summary should roll up the 7 dropped comments, got %q", r.Summary)
	}
}

func TestBuild_SummaryBreakdown(t *testing.T) {
	changed := []ChangedFile{{Path: "a.go", Lines: map[int]bool{5: true, 6: true}}}
	findings := []types.Finding{
		{Severity: types.SeverityCritical, Endpoint: "a.go:5", RuleID: "r1"},
		{Severity: types.SeverityMedium, Endpoint: "a.go:6", RuleID: "r2"},
	}
	r := Build(findings, changed, types.SeverityHigh)
	if !strings.Contains(r.Summary, "1 critical") || !strings.Contains(r.Summary, "1 medium") {
		t.Errorf("summary should carry the severity breakdown, got %q", r.Summary)
	}
}
