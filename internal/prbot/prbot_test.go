package prbot

import (
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
