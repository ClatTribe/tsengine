package prbot

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/pkg/types"
)

func reviewWith(findings []types.Finding, blockAt types.Severity) Review {
	changed := []ChangedFile{{Path: "app.go", Lines: map[int]bool{10: true, 20: true}}}
	return Build(findings, changed, blockAt)
}

func TestReviewPayload_EventAndComments(t *testing.T) {
	// A high finding on a changed line, block floor high → failure → REQUEST_CHANGES.
	r := reviewWith([]types.Finding{{RuleID: "sast::sqli", Severity: types.SeverityHigh, Endpoint: "app.go:10", Title: "SQLi"}}, types.SeverityHigh)
	p := ReviewPayload(r)
	if p.Event != "REQUEST_CHANGES" {
		t.Errorf("a failing review should REQUEST_CHANGES, got %q", p.Event)
	}
	if len(p.Comments) != 1 || p.Comments[0].Path != "app.go" || p.Comments[0].Line != 10 || p.Comments[0].Side != "RIGHT" {
		t.Errorf("inline comment mapping wrong: %+v", p.Comments)
	}

	// A medium finding below the floor → neutral → COMMENT (not REQUEST_CHANGES).
	rn := reviewWith([]types.Finding{{RuleID: "sast::style", Severity: types.SeverityMedium, Endpoint: "app.go:20"}}, types.SeverityHigh)
	if ev := ReviewPayload(rn).Event; ev != "COMMENT" {
		t.Errorf("a non-blocking review should COMMENT, got %q", ev)
	}
}

func TestCheckRunFor(t *testing.T) {
	r := reviewWith([]types.Finding{{Severity: types.SeverityCritical, Endpoint: "app.go:10", RuleID: "r"}}, types.SeverityHigh)
	c := CheckRunFor(r, "sha123")
	if c.Conclusion != "failure" || c.HeadSHA != "sha123" || c.Status != "completed" || c.Name == "" {
		t.Errorf("check-run payload wrong: %+v", c)
	}
}

type fakePoster struct {
	reviews   int
	checkRuns int
}

func (f *fakePoster) PostReview(context.Context, string, string, int, GitHubReviewPayload) error {
	f.reviews++
	return nil
}
func (f *fakePoster) PostCheckRun(context.Context, string, string, CheckRunPayload) error {
	f.checkRuns++
	return nil
}

func TestSubmit(t *testing.T) {
	// With findings on changed lines → both a check-run AND a review are posted.
	r := reviewWith([]types.Finding{{Severity: types.SeverityHigh, Endpoint: "app.go:10", RuleID: "r"}}, types.SeverityHigh)
	fp := &fakePoster{}
	if _, _, err := Submit(context.Background(), r, "o", "repo", 7, "sha", fp); err != nil {
		t.Fatalf("submit: %v", err)
	}
	if fp.checkRuns != 1 || fp.reviews != 1 {
		t.Errorf("expected 1 check-run + 1 review, got %d / %d", fp.checkRuns, fp.reviews)
	}

	// A clean PR (no findings on the diff) → a green check-run, NO review (don't spam).
	clean := Build([]types.Finding{{Severity: types.SeverityHigh, Endpoint: "app.go:999"}}, []ChangedFile{{Path: "app.go", Lines: map[int]bool{10: true}}}, types.SeverityHigh)
	fp2 := &fakePoster{}
	_, chk, _ := Submit(context.Background(), clean, "o", "repo", 7, "sha", fp2)
	if fp2.checkRuns != 1 || fp2.reviews != 0 {
		t.Errorf("clean PR → 1 check-run + 0 reviews, got %d / %d", fp2.checkRuns, fp2.reviews)
	}
	if chk.Conclusion != "success" {
		t.Errorf("clean PR check-run should be success, got %q", chk.Conclusion)
	}

	// nil poster → graceful no-op (payloads computed, nothing posted).
	rev, _, err := Submit(context.Background(), r, "o", "repo", 7, "sha", nil)
	if err != nil || len(rev.Comments) == 0 {
		t.Errorf("nil poster should compute the payload without error, got err=%v comments=%d", err, len(rev.Comments))
	}
}
