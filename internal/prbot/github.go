package prbot

import "context"

// GitHub posting (ADR 0010 Phase 2 wiring): turn a Review into the two GitHub API payloads — a
// PR review with inline comments, and a check-run that gates the merge — and submit them through
// an injected Poster. The payload builders are deterministic + offline-testable; the live POST is
// gated (it needs the GitHub App's PR-write scope), so a nil Poster computes the review without
// posting (the build-the-write-path / gate-the-live-call pattern, like cloud remediation).

// GitHubComment is one inline review comment (the new/RIGHT side of the diff).
type GitHubComment struct {
	Path string `json:"path"`
	Line int    `json:"line"`
	Side string `json:"side"`
	Body string `json:"body"`
}

// GitHubReviewPayload is the body for POST /repos/{owner}/{repo}/pulls/{n}/reviews.
type GitHubReviewPayload struct {
	Event    string          `json:"event"` // COMMENT | REQUEST_CHANGES
	Body     string          `json:"body"`
	Comments []GitHubComment `json:"comments"`
}

// CheckRunPayload is the body for POST /repos/{owner}/{repo}/check-runs.
type CheckRunPayload struct {
	Name       string `json:"name"`
	HeadSHA    string `json:"head_sha"`
	Status     string `json:"status"`     // always "completed" here
	Conclusion string `json:"conclusion"` // success | neutral | failure
	Output     struct {
		Title   string `json:"title"`
		Summary string `json:"summary"`
	} `json:"output"`
}

// ReviewPayload maps a Review to the GitHub PR-review body. A failing check requests changes
// (blocks the merge under branch protection); otherwise it's an informational comment.
func ReviewPayload(r Review) GitHubReviewPayload {
	event := "COMMENT"
	if r.Conclusion == "failure" {
		event = "REQUEST_CHANGES"
	}
	cs := make([]GitHubComment, 0, len(r.Comments))
	for _, c := range r.Comments {
		cs = append(cs, GitHubComment{Path: c.Path, Line: c.Line, Side: "RIGHT", Body: c.Body})
	}
	return GitHubReviewPayload{Event: event, Body: r.Summary, Comments: cs}
}

// CheckRunFor maps a Review to the check-run that gates the merge.
func CheckRunFor(r Review, headSHA string) CheckRunPayload {
	p := CheckRunPayload{Name: "tsengine/security", HeadSHA: headSHA, Status: "completed", Conclusion: r.Conclusion}
	p.Output.Title = "tsengine security review"
	p.Output.Summary = r.Summary
	return p
}

// Poster posts the review + check-run to GitHub. The real impl authenticates with the App /
// installation token (gated on the PR-write scope); tests inject a fake.
type Poster interface {
	PostReview(ctx context.Context, owner, repo string, pr int, p GitHubReviewPayload) error
	PostCheckRun(ctx context.Context, owner, repo string, p CheckRunPayload) error
}

// Submit posts the check-run (always — it carries the pass/fail gate) and, when there are inline
// findings, the review with comments. A nil Poster is a graceful no-op: the payloads are computed
// and returned for audit but nothing is posted (e.g. the App lacks the PR-write scope) — never a
// falsely-confident "posted". The check-run is posted before the review so a failure still gates
// the merge even if the comment post errors.
func Submit(ctx context.Context, r Review, owner, repo string, pr int, headSHA string, poster Poster) (GitHubReviewPayload, CheckRunPayload, error) {
	rev, chk := ReviewPayload(r), CheckRunFor(r, headSHA)
	if poster == nil {
		return rev, chk, nil
	}
	if err := poster.PostCheckRun(ctx, owner, repo, chk); err != nil {
		return rev, chk, err
	}
	if len(rev.Comments) > 0 {
		if err := poster.PostReview(ctx, owner, repo, pr, rev); err != nil {
			return rev, chk, err
		}
	}
	return rev, chk, nil
}
