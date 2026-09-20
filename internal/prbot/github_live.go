package prbot

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// GitHubPoster is the LIVE Poster: it posts the review and the check-run with an installation
// token minted by the GitHub App (internal/connector/ghapp). Until this existed, `Submit` was only
// ever called with a nil Poster, so the "PR-inline review bot" computed its payloads and posted
// nothing — the merge gate worked from the CI job's exit code and the developer never saw a comment
// on the line.
//
// The token is a func, not a string: installation tokens live an hour and are minted per call
// (the App caches them), so the poster must not hold one.
type GitHubPoster struct {
	Token   func(ctx context.Context) (string, error)
	APIBase string       // default https://api.github.com
	HTTP    *http.Client // default http.DefaultClient
}

func (p *GitHubPoster) base() string {
	if p.APIBase == "" {
		return "https://api.github.com"
	}
	return strings.TrimRight(p.APIBase, "/")
}

func (p *GitHubPoster) client() *http.Client {
	if p.HTTP != nil {
		return p.HTTP
	}
	return http.DefaultClient
}

// PostReview creates the PR review with its inline comments
// (POST /repos/{owner}/{repo}/pulls/{n}/reviews). Needs the App's `pull_requests: write`.
func (p *GitHubPoster) PostReview(ctx context.Context, owner, repo string, pr int, payload GitHubReviewPayload) error {
	return p.post(ctx, fmt.Sprintf("/repos/%s/%s/pulls/%d/reviews", owner, repo, pr), payload, "pull_requests: write")
}

// PostCheckRun creates the merge-gating check-run (POST /repos/{owner}/{repo}/check-runs). Needs the
// App's `checks: write` — and ONLY an App can own a check-run, which is why the OAuth token cannot
// stand in here.
func (p *GitHubPoster) PostCheckRun(ctx context.Context, owner, repo string, payload CheckRunPayload) error {
	return p.post(ctx, fmt.Sprintf("/repos/%s/%s/check-runs", owner, repo), payload, "checks: write")
}

func (p *GitHubPoster) post(ctx context.Context, path string, payload any, permission string) error {
	if p.Token == nil {
		return errors.New("prbot: no token source")
	}
	tok, err := p.Token(ctx)
	if err != nil {
		return err
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.base()+path, bytes.NewReader(b))
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+tok)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("Content-Type", "application/json")
	resp, err := p.client().Do(req)
	if err != nil {
		return fmt.Errorf("prbot: %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(body))
		if len(msg) > 300 {
			msg = msg[:300]
		}
		// A 403 here is almost always the App lacking the permission for THIS call; naming it turns
		// "the bot did not post" into something an admin can fix in the App's settings.
		if resp.StatusCode == http.StatusForbidden {
			return fmt.Errorf("prbot: HTTP 403 on %s — the GitHub App likely lacks `%s`: %s", path, permission, msg)
		}
		// 422 on a review is the canonical "a comment names a line not in the diff" — GitHub rejects
		// the whole review, so say which call failed.
		return fmt.Errorf("prbot: HTTP %d on %s: %s", resp.StatusCode, path, msg)
	}
	return nil
}
