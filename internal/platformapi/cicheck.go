package platformapi

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"

	"github.com/ClatTribe/tsengine/internal/prbot"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// handleCIPRCheck (POST /v1/ci/pr-check) is the CI entry point for the wedge in the developer's PR — gap
// #3: get the check where the developer lives, not in a separate dashboard. A GitHub Action (or any CI
// job) posts the PR's changed lines + the findings tsengine surfaced; this runs the merge-gating review
// (prbot.Build) at the tenant's block severity and returns the verdict — inline comments on the changed
// lines + a check conclusion (success|neutral|failure). The CI job fails the build when blocked, so a
// high+ finding the PR introduces (a leaked key, an injection on a changed line) stops the merge. The
// live GitHub post of the inline review is the gated half (the App PR-write scope); this endpoint returns
// the verdict the action acts on, so the gate works today with only a token in CI.
func (d Deps) handleCIPRCheck(w http.ResponseWriter, r *http.Request, tenantID string) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 8<<20))
	if err != nil {
		respond(w, nil, err)
		return
	}
	var in struct {
		ChangedFiles []struct {
			Path  string `json:"path"`
			Lines []int  `json:"lines"`
		} `json:"changed_files"`
		Findings      []types.Finding `json:"findings"`
		BlockSeverity string          `json:"block_severity,omitempty"` // optional per-call override
		// The PR to POST the review to. Optional: without all three the verdict is still computed
		// and returned (the exit-code gate), and `not_posted_reason` says the request named no PR.
		Repository string `json:"repository,omitempty"` // owner/repo
		PullNumber int    `json:"pull_number,omitempty"`
		HeadSHA    string `json:"head_sha,omitempty"`
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid pr-check body"))
		return
	}

	// Block floor + on/off come from the SHARED resolver, so this can never disagree with what
	// /v1/settings/pr-bot shows the customer. It used to default `enabled` to true for an
	// unconfigured tenant while the settings view reported false — every new workspace read
	// "disabled" and had its merges blocked anyway. A disabled policy makes the check informational
	// (it still comments, it never gates the merge).
	pol := d.resolvePRBotPolicy(r.Context(), tenantID)
	blockAt, enabled := pol.BlockAt, pol.Enabled
	if in.BlockSeverity != "" {
		blockAt = types.Severity(strings.ToLower(strings.TrimSpace(in.BlockSeverity)))
	}

	changed := make([]prbot.ChangedFile, 0, len(in.ChangedFiles))
	for _, cf := range in.ChangedFiles {
		lines := make(map[int]bool, len(cf.Lines))
		for _, ln := range cf.Lines {
			lines[ln] = true
		}
		changed = append(changed, prbot.ChangedFile{Path: cf.Path, Lines: lines})
	}

	review := prbot.Build(in.Findings, changed, blockAt)
	if !enabled && review.Conclusion == "failure" {
		review.Conclusion = "neutral" // policy off → never gate the merge (informational only)
	}
	// The LIVE post: the check-run (which gates the merge under branch protection) and the inline
	// review, with the App's installation token. `posted` is true only when GitHub accepted BOTH
	// calls that were due; anything else is false with the reason, because a review the developer
	// cannot see in the PR is the same as no review, whatever the API returned.
	posted, notPosted := false, ""
	owner, repo, okRepo := strings.Cut(in.Repository, "/")
	switch {
	case in.Repository == "" || in.PullNumber == 0 || in.HeadSHA == "":
		notPosted = "the request named no pull request (repository, pull_number, head_sha) — the verdict is returned for the CI exit code only"
	case !okRepo || owner == "" || repo == "":
		notPosted = "repository must be owner/repo"
	default:
		poster, reason := d.prPosterFor(r.Context(), tenantID)
		if poster == nil {
			notPosted = reason
			break
		}
		if _, _, err := prbot.Submit(r.Context(), review, owner, repo, in.PullNumber, in.HeadSHA, poster); err != nil {
			notPosted = err.Error()
			break
		}
		posted = true
	}
	if d.Recorder != nil {
		d.Recorder.Record("ci pr-check", "pr-bot",
			map[string]any{"tenant_id": tenantID, "conclusion": review.Conclusion, "comments": len(review.Comments),
				"posted": posted, "not_posted_reason": notPosted},
			"CI merge-gating check in the developer's PR")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"conclusion":        review.Conclusion,
		"blocked":           review.Conclusion == "failure",
		"summary":           review.Summary,
		"comments":          review.Comments,
		"posted":            posted,
		"not_posted_reason": notPosted,
	})
}
