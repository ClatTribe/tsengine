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
	}
	if err := json.Unmarshal(body, &in); err != nil {
		writeJSON(w, http.StatusBadRequest, errBody("invalid pr-check body"))
		return
	}

	// Block floor: the tenant's PR-bot policy (default high), overridable per call. A disabled policy
	// makes the check informational (it still comments, but never blocks the merge).
	blockAt := types.SeverityHigh
	enabled := true
	if t, terr := d.Store.GetTenant(r.Context(), tenantID); terr == nil && t.PRBot != nil {
		enabled = t.PRBot.Enabled
		if t.PRBot.BlockSeverity != "" {
			blockAt = types.Severity(t.PRBot.BlockSeverity)
		}
	}
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
	if d.Recorder != nil {
		d.Recorder.Record("ci pr-check", "pr-bot",
			map[string]any{"tenant_id": tenantID, "conclusion": review.Conclusion, "comments": len(review.Comments)},
			"CI merge-gating check in the developer's PR")
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"conclusion": review.Conclusion,
		"blocked":    review.Conclusion == "failure",
		"summary":    review.Summary,
		"comments":   review.Comments,
	})
}
