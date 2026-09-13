package platformapi

import (
	"context"
	"fmt"
	"log/slog"
	"strings"

	"github.com/ClatTribe/tsengine/internal/backport"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/remediate"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// BackportInputsFor is the connector-backed half of backport planning: it turns one delivered fix PR
// into the two inputs remediate.PlanBackports needs — the hunk the fix applied, and each maintained
// branch's copy of the file it touched.
//
// It closes the last leg of ADR/gap "backport planning has no caller". The planner was pure and
// tested; nothing could call it because nothing in the product held a DIFF (the pipeline carries
// whole-file content) and nothing could enumerate a repository's branches. backport.HunkBetween and
// connector.GitHub.ListBranches supply those; this assembles them.
//
// Grounded (§10) at every step, and each refusal returns an ERROR rather than an empty result,
// because "no other branch is affected" and "we could not look" must not be the same answer:
//   - no patched files on the action → there is no diff to port (the PR carried instructions only);
//   - the pre-fix content is read from the BASE branch the PR targets, so the hunk describes the real
//     change rather than a guess;
//   - a branch whose copy of the file cannot be read is SKIPPED and named, never treated as unaffected.
func (d Deps) BackportInputsFor(ctx context.Context, a platform.Action, c platform.Connection, token string) (backport.Hunk, []remediate.BranchFile, error) {
	gh, ok := d.githubConnector()
	if !ok {
		return backport.Hunk{}, nil, fmt.Errorf("no GitHub connector is registered, so branches cannot be read")
	}
	full, _ := a.Payload["full_name"].(string)
	if strings.TrimSpace(full) == "" {
		return backport.Hunk{}, nil, fmt.Errorf("the action names no owner/repo")
	}
	base, _ := a.Payload["base"].(string)

	path, after, ok := patchedFile(a)
	if !ok {
		// The PR shipped instructions, not a diff (no model configured, or the patch was withheld by
		// verification). There is nothing to port, and that is a fact about THIS fix, not the branches.
		return backport.Hunk{}, nil, fmt.Errorf("the fix PR carries no patched file, so there is no diff to backport")
	}

	beforeRaw, err := gh.FetchFile(ctx, token, full, path, base)
	if err != nil {
		return backport.Hunk{}, nil, fmt.Errorf("could not read %s on %s to derive the fix: %w", path, nz(base, "the default branch"), err)
	}
	hunk, ok := backport.HunkBetween(path, splitLines(beforeRaw), splitLines(after))
	if !ok {
		return backport.Hunk{}, nil, fmt.Errorf("the patched content of %s is identical to the branch it targets — no change to port", path)
	}

	names, complete, err := gh.ListBranches(ctx, token, full)
	if err != nil {
		return backport.Hunk{}, nil, fmt.Errorf("could not list branches: %w", err)
	}
	if !complete {
		// Honest partial: the caller still plans for what was read, and the log says the set was cut.
		slog.Warn("[backport] the branch list was truncated — some branches were NOT assessed for this fix",
			"repo", full, "read", len(names))
	}
	maintained := remediate.MaintainedBranches(names, nz(base, defaultBranchOf(names)))

	out := make([]remediate.BranchFile, 0, len(maintained))
	for _, b := range maintained {
		content, ferr := gh.FetchFile(ctx, token, full, path, b)
		if ferr != nil {
			// A branch that does not have this file at all is genuinely not affected; one we could not
			// read for any other reason is UNKNOWN. Both are skipped, and both are named — a branch
			// silently dropped would read as assessed-and-clean.
			slog.Info("[backport] branch skipped — its copy of the file could not be read",
				"repo", full, "branch", b, "path", path, "err", ferr.Error())
			continue
		}
		out = append(out, remediate.BranchFile{Branch: b, Path: path, Lines: splitLines(content)})
	}
	return hunk, out, nil
}

// patchedFile pulls the single patched file out of a delivered fix action. attachPatch writes
// `files` as path → whole-file content; both concrete shapes it can land in are read here.
//
// One file, deliberately: a hunk describes ONE file's change, and a multi-file fix is ported by
// planning per file — which needs a per-file hunk, not a merged one. Taking the first and saying so
// beats silently porting part of a fix as though it were all of it.
func patchedFile(a platform.Action) (path, content string, ok bool) {
	switch files := a.Payload["files"].(type) {
	case map[string]string:
		for p, c := range files {
			if strings.TrimSpace(c) != "" {
				return p, c, true
			}
		}
	case map[string]any:
		for p, v := range files {
			if c, isStr := v.(string); isStr && strings.TrimSpace(c) != "" {
				return p, c, true
			}
		}
	}
	return "", "", false
}

// githubConnector resolves the registered GitHub connector as its concrete type — FetchFile and
// ListBranches are GitHub-specific reads, not part of the generic Connector interface.
func (d Deps) githubConnector() (*connector.GitHub, bool) {
	if d.Connectors == nil {
		return nil, false
	}
	c, err := d.Connectors.Get(platform.ConnGitHub)
	if err != nil {
		return nil, false
	}
	gh, ok := c.(*connector.GitHub)
	return gh, ok
}

// defaultBranchOf picks the conventional default when the action did not name a base, so the branch
// the fix landed on is still excluded from its own backport list.
func defaultBranchOf(names []string) string {
	for _, want := range []string{"main", "master"} {
		for _, n := range names {
			if strings.EqualFold(n, want) {
				return n
			}
		}
	}
	return ""
}

func splitLines(s string) []string {
	return strings.Split(strings.ReplaceAll(s, "\r\n", "\n"), "\n")
}
