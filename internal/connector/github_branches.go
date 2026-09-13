package connector

import (
	"context"
	"fmt"
	"net/http"
	"strings"
)

// ListBranches returns the repository's branch names — the other half of the backport question
// ("which branches that customers actually run still have this bug?"). `internal/remediate.
// PlanBackports` was pure, tested and unreachable partly for want of this: nothing in the tree could
// enumerate a repository's branches, so no caller could assemble its []BranchFile.
//
// Paginated to a bound. A repository with thousands of stale feature branches is common, and fetching
// the fixed file on every one would spend a request each to answer a question nobody asked — the
// caller filters to MAINTAINED branches (see remediate.MaintainedBranches) before fetching anything.
// The cap is on pages read, so a huge repository yields a partial list rather than an unbounded walk;
// the caller is told, because a silently truncated branch list reads as "no other branch is affected".
func (g *GitHub) ListBranches(ctx context.Context, token, full string) (names []string, complete bool, err error) {
	if full == "" {
		return nil, false, fmt.Errorf("github: list branches needs a repo")
	}
	const perPage, maxPages = 100, 5
	for page := 1; page <= maxPages; page++ {
		var out []struct {
			Name string `json:"name"`
		}
		p := fmt.Sprintf("/repos/%s/branches?per_page=%d&page=%d", full, perPage, page)
		if err := g.ghJSON(ctx, token, http.MethodGet, p, nil, &out); err != nil {
			return nil, false, fmt.Errorf("github: list branches %s: %w", full, err)
		}
		for _, b := range out {
			if n := strings.TrimSpace(b.Name); n != "" {
				names = append(names, n)
			}
		}
		if len(out) < perPage {
			return names, true, nil // last page — the list is complete
		}
	}
	// Hit the page cap with more to read: honest partial (§10), never presented as the whole set.
	return names, false, nil
}
