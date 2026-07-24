package codelocalize

import (
	"context"
	"fmt"

	"github.com/ClatTribe/tsengine/pkg/types"
)

// finding.go is the finding-driven entry point: the one-call API a consumer (autofix, the VAPT report,
// the L2 code agent) uses to answer "for THIS emitted finding, where in the repo is the sink?" without
// knowing about Repo loading or Query construction. This is the seam that keeps the eventual in-product
// wiring a single line at each call site — the localizer stays decoupled from the L1.5 chain / platform
// API so it can be adopted incrementally.

// FindingLocation pairs a finding with its localization result (the ranked candidate sink files).
type FindingLocation struct {
	Finding types.Finding
	Result  Result
}

// Located reports whether the localizer produced at least one candidate (a clean localization — no sink
// evidence — is a legitimate, honest outcome, not an error).
func (fl FindingLocation) Located() bool { return len(fl.Result.Ranked) > 0 }

// LocalizeFinding loads repoDir and localizes a single finding's vulnerability class within it.
func LocalizeFinding(ctx context.Context, loc Localizer, f types.Finding, repoDir string, opts LoadOptions) (Result, error) {
	repo, err := LoadRepo(repoDir, opts)
	if err != nil {
		return Result{}, err
	}
	return loc.Localize(ctx, QueryFromFinding(f), repo)
}

// LocalizeFindings localizes many findings against ONE repo, loading it a single time (the batch path —
// a repository scan emits many findings over the same tree, so re-walking per finding would be wasteful).
// Results are returned in input order. A per-finding localization error aborts with context; a finding
// that localizes clean simply carries an empty ranking.
func LocalizeFindings(ctx context.Context, loc Localizer, fs []types.Finding, repoDir string, opts LoadOptions) ([]FindingLocation, error) {
	repo, err := LoadRepo(repoDir, opts)
	if err != nil {
		return nil, err
	}
	out := make([]FindingLocation, 0, len(fs))
	for i, f := range fs {
		res, err := loc.Localize(ctx, QueryFromFinding(f), repo)
		if err != nil {
			return nil, fmt.Errorf("localize finding %d (%s): %w", i, f.RuleID, err)
		}
		out = append(out, FindingLocation{Finding: f, Result: res})
	}
	return out, nil
}
