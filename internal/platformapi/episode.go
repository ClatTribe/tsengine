package platformapi

import (
	"context"
	"runtime/debug"
	"time"

	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// episode.go censuses a tenant's posture into a ledger.SecurityState, so an agent run
// can be BRACKETED and its effect measured rather than described (ADR 0018 §4).
//
// The census is the caller's job by design: pkg/ledger is a leaf and must not learn
// what a finding is. It also must not become a fourth change detector — detect,
// clouddrift and retest each own one, and the ADR keeps the count at three. This only
// counts what the store already holds.

// censusState builds a SecurityState over the tenant's findings.
//
// scope is what makes the state comparable, and getting it wrong is the one way to
// produce a delta that is confidently false — ledger.Diff refuses a mismatch, so the
// scope has to name the same population on both sides of a run.
//
// Keys come from crossdetect.DedupKey, never hand-rolled. A hand-built key of the same
// shape has silently matched nothing for every tenant before, and its test passed
// because the fixture copied the bug.
func (d Deps) censusState(ctx context.Context, tenantID, scope string, keep func(types.Finding) bool) *ledger.SecurityState {
	if d.Store == nil {
		// No store is not an empty posture. Returning a zero state here would make the
		// next Diff report every issue the run found as newly opened by the run.
		return nil
	}
	all, err := d.Store.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return nil
	}
	s := &ledger.SecurityState{
		At: time.Now().UTC(), Scope: scope,
		BySeverity: map[string]int{}, Facts: map[string]int{},
	}
	seen := map[string]bool{}
	for _, f := range all {
		if keep != nil && !keep(f) {
			continue
		}
		k := crossdetect.DedupKey(f)
		if k == "" || seen[k] {
			continue
		}
		seen[k] = true
		s.IssueKeys = append(s.IssueKeys, k)
		s.BySeverity[string(f.Severity)]++
		if f.VerificationStatus == types.VerificationVerified {
			s.Facts["verified"]++
		}
		if f.ThreatIntel != nil && f.ThreatIntel.KEV != nil && f.ThreatIntel.KEV.Listed {
			s.Facts["kev_listed"]++
		}
	}
	return s
}

// cloudFinding reports whether a finding came from the cloud surface. Used as the
// census filter so a cloud episode is not credited with — or blamed for — a change in
// the tenant's repositories, which is the scope error ledger.Diff exists to catch one
// level up.
func cloudFinding(f types.Finding) bool {
	switch f.Tool {
	case "cloudagent", "prowler", "scout-suite", "cloudsploit", "clouddrift", "cloudcdr":
		return true
	}
	return len(f.RuleID) > 5 && (f.RuleID[:5] == "cloud" || f.RuleID[:5] == "aws::" || f.RuleID[:5] == "gcp::")
}

// agentVersion identifies what produced an episode, read from the build's own VCS
// stamp rather than a constant.
//
// A hardcoded version string here would be a second place to remember to bump, and the
// failure mode is silent: every episode after the miss is attributed to the previous
// build, so a benchmark movement gets credited to the wrong change. The build stamp
// cannot drift because nobody maintains it.
//
// Empty when the binary carries no VCS info (`go run`, or a build with -buildvcs=false).
// Empty is the honest answer — the field is omitempty, and an episode that cannot say
// what produced it is better than one that says the wrong thing.
func agentVersion() string {
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	var rev, dirty string
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			rev = s.Value
		case "vcs.modified":
			if s.Value == "true" {
				dirty = "-dirty"
			}
		}
	}
	if rev == "" {
		return ""
	}
	if len(rev) > 12 {
		rev = rev[:12]
	}
	return rev + dirty
}
