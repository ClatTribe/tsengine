package platformapi

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"net/http"
	"runtime/debug"
	"strconv"
	"strings"
	"time"

	"github.com/ClatTribe/tsengine/internal/coverage"
	"github.com/ClatTribe/tsengine/internal/crossdetect"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
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
//
// LIMIT WORTH KNOWING: the bracket measures the window between two censuses, not the
// agent in isolation. If a scheduled scan lands findings on the same surface while the
// agent is running, they appear in the delta as the agent's. The window is one handler's
// duration, so this is uncommon — and the alternative, intersecting the delta with what
// the run itself stored, would just be the run's own report dressed as a measurement.
// The measurement is worth having precisely because it can disagree with that report.
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

// surfaceFilter builds a census filter for one asset type from coverage.Toolset — the
// SAME declared anchor list the coverage page renders, plus the agent that specialises in
// that surface.
//
// Derived rather than hand-written on purpose. A hand-written tool list is a second place
// to remember when an anchor changes, and the failure is silent in the direction that
// matters: a tool missing from the list is missing from the BEFORE census, so its
// findings look like ones the run opened. Reading the declared toolset means adding an
// anchor updates this for free, and the coverage page is where anyone would look for that
// list anyway.
func surfaceFilter(assetTypes []string, agentTools ...string) func(types.Finding) bool {
	tools := map[string]bool{}
	for _, t := range agentTools {
		tools[t] = true
	}
	for _, at := range assetTypes {
		for _, t := range coverage.Toolset[at] {
			tools[t] = true
		}
	}
	return func(f types.Finding) bool {
		if tools[f.Tool] {
			return true
		}
		// A finding whose Tool is unset but whose rule names a known tool still belongs to
		// the surface — some ingest paths set only the rule id.
		for t := range tools {
			if strings.HasPrefix(f.RuleID, t+"::") {
				return true
			}
		}
		return false
	}
}

// codeFinding covers the repository and container surfaces plus the code agent's own
// confirmations.
//
// Scope is the whole tenant's code surface rather than one repository, because a repo
// name is not reliably recoverable from a finding: the code agent records it inside
// raw_output and the L1 scanners do not record it at all. Censusing broadly is the honest
// choice — it widens what counts as PERSISTED without misattributing anything as opened
// or closed. Narrowing it would mean matching on a field that is often absent, and a
// filter that silently drops findings understates the before-state, which turns
// pre-existing issues into ones the run appears to have opened.
var codeFinding = surfaceFilter([]string{"repository", "container_image"}, "codeagent")

// cloudFinding covers the cloud surface: the declared cloud_account anchors, the cloud
// agent, and the cloud-specific detectors that write findings through their own ingest
// paths rather than through a scan.
//
// Keeping it separate from codeFinding is what keeps a cloud episode's scope honest — a
// cloud run must not be credited with, or blamed for, a change in the tenant's
// repositories, which is the scope error ledger.Diff exists to catch one level up.
var cloudFinding = surfaceFilter(
	[]string{"cloud_account"},
	"cloudagent", "scout-suite", "cloudsploit", "clouddrift", "cloudcdr",
)

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

// recordEpisode persists a scored run into the tenant's corpus.
//
// Best-effort: a store failure loses the score, never the run's actual output, which
// has already been stored and enriched by the time this is called. That ordering is
// deliberate — the corpus is an observation about the product's work and must never be
// able to block it.
func (d Deps) recordEpisode(ctx context.Context, tenantID, scope string, e *ledger.Episode, saved []types.Finding) {
	if d.Store == nil || e == nil {
		return
	}
	verified := 0
	for _, f := range saved {
		if f.VerificationStatus == types.VerificationVerified {
			verified++
		}
	}
	rec := platform.NewEpisodeRecord(tenantID, scope, e, verified)
	if rec.RanAt.IsZero() {
		rec.RanAt = time.Now().UTC()
	}
	// The id is a timestamp PLUS a random suffix, and the suffix is not decoration.
	// A pure RFC3339Nano id collides whenever two episodes land in the same clock tick —
	// which is not hypothetical: macOS timer granularity is coarse enough that two runs
	// recorded back to back can read the same nanosecond, and the store keys by id, so the
	// second silently overwrites the first. A corpus that loses rows under load loses
	// exactly the rows that came from a busy period.
	rec.ID = rec.RanAt.UTC().Format(time.RFC3339Nano) + "-" + randSuffix()
	_ = d.Store.PutEpisode(ctx, rec)
}

// handleEpisodes (GET /v1/episodes) returns the tenant's episode corpus and its
// roll-up.
//
// The response reports scored alongside episodes on purpose. The gap between them is
// the share of runs whose effect nobody could measure, and it belongs next to the
// numbers derived from the rest — a cost-per-verified computed over half the corpus,
// presented without saying so, is a more confident number than the data supports.
func (d Deps) handleEpisodes(w http.ResponseWriter, r *http.Request, tenantID string) {
	eps, err := d.Store.ListEpisodes(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if scope := r.URL.Query().Get("scope"); scope != "" {
		kept := make([]platform.EpisodeRecord, 0, len(eps))
		for _, e := range eps {
			if e.Scope == scope {
				kept = append(kept, e)
			}
		}
		eps = kept
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"episodes": eps,
		"stats":    platform.SummarizeEpisodes(eps),
	})
}

// randSuffix returns 8 hex characters of entropy, falling back to a nanosecond stamp if
// the system source fails. The fallback is weaker but never worse than what it replaced.
func randSuffix() string {
	var b [4]byte
	if _, err := rand.Read(b[:]); err != nil {
		return strconv.FormatInt(time.Now().UnixNano()%0xffffffff, 16)
	}
	return hex.EncodeToString(b[:])
}
