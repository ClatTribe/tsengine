package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// The refusal that keeps a bracket from lying: with no store there is no census, and a
// zero-valued state would make the very next Diff report every issue the run found as
// newly opened BY the run.
func TestCensusState_NoStoreIsNotAnEmptyPosture(t *testing.T) {
	var d Deps
	if got := d.censusState(context.Background(), "t1", "cloud:t1", nil); got != nil {
		t.Errorf("no store must yield no state, got %+v", got)
	}
}

func TestCensusState_CountsDistinctIssuesAndFacts(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	kev := &types.ThreatIntel{KEV: &types.KEVStatus{Listed: true}}
	for _, f := range []types.Finding{
		{ID: "1", RuleID: "cloudagent::path", Tool: "cloudagent", Severity: types.SeverityHigh, Endpoint: "aws://a"},
		{ID: "2", RuleID: "prowler::iam", Tool: "prowler", Severity: types.SeverityMedium, Endpoint: "aws://b",
			VerificationStatus: types.VerificationVerified, ThreatIntel: kev},
		// A repository finding: out of scope for a cloud census, and counting it would
		// hand the cloud agent credit for someone else's surface.
		{ID: "3", RuleID: "semgrep::sqli", Tool: "semgrep", Severity: types.SeverityHigh, Endpoint: "src/a.go:12"},
	} {
		if err := st.PutFinding(ctx, "t1", f); err != nil {
			t.Fatal(err)
		}
	}
	d := Deps{Store: st}
	s := d.censusState(ctx, "t1", "cloud:t1", cloudFinding)
	if s == nil {
		t.Fatal("want a state")
	}
	if len(s.IssueKeys) != 2 {
		t.Errorf("IssueKeys = %v, want the 2 cloud findings only", s.IssueKeys)
	}
	if s.BySeverity["high"] != 1 || s.BySeverity["medium"] != 1 {
		t.Errorf("BySeverity = %v", s.BySeverity)
	}
	if s.Facts["verified"] != 1 || s.Facts["kev_listed"] != 1 {
		t.Errorf("Facts = %v", s.Facts)
	}
	if s.Scope != "cloud:t1" {
		t.Errorf("Scope = %q", s.Scope)
	}
}

// The whole point of the bracket: an issue already on the books before the run is not
// something the run opened.
func TestCensusState_BracketAttributesOnlyWhatChanged(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	pre := types.Finding{ID: "1", RuleID: "prowler::iam", Tool: "prowler", Severity: types.SeverityHigh, Endpoint: "aws://a"}
	if err := st.PutFinding(ctx, "t1", pre); err != nil {
		t.Fatal(err)
	}
	d := Deps{Store: st}
	before := d.censusState(ctx, "t1", "cloud:t1", cloudFinding)

	// The "run" surfaces one new path and re-reports the one that was already there.
	got := types.Finding{ID: "2", RuleID: "cloudagent::path", Tool: "cloudagent", Severity: types.SeverityCritical, Endpoint: "aws://b"}
	if err := st.PutFinding(ctx, "t1", got); err != nil {
		t.Fatal(err)
	}
	after := d.censusState(ctx, "t1", "cloud:t1", cloudFinding)

	dl, err := ledger.Diff(before, after)
	if err != nil {
		t.Fatal(err)
	}
	if len(dl.Opened) != 1 {
		t.Errorf("Opened = %v, want only the new path", dl.Opened)
	}
	if dl.Persisted != 1 {
		t.Errorf("Persisted = %d, want the pre-existing issue counted as persisted, not opened", dl.Persisted)
	}
	if len(dl.Closed) != 0 {
		t.Errorf("Closed = %v, want none", dl.Closed)
	}
}

// cloudFinding is what keeps a cloud episode's scope honest, so its boundary is worth
// pinning: a repo or identity finding must not enter a cloud census.
func TestCloudFinding_SurfaceBoundary(t *testing.T) {
	for _, tc := range []struct {
		f    types.Finding
		want bool
	}{
		{types.Finding{Tool: "cloudagent"}, true},
		{types.Finding{Tool: "prowler"}, true},
		{types.Finding{Tool: "clouddrift"}, true},
		{types.Finding{Tool: "semgrep", RuleID: "semgrep::sqli"}, false},
		{types.Finding{Tool: "gitleaks", RuleID: "gitleaks::aws-key"}, false},
		{types.Finding{Tool: "operate", RuleID: "operate::mfa-missing"}, false},
	} {
		if got := cloudFinding(tc.f); got != tc.want {
			t.Errorf("cloudFinding(%s/%s) = %v, want %v", tc.f.Tool, tc.f.RuleID, got, tc.want)
		}
	}
}

// A corpus with no clock would collapse to one row: every record overwriting the last
// under an empty ID.
func TestRecordEpisode_NeverWritesAnEmptyID(t *testing.T) {
	st := store.NewMemory()
	d := Deps{Store: st}
	ctx := context.Background()
	e1 := ledger.NewEpisode(&ledger.Ledger{AgentKind: "cloudagent"}, nil)
	e2 := ledger.NewEpisode(&ledger.Ledger{AgentKind: "cloudagent"}, nil)
	d.recordEpisode(ctx, "t1", "cloud:t1", e1, nil)
	d.recordEpisode(ctx, "t1", "cloud:t1", e2, nil)
	got, err := st.ListEpisodes(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 {
		t.Fatalf("two runs must be two rows, got %d", len(got))
	}
	for _, e := range got {
		if e.ID == "" || e.RanAt.IsZero() {
			t.Errorf("record has no identity: %+v", e)
		}
	}
}

// The roll-up must say how much of the corpus it could actually score. A
// cost-per-verified computed over half the runs and presented without that number is
// more confident than the data supports.
func TestSummarizeEpisodes_ReportsTheUnscorableShare(t *testing.T) {
	eps := []platform.EpisodeRecord{
		{Delta: &ledger.SecurityStateDelta{Opened: []string{"a"}}, Cost: ledger.Cost{USD: 2}, Verified: 1,
			Training: ledger.Training{Consented: true}},
		{Unscored: "scope mismatch", Cost: ledger.Cost{USD: 1}},
	}
	s := platform.SummarizeEpisodes(eps)
	if s.Episodes != 2 || s.Scored != 1 {
		t.Errorf("Episodes=%d Scored=%d, want 2 and 1", s.Episodes, s.Scored)
	}
	if s.Trainable != 1 {
		t.Errorf("Trainable = %d, want 1", s.Trainable)
	}
	if !s.HasCostPer || s.CostPerVerified != 3 {
		t.Errorf("CostPerVerified = %v (%v), want 3", s.CostPerVerified, s.HasCostPer)
	}
}

// Zero verified outcomes has no ratio. Reporting 0 would rank the agent that finds
// nothing as the most efficient one in any fleet average.
func TestSummarizeEpisodes_NoVerifiedHasNoRatio(t *testing.T) {
	s := platform.SummarizeEpisodes([]platform.EpisodeRecord{{Cost: ledger.Cost{USD: 9}}})
	if s.HasCostPer {
		t.Error("no verified outcome must report no cost-per-verified, not a ratio")
	}
}

// NewEpisodeRecord must assert nothing the episode does not hold — an unsigned ledger
// has no attestation hash, and inventing one would make a score look replayable when
// there is nothing to replay it against.
func TestNewEpisodeRecord_NoAttestationMeansNoSHA(t *testing.T) {
	e := ledger.NewEpisode(&ledger.Ledger{AgentKind: "webagent"}, nil)
	rec := platform.NewEpisodeRecord("t1", "web:t1", e, 0)
	if rec.LedgerSHA != "" {
		t.Errorf("LedgerSHA = %q, want empty for an unsigned ledger", rec.LedgerSHA)
	}
	if rec.AgentKind != "webagent" {
		t.Errorf("AgentKind = %q", rec.AgentKind)
	}
}
