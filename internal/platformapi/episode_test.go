package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/ledger"
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
