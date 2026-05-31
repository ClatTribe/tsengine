package cloudquery

import (
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// TestCloudQuery_EndToEnd is the headline anti-overfit demonstration: prowler's
// catalog defines "bad" over the emulated CloudQuery config, cloudiam defines
// exploitability truth (over trust policies + permission boundaries), and the AI
// Cloud Engineer — ingesting CloudQuery with effective-permission resolution —
// must correctly separate the two, INCLUDING the boundary-blocked privesc and the
// trust-denied assume that a naive ingest gets wrong (the held-out gap, closed).
func TestCloudQuery_EndToEnd(t *testing.T) {
	ds, err := Generate()
	if err != nil {
		t.Fatalf("Generate (independent cloudiam validation) failed: %v", err)
	}

	findings := EvalProwler(ds.Tables)
	if len(findings) == 0 {
		t.Fatal("prowler catalog produced no findings over the config")
	}

	inv := ToInventory(ds.Tables)
	snap := cloudgraph.Ingest(inv)
	a := cloudengine.Assess(snap, findings, cloudengine.SnapshotOracle{}, cloudengine.Options{MaxHypotheses: 40})
	s := ScoreAssessment(ds, a)

	if !s.Pass {
		t.Errorf("engineer must ace the prowler-grounded CloudQuery account: %+v", s)
	}
	if s.PathRecall != 1.0 {
		t.Errorf("recall %.2f, want 1.0 (%d/%d)", s.PathRecall, s.RealFound, s.RealTotal)
	}
	if s.FPReduction != 1.0 {
		t.Errorf("FP-reduction %.2f, want 1.0 (%d/%d inert)", s.FPReduction, s.InertDown, s.InertTotal)
	}
	if len(s.Extra) != 0 {
		t.Errorf("unexpected extra paths: %v", s.Extra)
	}

	// The crux: the held-out classes must be DOWNGRADED, not reported as real.
	down := map[string]bool{}
	for _, d := range a.Downgraded {
		down[d] = true
	}
	boundaryFinding := FindingID("iam_policy_allows_privilege_escalation", roleP+"ci-role")
	trustFinding := FindingID("s3_bucket_no_mfa_delete", finARN)
	if !down[boundaryFinding] {
		t.Errorf("boundary-blocked privesc (%s) must be downgraded — the engineer must honor the permission boundary", boundaryFinding)
	}
	if !down[trustFinding] {
		t.Errorf("trust-denied assume (%s) must be downgraded — the engineer must honor the trust policy", trustFinding)
	}
}

// TestCloudQuery_RoundTrip asserts a dataset saved to disk reloads to an
// identical ingest (the CloudQuery sync → operator-provided dir path).
func TestCloudQuery_RoundTrip(t *testing.T) {
	ds, err := Generate()
	if err != nil {
		t.Fatalf("Generate: %v", err)
	}
	dir := t.TempDir()
	if err := ds.Tables.Save(dir); err != nil {
		t.Fatalf("Save: %v", err)
	}
	loaded, err := Load(dir)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cloudgraph.Ingest(ToInventory(loaded)).Hash() != cloudgraph.Ingest(ToInventory(ds.Tables)).Hash() {
		t.Error("CloudQuery dataset round-trip changed the resolved graph")
	}
}
