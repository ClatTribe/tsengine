package cloudquery

import (
	"reflect"
	"testing"

	"github.com/ClatTribe/tsengine/internal/cloudengine"
	"github.com/ClatTribe/tsengine/internal/cloudgraph"
)

// TestLarge_GenerateScoreRoundTrip is the scale benchmark: a large, realistic
// account with hundreds of resources and lots of config-bad noise. The engineer
// must find every planted real target, downgrade every planted decoy, and report
// ZERO false paths across the whole account — and the dataset must survive an
// emit→reload (the CloudQuery sync round-trip) unchanged.
func TestLarge_GenerateScoreRoundTrip(t *testing.T) {
	ds, err := GenerateLarge(SizedLargeOpts(1, 120))
	if err != nil {
		t.Fatalf("GenerateLarge (cloudiam validation) failed: %v", err)
	}

	// Sanity: it is actually large and noisy.
	if len(ds.Tables.S3Buckets) < 50 || len(ds.Tables.IAMRoles) < 50 {
		t.Fatalf("dataset is not large: %s", ds.Stats())
	}
	findings := EvalProwler(ds.Tables)
	if len(findings) < 40 {
		t.Fatalf("expected lots of config-bad noise findings, got %d", len(findings))
	}

	a := cloudengine.Assess(cloudgraph.Ingest(ToInventory(ds.Tables)), findings,
		cloudengine.SnapshotOracle{}, cloudengine.Options{MaxHypotheses: 200})
	s := ScoreAssessment(ds, a)

	if s.PathRecall != 1.0 {
		t.Errorf("recall %.4f, want 1.0 (missed %v)", s.PathRecall, s.Missed)
	}
	if s.FPReduction != 1.0 {
		t.Errorf("FP-reduction %.4f, want 1.0 (%d/%d)", s.FPReduction, s.InertDown, s.InertTotal)
	}
	if len(s.Extra) != 0 {
		t.Errorf("expected ZERO false paths across the account, got %d: %v", len(s.Extra), s.Extra)
	}
	if !s.Pass {
		t.Errorf("engine must ace the large account: %+v", s)
	}

	// Emit → reload (CloudQuery sync round-trip): tables + answer key intact.
	dir := t.TempDir()
	if err := ds.SaveAll(dir); err != nil {
		t.Fatalf("SaveAll: %v", err)
	}
	loaded, err := LoadDataset(dir)
	if err != nil {
		t.Fatalf("LoadDataset: %v", err)
	}
	if !reflect.DeepEqual(loaded.AnswerKey, ds.AnswerKey) {
		t.Error("answer key changed across emit/reload")
	}
	if cloudgraph.Ingest(ToInventory(loaded.Tables)).Hash() != cloudgraph.Ingest(ToInventory(ds.Tables)).Hash() {
		t.Error("resolved graph changed across emit/reload")
	}
}

// TestLarge_DeterministicFromSeed: same seed → identical dataset (reproducible).
func TestLarge_DeterministicFromSeed(t *testing.T) {
	a, err := GenerateLarge(SizedLargeOpts(42, 80))
	if err != nil {
		t.Fatal(err)
	}
	b, err := GenerateLarge(SizedLargeOpts(42, 80))
	if err != nil {
		t.Fatal(err)
	}
	if cloudgraph.Ingest(ToInventory(a.Tables)).Hash() != cloudgraph.Ingest(ToInventory(b.Tables)).Hash() {
		t.Error("same seed must produce the same dataset")
	}
}
