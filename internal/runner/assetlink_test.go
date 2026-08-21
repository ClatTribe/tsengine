package runner

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// The runner is the only place that knows which asset a finding came from without guessing.
// Everything downstream had been re-deriving it by matching the asset's target inside the
// endpoint — a heuristic that cannot work for a repository, whose findings are file-relative,
// so a scanned repo holding a leaked key attributed to nothing and the coverage page reported
// "No findings recorded".
func TestScanAsset_StampsTheAssetOnEveryStoredFinding(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	a := platform.Asset{ID: "a1", TenantID: "t1", Type: "container_image", Target: "acme:1.0"}
	if err := st.PutAsset(ctx, a); err != nil {
		t.Fatal(err)
	}
	s := &Service{Store: st, Scanner: cveScanner{}, NewID: func() string { return "id-1" }}
	_, returned, err := s.scanAsset(ctx, a, "test")
	if err != nil {
		t.Fatalf("scanAsset: %v", err)
	}
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(stored) == 0 {
		t.Fatal("no findings stored")
	}
	for _, f := range stored {
		if f.AssetID != "a1" {
			t.Errorf("stored finding %s carries AssetID %q, want a1 — without it every consumer is "+
				"back to guessing from the endpoint", f.RuleID, f.AssetID)
		}
	}
	// The caller's slice matters too: the incident and GRC paths read what scanAsset returns,
	// not what the store holds, so stamping only on the way to storage would leave them blind.
	for _, f := range returned {
		if f.AssetID != "a1" {
			t.Errorf("RETURNED finding %s carries AssetID %q — the incident and GRC paths read this slice",
				f.RuleID, f.AssetID)
		}
	}
}
