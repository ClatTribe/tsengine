package runner

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// cveScanner returns one raw, unenriched CVE finding — what an OSS scanner actually emits.
type cveScanner struct{}

func (cveScanner) Scan(context.Context, platform.Asset) ([]types.Finding, error) {
	return []types.Finding{{
		ID: "raw-1", RuleID: "grype::CVE-2021-44228", Tool: "grype",
		Severity: types.SeverityHigh, Endpoint: "pkg:maven/log4j-core@2.14.1",
		Title: "log4j-core 2.14.1 is vulnerable", CWE: []string{"CWE-502"},
	}}, nil
}

// The engine scan path — the PRODUCT's primary path — must run the L1.5 chain before storing.
//
// It did not. runner.scanAsset took whatever the scanner returned and called PutFinding directly:
// no tracer exists anywhere in internal/orchestrator or internal/sandbox, and only the CLI built
// one. So every repo/container/web/api/ip scan landed raw, while the secondary ingest paths (which
// all call enrichFindings) were fully enriched — the asymmetry ran opposite to what the comments
// claimed.
//
// This asserts the CONSEQUENCE rather than the plumbing: a stored finding must carry the signals a
// security engineer actually triages on. Confidence + verification_status are set by the finalize
// pass for every finding, so they are the load-bearing check; KEV/EPSS additionally require the
// threat-intel corpus, which is not present in a unit test.
func TestEngineScanFindingsAreEnrichedBeforeStorage(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	asset := platform.Asset{ID: "a1", TenantID: "t1", Type: "container_image", Target: "acme:1.0"}
	_ = st.PutAsset(ctx, asset)

	s := &Service{
		Store:   st,
		Scanner: cveScanner{},
		NewID:   func() string { return "id-1" },
	}
	if _, _, err := s.scanAsset(ctx, asset, "test"); err != nil {
		t.Fatalf("scanAsset: %v", err)
	}

	stored, err := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(stored) == 0 {
		t.Fatal("no findings stored")
	}
	f := stored[0]
	if f.VerificationStatus == "" {
		t.Error("stored finding has no verification_status — the L1.5 finalize pass did not run, so a " +
			"security engineer cannot tell a pattern match from a corroborated finding")
	}
	if f.Confidence == 0 {
		t.Error("stored finding has no confidence — triage order is exactly what this audience uses it for")
	}
}

// The ablation flag must still work through the new path, or the L1-vs-L1.5 delta (§14.1) stops
// being measurable on the engine path.
func TestEngineScanRespectsTheL15AblationFlag(t *testing.T) {
	t.Setenv("TSENGINE_L15_DISABLED", "1")
	ctx := context.Background()
	st := store.NewMemory()
	asset := platform.Asset{ID: "a1", TenantID: "t1", Type: "container_image", Target: "acme:1.0"}
	_ = st.PutAsset(ctx, asset)

	s := &Service{Store: st, Scanner: cveScanner{}, NewID: func() string { return "id-1" }}
	if _, _, err := s.scanAsset(ctx, asset, "test"); err != nil {
		t.Fatalf("scanAsset: %v", err)
	}
	stored, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(stored) == 0 {
		t.Fatal("no findings stored")
	}
	if stored[0].Confidence != 0 || stored[0].VerificationStatus != "" {
		t.Errorf("with L1.5 disabled the finding must land raw, got confidence=%v status=%q",
			stored[0].Confidence, stored[0].VerificationStatus)
	}
}
