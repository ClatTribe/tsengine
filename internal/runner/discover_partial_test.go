package runner

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// failOneScanner fails exactly the asset whose target contains `bad` and scans the rest.
type failOneScanner struct {
	bad   string
	calls int
}

func (s *failOneScanner) Scan(_ context.Context, a platform.Asset) ([]types.Finding, error) {
	s.calls++
	if strings.Contains(a.Target, s.bad) {
		return nil, errors.New("sandbox: clone failed")
	}
	return []types.Finding{{ID: "f-" + a.Target, Severity: types.SeverityHigh, Title: "issue in " + a.Target}}, nil
}

// DiscoverAndScan used to RETURN on the first asset whose scan failed, so every asset discovered after
// it was registered but never scanned — and the caller learned only "N scanned", not that the rest
// were skipped. The onboarding scan must behave like RescanTenant: keep going, count what scanned,
// and hand back the first error so a partial pass can be reported as partial.
func TestDiscoverAndScan_ContinuesPastFailingAsset(t *testing.T) {
	st := store.NewMemory()
	sc := &failOneScanner{bad: "acme/web"} // fakeConn discovers acme/web FIRST, then acme/api
	n := 0
	svc := &Service{Store: st, Connectors: connector.NewRegistry(fakeConn{}), Tokens: fakeTokens{}, Scanner: sc, NewID: func() string { n++; return itoa(n) }}
	ctx := context.Background()

	scanned, err := svc.DiscoverAndScan(ctx, platform.Connection{ID: "c1", TenantID: "t1", Kind: platform.ConnGitHub})
	if sc.calls != 2 {
		t.Fatalf("both discovered assets must be attempted, got %d scan calls", sc.calls)
	}
	if scanned != 1 {
		t.Fatalf("want 1 scanned (the one that succeeded), got %d", scanned)
	}
	if err == nil || !strings.Contains(err.Error(), "acme/web") {
		t.Fatalf("the first error must be returned and name the asset, got %v", err)
	}
	// the asset that scanned has its finding; the one that failed has none — but BOTH are registered
	fs, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(fs) != 1 || !strings.Contains(fs[0].ID, "acme/api") {
		t.Fatalf("want the second asset's finding persisted, got %+v", fs)
	}
	if assets, _ := st.ListAssets(ctx, "t1"); len(assets) != 2 {
		t.Fatalf("want both assets registered, got %d", len(assets))
	}
}
