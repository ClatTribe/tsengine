package platformapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// partialScanner fails on the asset whose Target contains "bad" and succeeds otherwise, so a rescan
// produces a partial result (one scanned, one errored) — the real-world "one stale/401 connection"
// case that should NOT fail the whole pass.
type partialScanner struct{}

func (partialScanner) Scan(_ context.Context, a platform.Asset) ([]types.Finding, error) {
	if strings.Contains(a.Target, "bad") {
		return nil, errors.New("connection 401")
	}
	return []types.Finding{{ID: "f-" + a.ID, Severity: types.SeverityHigh, Title: "issue in " + a.Target}}, nil
}

// A rescan where one asset errors but another scans must report SUCCESS (200) with a warning, never a
// total failure (502) — a single degraded connection should never make a founder's "Scan now" read as
// failed and mask that everything else scanned.
func TestRescan_PartialSuccessIsNotFailure(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "good", TenantID: "t1", Type: "repository", Target: "https://github.com/acme/good"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "bad", TenantID: "t1", Type: "repository", Target: "https://github.com/acme/bad"})

	svc := &runner.Service{Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{}, Scanner: partialScanner{}}
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Runner: svc, Token: "platform-tok"})

	rec := do(h, "POST", "/v1/rescan", "t1", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("partial rescan should be 200 OK, got %d: %s", rec.Code, rec.Body.String())
	}
	var res map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if n, _ := res["assets_scanned"].(float64); n < 1 {
		t.Errorf("expected ≥1 asset scanned, got %v", res["assets_scanned"])
	}
	if res["warning"] == nil {
		t.Error("expected a warning about the failed asset, got none")
	}
}

// When NOTHING scans (every asset errors), the rescan is a genuine failure (502) — partial-success
// tolerance must not swallow a total failure.
func TestRescan_TotalFailureIs502(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "Acme"})
	_ = st.PutAsset(ctx, platform.Asset{ID: "bad", TenantID: "t1", Type: "repository", Target: "https://github.com/acme/bad"})

	svc := &runner.Service{Store: st, Connectors: connector.NewRegistry(), Tokens: fakeTokens{}, Scanner: partialScanner{}}
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Runner: svc, Token: "platform-tok"})

	rec := do(h, "POST", "/v1/rescan", "t1", "")
	if rec.Code != http.StatusBadGateway {
		t.Fatalf("total-failure rescan should be 502, got %d: %s", rec.Code, rec.Body.String())
	}
}
