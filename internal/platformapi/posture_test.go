package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestPostureView_GroupsBySource(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "a", Tool: "tprm", RuleID: "tprm::vendor-uncertified", Severity: types.SeverityHigh, Endpoint: "vendor:X"})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "b", Tool: "deviceposture", RuleID: "deviceposture::disk-unencrypted", Severity: types.SeverityHigh, Endpoint: "device:Y"})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "c", Tool: "nuclei", RuleID: "nuclei::x", Severity: types.SeverityLow, Endpoint: "https://z"}) // NOT a posture source

	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "GET", "/v1/posture/sources", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("posture view should be 200, got %d", rec.Code)
	}
	var resp struct {
		Total   int `json:"total"`
		Sources []struct {
			Key   string `json:"key"`
			Count int    `json:"count"`
		} `json:"sources"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Total != 2 { // tprm + deviceposture; nuclei excluded
		t.Errorf("posture total should count only posture sources (2), got %d", resp.Total)
	}
	counts := map[string]int{}
	for _, s := range resp.Sources {
		counts[s.Key] = s.Count
	}
	if counts["tprm"] != 1 || counts["deviceposture"] != 1 {
		t.Errorf("expected 1 tprm + 1 deviceposture, got %v", counts)
	}

	// ?source=tprm filters to just that source
	rec2 := do(h, "GET", "/v1/posture/sources?source=tprm", "t1", "")
	var r2 struct{ Total int `json:"total"` }
	_ = json.Unmarshal(rec2.Body.Bytes(), &r2)
	if r2.Total != 1 {
		t.Errorf("?source=tprm should return only 1, got %d", r2.Total)
	}
}
