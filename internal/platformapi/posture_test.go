package platformapi

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
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
	var r2 struct {
		Total int `json:"total"`
	}
	_ = json.Unmarshal(rec2.Body.Bytes(), &r2)
	if r2.Total != 1 {
		t.Errorf("?source=tprm should return only 1, got %d", r2.Total)
	}
}

// A posture source that was never ingested must NOT read as clean. These assessors are grounded — a
// well-managed estate yields zero findings — so "assessed, clean" and "never ran" are byte-identical
// in the findings store. The tenant-level stamp is what separates them; without it the UI showed the
// reassuring reading for both.
func TestPostureView_NeverIngestedIsNotClean(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "acme"})
	// Vendor risk WAS assessed and came back clean; devices were never ingested at all.
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "acme",
		PostureAssessed: map[string]time.Time{"tprm": time.Now().UTC()}})

	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	rec := do(h, "GET", "/v1/posture/sources", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var resp struct {
		Sources []struct {
			Key      string `json:"key"`
			Count    int    `json:"count"`
			Assessed bool   `json:"assessed"`
		} `json:"sources"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
		t.Fatalf("decode: %v", err)
	}
	got := map[string]bool{}
	for _, s := range resp.Sources {
		if s.Count != 0 {
			t.Fatalf("precondition: source %s should have 0 findings, got %d", s.Key, s.Count)
		}
		got[s.Key] = s.Assessed
	}
	if !got["tprm"] {
		t.Error("vendor risk WAS assessed (clean) but reports assessed=false — a real clean result is being hidden")
	}
	if got["deviceposture"] {
		t.Error("device posture was NEVER ingested but reports assessed=true — zero findings reads as a clean fleet")
	}
}

// The stamp is written on a CLEAN ingest too — that is the whole point. An assessor that finds
// nothing must still leave proof it ran.
func TestMarkPostureAssessed_StampedOnCleanIngest(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "acme"})

	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	// A fully compliant fleet: zero findings result.
	rec := do(h, "POST", "/v1/devices/ingest", "t1",
		`{"devices":[{"name":"mac-1","os":"macOS 15.3","disk_encrypted":true,"screen_lock":true,"firewall_on":true,"edr":true,"auto_update":true}]}`)
	if rec.Code != 200 {
		t.Fatalf("ingest should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	tn, err := st.GetTenant(ctx, "t1")
	if err != nil {
		t.Fatalf("get tenant: %v", err)
	}
	if _, ok := tn.PostureAssessed["deviceposture"]; !ok {
		t.Fatal("a clean device ingest left no assessed stamp — the clean result is indistinguishable from never running")
	}
}
