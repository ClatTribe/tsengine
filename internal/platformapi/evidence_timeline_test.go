package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// TestEvidenceTimeline_E2E: the continuous-evidence API end to end — capture a posture snapshot on demand
// (POST .../evidence/capture) and read the timeline back (GET .../evidence-history) with its continuity
// summary. Proves the SOC 2 Type II "prove it held across the window" artifact is reachable over HTTP.
func TestEvidenceTimeline_E2E(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	// a fully-met SOC 2 posture (two met controls).
	for _, c := range []string{"CC6.1", "CC7.1"} {
		if err := st.UpsertControlState(ctx, platform.ControlState{
			TenantID: "t1", Framework: "soc2", ControlID: c, State: platform.ControlMet,
		}); err != nil {
			t.Fatal(err)
		}
	}
	d := Deps{Store: st, Connectors: connector.NewRegistry(), GRC: &grc.GRC{Store: st}, Token: "platform-tok"}
	h := NewHandler(d)

	// capture on demand.
	rec := do(h, "POST", "/v1/compliance/soc2/evidence/capture", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("capture: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var cap struct {
		Captured bool                        `json:"captured"`
		Snapshot platform.ComplianceSnapshot `json:"snapshot"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &cap)
	if !cap.Captured || !cap.Snapshot.FullyMet || cap.Snapshot.MetControls != 2 {
		t.Fatalf("capture should record a fully-met snapshot, got %+v", cap)
	}

	// read the timeline back.
	rec = do(h, "GET", "/v1/compliance/soc2/evidence-history", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("history: want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var tl grc.EvidenceTimeline
	_ = json.Unmarshal(rec.Body.Bytes(), &tl)
	if tl.Count != 1 || !tl.Continuous || tl.FullyMetRatio != 1.0 {
		t.Fatalf("timeline should be 1 snapshot, continuous, ratio 1.0, got %+v", tl)
	}

	// a framework the tenant never assessed → empty, honest (not fabricated "continuously compliant").
	rec = do(h, "GET", "/v1/compliance/pci/evidence-history", "t1", "")
	var empty grc.EvidenceTimeline
	_ = json.Unmarshal(rec.Body.Bytes(), &empty)
	if empty.Count != 0 || empty.Continuous {
		t.Fatalf("un-monitored framework must be empty + non-continuous, got %+v", empty)
	}
}
