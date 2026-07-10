package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/detect"
	"github.com/ClatTribe/tsengine/internal/grc"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// TestCDR_OpensIncidentImmediately: a live control-plane threat (a root console login) posted to
// /v1/cloud/events must open an incident RIGHT AWAY — CDR's whole promise is detection-and-response in
// seconds, not the hours a periodic scan takes. Before, the finding was stored but only escalated on the
// next monitoring pass's Reconcile.
func TestCDR_OpensIncidentImmediately(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	n := 0
	det := &detect.Detector{Store: st, NewID: func() string { n++; return "inc-" + string(rune('a'+n)) }}
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", IncidentOpener: det}
	h := NewHandler(d)

	// a root-account console login — a high-severity live attack signal.
	body := `{"provider":"aws","event_name":"ConsoleLogin","actor":"root","source_ip":"203.0.113.9"}`
	rec := do(h, "POST", "/v1/cloud/events", "t1", body)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		Detected int `json:"threats_detected"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.Detected < 1 {
		t.Fatalf("a root console login must be detected as a threat, got %d", resp.Detected)
	}

	// the finding must be stored...
	fs, _ := st.ListFindings(ctx, "t1", store.FindingFilter{})
	if len(fs) == 0 {
		t.Fatal("the CDR threat must be stored as a finding")
	}
	// ...AND an incident opened immediately (the fix — not left for the next scan pass).
	incs, err := st.ListIncidents(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(incs) == 0 {
		t.Fatal("a live control-plane threat must open an incident IMMEDIATELY on ingest (CDR = seconds, not hours)")
	}
}

// Without an IncidentOpener wired, ingest still stores the finding (graceful — the fix is additive).
func TestCDR_NoOpenerStillStores(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"}
	rec := do(NewHandler(d), "POST", "/v1/cloud/events", "t1", `{"provider":"aws","event_name":"ConsoleLogin","actor":"root"}`)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	if fs, _ := st.ListFindings(ctx, "t1", store.FindingFilter{}); len(fs) == 0 {
		t.Error("the threat must still be stored without an opener wired")
	}
}

// TestCDR_FoldsIntoCompliancePosture: a live control-plane threat that carries a compliance nexus (a
// public-resource-exposure = CWE-284 → SOC2 CC6.1/CC6.3) must mark those controls a gap in the compliance
// posture — like every other ingest path. Before, CDR was the only ingest that skipped grc.Apply, so a
// live exposure showed in issues but never in GET /v1/compliance.
func TestCDR_FoldsIntoCompliancePosture(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	g := &grc.GRC{Store: st}
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", GRC: g}

	// a bucket just made public — CWE-284, maps to SOC2 access-control controls.
	body := `{"provider":"aws","event_name":"PutBucketAcl","resource":"arn:aws:s3:::acme-data","detail":"granted AllUsers READ"}`
	rec := do(NewHandler(d), "POST", "/v1/cloud/events", "t1", body)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}

	// the SOC2 posture must now show a gap driven by this live threat.
	cs, err := g.Posture(ctx, "t1", grc.FrameworkSOC2)
	if err != nil {
		t.Fatal(err)
	}
	gaps := 0
	for _, c := range cs {
		if c.State == platform.ControlGap {
			gaps++
		}
	}
	if gaps == 0 {
		t.Fatal("a live public-exposure CDR threat (CWE-284) must fold into the SOC2 posture as a control gap")
	}
}
