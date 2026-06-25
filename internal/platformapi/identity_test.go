package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestIngestIdentityEvents_DetectsAndStores(t *testing.T) {
	st := store.NewMemory()
	n := 0
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", NewID: func() string { n++; return "id-" + string(rune('a'+n)) }})

	// US then DE login 20 min apart for one user → impossible travel.
	body := `[
	  {"id":"1","user":"ana","type":"login","time":"2026-06-22T09:00:00Z","country":"US"},
	  {"id":"2","user":"ana","type":"login","time":"2026-06-22T09:20:00Z","country":"DE"},
	  {"id":"3","user":"bob","type":"role_grant","time":"2026-06-22T09:00:00Z","admin":true,"detail":"Super Admin"}
	]`
	rec := do(h, "POST", "/v1/identity/events", "t1", body)
	if rec.Code != 200 {
		t.Fatalf("want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		EventsIngested  int `json:"events_ingested"`
		ThreatsDetected int `json:"threats_detected"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.EventsIngested != 3 {
		t.Errorf("3 events ingested, got %d", resp.EventsIngested)
	}
	if resp.ThreatsDetected < 2 { // impossible_travel + privileged_grant
		t.Errorf("expected >=2 threats, got %d", resp.ThreatsDetected)
	}

	// The threats are stored as findings (so they flow into issues/incidents).
	fs, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	if len(fs) < 2 {
		t.Fatalf("threats should be stored as findings, got %d", len(fs))
	}
	var sawTravel bool
	for _, f := range fs {
		if f.RuleID == "identitythreat::impossible_travel" && f.Severity == types.SeverityHigh {
			sawTravel = true
		}
		if f.Tool != "identitythreat" {
			t.Errorf("identity findings should be tagged tool=identitythreat, got %q", f.Tool)
		}
	}
	if !sawTravel {
		t.Error("the impossible-travel threat should be a stored finding")
	}

	// Tenant isolation: another tenant sees none.
	other, _ := st.ListFindings(context.Background(), "t2", store.FindingFilter{})
	if len(other) != 0 {
		t.Errorf("another tenant must not see t1's identity findings, got %d", len(other))
	}
}

func TestIngestIdentityEvents_BadBody(t *testing.T) {
	st := store.NewMemory()
	n := 0
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", NewID: func() string { n++; return "id-" + string(rune('a'+n)) }})
	if rec := do(h, "POST", "/v1/identity/events", "t1", `not json`); rec.Code != 400 {
		t.Errorf("a non-JSON body should 400, got %d", rec.Code)
	}
}
