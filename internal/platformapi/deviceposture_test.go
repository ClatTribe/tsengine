package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
)

func TestDevicePosture_EndToEnd(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	body := `{"devices":[
	  {"name":"laptop-1","owner":"eng@acme.io","disk_encrypted":false,"screen_lock":false,"firewall_on":true,"edr":true,"auto_update":true},
	  {"name":"laptop-2","disk_encrypted":true,"screen_lock":true,"firewall_on":true,"edr":true,"auto_update":true}
	]}`
	rec := do(h, "POST", "/v1/devices/ingest", "t1", body)
	if rec.Code != 200 {
		t.Fatalf("device ingest should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		IssuesDetected int `json:"issues_detected"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.IssuesDetected != 2 { // laptop-1: disk-unencrypted + no-screen-lock; laptop-2 compliant (silent)
		t.Fatalf("want 2 device issues (unencrypted + no-lock on laptop-1), got %d", resp.IssuesDetected)
	}
	fs, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	for _, f := range fs {
		if f.Tool != "deviceposture" {
			t.Errorf("stored finding should be tool=deviceposture, got %q", f.Tool)
		}
	}
}
