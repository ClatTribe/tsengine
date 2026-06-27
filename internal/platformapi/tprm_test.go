package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
)

func TestTPRM_EndToEnd(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	body := `{"vendors":[
	  {"name":"AnalyticsCo","data_access":"pii"},
	  {"name":"DataPipe","subprocessor":true,"data_access":"pii","certifications":["SOC2"]},
	  {"name":"AWS","data_access":"sensitive","subprocessor":true,"has_dpa":true,"certifications":["SOC2","ISO27001"]}
	]}`
	rec := do(h, "POST", "/v1/tprm/ingest", "t1", body)
	if rec.Code != 200 {
		t.Fatalf("tprm ingest should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		RisksDetected int `json:"risks_detected"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.RisksDetected != 2 { // AnalyticsCo uncertified + DataPipe subprocessor-no-dpa (AWS is clean)
		t.Fatalf("want 2 vendor risks (uncertified + subprocessor-no-dpa), got %d", resp.RisksDetected)
	}
	fs, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	for _, f := range fs {
		if f.Tool != "tprm" {
			t.Errorf("stored finding should be tool=tprm, got %q", f.Tool)
		}
	}
}
