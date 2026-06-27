package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
)

// End-to-end: POST a prev+cur cloud inventory; a resource that became public + a new privileged principal
// must land as stored clouddrift findings (tool=clouddrift) flowing into the tenant's store.
func TestCloudDrift_EndToEnd(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	body := `{
	  "prev": {"account_id":"acct","provider":"aws","resources":[
	    {"id":"bucket-1","kind":"resource","type":"AWS::S3::Bucket","name":"pii","public":false,"sensitive":"high"}
	  ]},
	  "cur": {"account_id":"acct","provider":"aws","resources":[
	    {"id":"bucket-1","kind":"resource","type":"AWS::S3::Bucket","name":"pii","public":true,"sensitive":"high"},
	    {"id":"role-x","kind":"principal","name":"new-admin","privileged":true}
	  ]}
	}`
	rec := do(h, "POST", "/v1/cloud/drift", "t1", body)
	if rec.Code != 200 {
		t.Fatalf("drift ingest should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var resp struct {
		DriftDetected int `json:"drift_detected"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.DriftDetected < 2 {
		t.Fatalf("want >=2 drift findings (became-public + new-privileged), got %d", resp.DriftDetected)
	}
	fs, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	rules := map[string]bool{}
	for _, f := range fs {
		if f.Tool != "clouddrift" {
			t.Errorf("stored finding should be tool=clouddrift, got %q", f.Tool)
		}
		rules[f.RuleID] = true
	}
	if !rules["clouddrift::resource-became-public"] || !rules["clouddrift::new-privileged-principal"] {
		t.Errorf("expected became-public + new-privileged findings, got %v", rules)
	}
}

// No drift between identical snapshots → 200 with zero findings (not noise).
func TestCloudDrift_NoChange(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	inv := `{"account_id":"a","provider":"aws","resources":[{"id":"n1","kind":"resource","public":true}]}`
	rec := do(h, "POST", "/v1/cloud/drift", "t1", `{"prev":`+inv+`,"cur":`+inv+`}`)
	if rec.Code != 200 {
		t.Fatalf("should be 200, got %d", rec.Code)
	}
	var resp struct {
		DriftDetected int `json:"drift_detected"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &resp)
	if resp.DriftDetected != 0 {
		t.Errorf("identical snapshots must yield zero drift, got %d", resp.DriftDetected)
	}
}
