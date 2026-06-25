package platformapi

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
)

func TestIngestOSINT_StoresAndViews(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})

	snap := `{"org":"acme",
	  "breached_accounts":[{"email":"ceo@acme.com","breach":"X","source":"hibp"}],
	  "leaked_secrets":[{"kind":"AWS key","location":"https://gh/x","source":"trufflehog","verified":true}],
	  "exposed_hosts":[{"host":"legacy.acme.com","services":["rdp"],"source":"shodan"},{"host":"app.acme.com","in_scope":true,"source":"crtsh"}]}`
	rec := do(h, "POST", "/v1/osint/ingest", "t1", snap)
	if rec.Code != 200 {
		t.Fatalf("ingest should be 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var ing struct {
		FindingsDetected int `json:"findings_detected"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &ing)
	if ing.FindingsDetected != 3 { // breach + leak + exposed-host (in-scope host is silent)
		t.Errorf("want 3 findings (in-scope host silent), got %d", ing.FindingsDetected)
	}

	// every stored finding is tagged tool=osint
	fs, _ := st.ListFindings(context.Background(), "t1", store.FindingFilter{})
	for _, f := range fs {
		if f.Tool != "osint" {
			t.Errorf("OSINT findings must be tool=osint, got %q", f.Tool)
		}
	}

	// the External-exposure view returns them + a per-class summary
	view := do(h, "GET", "/v1/osint", "t1", "")
	if view.Code != 200 {
		t.Fatalf("view 200, got %d", view.Code)
	}
	var vr struct {
		Total   int              `json:"total"`
		Summary []map[string]any `json:"summary"`
	}
	_ = json.Unmarshal(view.Body.Bytes(), &vr)
	if vr.Total != 3 || len(vr.Summary) == 0 {
		t.Errorf("view should list 3 OSINT findings with a summary, got total=%d summary=%v", vr.Total, vr.Summary)
	}
}

func TestIngestOSINT_TenantIsolation(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	do(h, "POST", "/v1/osint/ingest", "t1", `{"org":"acme","leaked_secrets":[{"kind":"key","location":"x","source":"y"}]}`)
	// t2 sees none of t1's OSINT findings.
	if v := do(h, "GET", "/v1/osint", "t2", ""); v.Code == 200 {
		var vr struct {
			Total int `json:"total"`
		}
		_ = json.Unmarshal(v.Body.Bytes(), &vr)
		if vr.Total != 0 {
			t.Errorf("tenant isolation: t2 must see 0 of t1's OSINT findings, got %d", vr.Total)
		}
	}
}
