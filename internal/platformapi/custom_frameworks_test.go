package platformapi

import (
	"context"
	"testing"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

func TestCustomFramework_CreateDeriveDelete(t *testing.T) {
	st := store.NewMemory()
	ctx := context.Background()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1", Name: "ACME"})
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f1", CWE: []string{"CWE-89"}, Severity: types.SeverityHigh})
	d := Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok", NewID: func() string { return "x1" }}
	h := NewHandler(d)

	// create
	body := `{"name":"ACME Framework","controls":[{"id":"A-1","maps_to":["cwe:CWE-89"]},{"id":"A-2","maps_to":["cwe:CWE-99999"]}]}`
	if rec := do(h, "POST", "/v1/custom-frameworks", "t1", body); rec.Code != 200 {
		t.Fatalf("create → 200, got %d: %s", rec.Code, rec.Body.String())
	}
	// posture: A-1 should be a gap (CWE-89 present), A-2 unassessed
	rec := do(h, "GET", "/v1/custom-frameworks/cf-x1/posture", "t1", "")
	if rec.Code != 200 {
		t.Fatalf("posture → 200, got %d: %s", rec.Code, rec.Body.String())
	}
	if !contains(rec.Body.String(), "A-1") || !contains(rec.Body.String(), "gap") {
		t.Errorf("posture should show A-1 as a gap: %s", rec.Body.String())
	}
	// delete
	if rec := do(h, "DELETE", "/v1/custom-frameworks/cf-x1", "t1", ""); rec.Code != 200 {
		t.Fatalf("delete → 200, got %d", rec.Code)
	}
}

func contains(s, sub string) bool { return len(s) >= len(sub) && (indexOf(s, sub) >= 0) }
func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}
