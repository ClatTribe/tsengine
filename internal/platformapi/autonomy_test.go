package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/autonomy"
	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func autonomyReq(h http.Handler, method, path, session, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+session)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// The owner may allow only what the record earned, the grant names who made it, and a member cannot.
func TestAutonomyAPI_GrantIsEarnedNamedAndOwnerOnly(t *testing.T) {
	ctx := context.Background()
	d, st := ownerScopeDeps(t)
	d.Connectors = connector.NewRegistry()
	h := NewHandler(d)
	grant := `{"class":"nuclei::sqli","remediation_type":"waf_rule","allow":true}`

	if rec := autonomyReq(h, "POST", "/v1/settings/autonomy", "sess-own", grant); rec.Code != http.StatusConflict {
		t.Fatalf("a grant with no record must be refused, got %d %s", rec.Code, rec.Body.String())
	}

	for i := 0; i < autonomy.DefaultMinClosed; i++ {
		_ = st.PutAction(ctx, platform.Action{ID: "a" + itoa(i), TenantID: "t1", Tier: platform.GateTier,
			Status: platform.ActApplied, DecidedAt: time.Now().Add(-time.Hour),
			FindingKeys: []string{"nuclei::sqli|https://x/" + itoa(i)}, Payload: map[string]any{"remediation_type": "waf_rule"},
			Verification: &platform.FixVerification{Status: platform.FixStatusFixed}})
	}
	var view autonomy.Report
	_ = json.Unmarshal(autonomyReq(h, "GET", "/v1/autonomy", "sess-mem", "").Body.Bytes(), &view)
	if len(view.Offers) != 1 {
		t.Fatalf("a clean record should be offered to the owner (and visible to members): %+v", view)
	}

	if rec := autonomyReq(h, "POST", "/v1/settings/autonomy", "sess-mem", grant); rec.Code != http.StatusForbidden {
		t.Fatalf("a member granted autonomy: %d", rec.Code)
	}
	if rec := autonomyReq(h, "POST", "/v1/settings/autonomy", "sess-own", grant); rec.Code != http.StatusOK {
		t.Fatalf("owner grant: %d %s", rec.Code, rec.Body.String())
	}
	tn, _ := st.GetTenant(ctx, "t1")
	if len(tn.AutonomyGrants) != 1 || tn.AutonomyGrants[0].GrantedBy != "ada@acme.io" || tn.AutonomyGrants[0].BasisClosed != autonomy.DefaultMinClosed {
		t.Fatalf("grant must record who and on what basis: %+v", tn.AutonomyGrants)
	}

	revoke := strings.Replace(grant, `"allow":true`, `"allow":false`, 1)
	if rec := autonomyReq(h, "POST", "/v1/settings/autonomy", "sess-own", revoke); rec.Code != http.StatusOK {
		t.Fatalf("revoke: %d", rec.Code)
	}
	if tn, _ := st.GetTenant(ctx, "t1"); len(tn.AutonomyGrants) != 0 {
		t.Fatalf("revoke left a grant: %+v", tn.AutonomyGrants)
	}
}
