package platformapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func escalationDeps(t *testing.T) Deps {
	t.Helper()
	st := store.NewMemory()
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: "ten-1"}); err != nil {
		t.Fatal(err)
	}
	return Deps{Store: st}
}

func putEscalation(d Deps, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/v1/settings/escalation", strings.NewReader(body))
	rec := httptest.NewRecorder()
	d.handlePutEscalationSettings(rec, req, "ten-1")
	return rec
}

func TestEscalationSettings_StoresAndRoundTrips(t *testing.T) {
	d := escalationDeps(t)
	body := `{"enabled":true,"ack_window_mins":15,"tiers":[
		{"min_severity":"critical","channels":["pagerduty","slack"]},
		{"min_severity":"high","channels":["slack"]}]}`
	if rec := putEscalation(d, body); rec.Code != http.StatusOK {
		t.Fatalf("PUT want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	tn, _ := d.Store.GetTenant(context.Background(), "ten-1")
	if tn.Escalation == nil || !tn.Escalation.Enabled || tn.Escalation.AckWindowMins != 15 || len(tn.Escalation.Tiers) != 2 {
		t.Fatalf("policy not stored: %+v", tn.Escalation)
	}
	// the routing logic resolves through the stored policy
	if ch, ok := tn.Escalation.ChannelsFor("critical"); !ok || len(ch) != 2 || ch[0] != "pagerduty" {
		t.Errorf("critical should route to [pagerduty slack], got %v ok=%v", ch, ok)
	}
}

func TestEscalationSettings_Validation(t *testing.T) {
	d := escalationDeps(t)
	cases := map[string]string{
		"bad severity":     `{"enabled":true,"tiers":[{"min_severity":"urgent","channels":["slack"]}]}`,
		"unknown channel":  `{"enabled":true,"tiers":[{"min_severity":"high","channels":["carrierpigeon"]}]}`,
		"tier no channels": `{"enabled":true,"tiers":[{"min_severity":"high","channels":[]}]}`,
		"enabled no tiers": `{"enabled":true,"tiers":[]}`,
		"negative ack":     `{"enabled":true,"ack_window_mins":-5,"tiers":[{"min_severity":"high","channels":["slack"]}]}`,
	}
	for name, b := range cases {
		if rec := putEscalation(d, b); rec.Code != http.StatusBadRequest {
			t.Errorf("%s should be 400, got %d", name, rec.Code)
		}
	}
}

func TestEscalationSettings_GetDefaultsDisabled(t *testing.T) {
	d := escalationDeps(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/settings/escalation", nil)
	rec := httptest.NewRecorder()
	d.handleGetEscalationSettings(rec, req, "ten-1")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"enabled":false`) {
		t.Errorf("GET on a fresh tenant should report disabled, got %d %s", rec.Code, rec.Body.String())
	}
	if !strings.Contains(rec.Body.String(), `"tiers":[]`) {
		t.Errorf("empty tiers must serialize as [] not null, got %s", rec.Body.String())
	}
}

func ackReq(d Deps, tenant, id, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/incidents/"+id+"/ack", strings.NewReader(body))
	req.SetPathValue("id", id)
	rec := httptest.NewRecorder()
	d.handleAckIncident(rec, req, tenant)
	return rec
}

func TestAckIncident_SetsAcknowledgedAndStopsEscalation(t *testing.T) {
	d := escalationDeps(t)
	ctx := context.Background()
	_ = d.Store.PutIncident(ctx, platform.Incident{ID: "inc-1", TenantID: "ten-1", Status: platform.IncidentOpen, OpenedAt: time.Now().Add(-2 * time.Hour)})

	if rec := ackReq(d, "ten-1", "inc-1", `{"by":"alice@acme.com"}`); rec.Code != http.StatusOK {
		t.Fatalf("ack want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	all, _ := d.Store.ListIncidents(ctx, "ten-1")
	if len(all) != 1 || !all[0].Acknowledged() || all[0].AcknowledgedBy != "alice@acme.com" {
		t.Fatalf("incident not acknowledged: %+v", all)
	}
	// once acked, it is no longer overdue (timed escalation stops)
	if all[0].Overdue(30, time.Now()) {
		t.Error("an acknowledged incident must not be overdue")
	}
}

func TestAckIncident_TenantIsolationAnd404(t *testing.T) {
	d := escalationDeps(t)
	ctx := context.Background()
	_ = d.Store.PutTenant(ctx, platform.Tenant{ID: "ten-2"})
	_ = d.Store.PutIncident(ctx, platform.Incident{ID: "inc-x", TenantID: "ten-2", Status: platform.IncidentOpen})

	// ten-1 cannot ack ten-2's incident
	if rec := ackReq(d, "ten-1", "inc-x", "{}"); rec.Code != http.StatusNotFound {
		t.Fatalf("cross-tenant ack want 404, got %d", rec.Code)
	}
	// unknown id → 404
	if rec := ackReq(d, "ten-1", "nope", "{}"); rec.Code != http.StatusNotFound {
		t.Fatalf("unknown incident want 404, got %d", rec.Code)
	}
}
