package platformapi

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func slaDeps(t *testing.T) Deps {
	t.Helper()
	st := store.NewMemory()
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: "ten-1"}); err != nil {
		t.Fatal(err)
	}
	return Deps{Store: st}
}

func putSLA(d Deps, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPut, "/v1/settings/sla", strings.NewReader(body))
	rec := httptest.NewRecorder()
	d.handlePutSLASettings(rec, req, "ten-1")
	return rec
}

func TestSLASettings_StoresAndRoundTrips(t *testing.T) {
	d := slaDeps(t)
	body := `{"enabled":true,"targets":[
		{"severity":"critical","ack_hours":1,"resolve_hours":4},
		{"severity":"high","ack_hours":4,"resolve_hours":24}]}`
	if rec := putSLA(d, body); rec.Code != http.StatusOK {
		t.Fatalf("PUT want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	tn, _ := d.Store.GetTenant(context.Background(), "ten-1")
	if tn.SLA == nil || !tn.SLA.Enabled || len(tn.SLA.Targets) != 2 {
		t.Fatalf("policy not stored: %+v", tn.SLA)
	}
	if tg, ok := tn.SLA.TargetFor("critical"); !ok || tg.AckHours != 1 || tg.ResolveHours != 4 {
		t.Errorf("critical target wrong: %+v ok=%v", tg, ok)
	}
}

func TestSLASettings_GetDefaultsDisabled(t *testing.T) {
	d := slaDeps(t)
	req := httptest.NewRequest(http.MethodGet, "/v1/settings/sla", nil)
	rec := httptest.NewRecorder()
	d.handleGetSLASettings(rec, req, "ten-1")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"targets":[]`) {
		t.Fatalf("GET default want disabled empty policy, got %d: %s", rec.Code, rec.Body.String())
	}
}

func TestSLASettings_Validation(t *testing.T) {
	d := slaDeps(t)
	cases := map[string]string{
		"bad severity":      `{"enabled":true,"targets":[{"severity":"sev0","ack_hours":1}]}`,
		"negative hours":    `{"enabled":true,"targets":[{"severity":"high","ack_hours":-1}]}`,
		"both zero":         `{"enabled":true,"targets":[{"severity":"high","ack_hours":0,"resolve_hours":0}]}`,
		"duplicate sev":     `{"enabled":true,"targets":[{"severity":"high","ack_hours":1},{"severity":"high","resolve_hours":2}]}`,
		"enabled no target": `{"enabled":true,"targets":[]}`,
	}
	for name, body := range cases {
		if rec := putSLA(d, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}
}

func TestHandleIncidents_AnnotatesSLABreach(t *testing.T) {
	d := slaDeps(t)
	ctx := context.Background()
	// SLA: critical resolves in 4h. An open critical opened 5h ago is in resolve breach.
	t0, _ := d.Store.GetTenant(ctx, "ten-1")
	t0.SLA = &platform.SLAPolicy{Enabled: true, Targets: []platform.SLATarget{{Severity: "critical", AckHours: 1, ResolveHours: 4}}}
	_ = d.Store.PutTenant(ctx, t0)
	_ = d.Store.PutIncident(ctx, platform.Incident{ID: "inc-1", TenantID: "ten-1", Severity: "critical", Status: platform.IncidentOpen, OpenedAt: time.Now().Add(-5 * time.Hour)})

	req := httptest.NewRequest(http.MethodGet, "/v1/incidents", nil)
	rec := httptest.NewRecorder()
	d.handleIncidents(rec, req, "ten-1")
	if rec.Code != http.StatusOK {
		t.Fatalf("want 200, got %d", rec.Code)
	}
	var incs []platform.Incident
	if err := json.Unmarshal(rec.Body.Bytes(), &incs); err != nil {
		t.Fatal(err)
	}
	if len(incs) != 1 || incs[0].SLABreach == nil {
		t.Fatalf("incident should carry an sla_breach annotation: %s", rec.Body.String())
	}
	if !incs[0].SLABreach.ResolveBreached || !incs[0].SLABreach.Breached() {
		t.Errorf("5h-old open critical (4h resolve SLA) should be resolve-breached: %+v", incs[0].SLABreach)
	}
	// the annotation must NOT be persisted
	stored, _ := d.Store.ListIncidents(ctx, "ten-1")
	if stored[0].SLABreach != nil {
		t.Error("sla_breach must be a read-time annotation, never persisted")
	}
}
