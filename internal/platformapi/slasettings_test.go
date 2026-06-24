package platformapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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
