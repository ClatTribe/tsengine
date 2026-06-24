package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

func mwDeps(t *testing.T) Deps {
	t.Helper()
	st := store.NewMemory()
	if err := st.PutTenant(context.Background(), platform.Tenant{ID: "ten-1"}); err != nil {
		t.Fatal(err)
	}
	n := 0
	return Deps{Store: st, NewID: func() string { n++; return fmt.Sprintf("w%d", n) }}
}

func addMW(d Deps, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodPost, "/v1/maintenance-windows", strings.NewReader(body))
	rec := httptest.NewRecorder()
	d.handleAddMaintenanceWindow(rec, req, "ten-1")
	return rec
}

func TestMaintenanceWindows_AddListDelete(t *testing.T) {
	d := mwDeps(t)
	ctx := context.Background()
	start := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	end := time.Now().Add(3 * time.Hour).UTC().Format(time.RFC3339)
	body := fmt.Sprintf(`{"name":"Q3 deploy","starts_at":%q,"ends_at":%q,"reason":"release"}`, start, end)

	rec := addMW(d, body)
	if rec.Code != http.StatusOK {
		t.Fatalf("add want 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var win platform.MaintenanceWindow
	_ = json.Unmarshal(rec.Body.Bytes(), &win)
	if win.ID == "" || win.Name != "Q3 deploy" {
		t.Fatalf("returned window malformed: %+v", win)
	}

	// list
	lreq := httptest.NewRequest(http.MethodGet, "/v1/maintenance-windows", nil)
	lrec := httptest.NewRecorder()
	d.handleListMaintenanceWindows(lrec, lreq, "ten-1")
	var list []platform.MaintenanceWindow
	_ = json.Unmarshal(lrec.Body.Bytes(), &list)
	if len(list) != 1 || list[0].ID != win.ID {
		t.Fatalf("list should have the window, got %+v", list)
	}

	// delete
	dreq := httptest.NewRequest(http.MethodDelete, "/v1/maintenance-windows/"+win.ID, nil)
	dreq.SetPathValue("id", win.ID)
	drec := httptest.NewRecorder()
	d.handleDeleteMaintenanceWindow(drec, dreq, "ten-1")
	if drec.Code != http.StatusOK {
		t.Fatalf("delete want 200, got %d", drec.Code)
	}
	tn, _ := d.Store.GetTenant(ctx, "ten-1")
	if len(tn.MaintenanceWindows) != 0 {
		t.Errorf("window should be gone, got %+v", tn.MaintenanceWindows)
	}
	// deleting an unknown id → 404
	d2 := httptest.NewRecorder()
	r2 := httptest.NewRequest(http.MethodDelete, "/v1/maintenance-windows/nope", nil)
	r2.SetPathValue("id", "nope")
	d.handleDeleteMaintenanceWindow(d2, r2, "ten-1")
	if d2.Code != http.StatusNotFound {
		t.Errorf("unknown delete want 404, got %d", d2.Code)
	}
}

func TestMaintenanceWindows_Validation(t *testing.T) {
	d := mwDeps(t)
	future := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)
	past := time.Now().Add(-2 * time.Hour).UTC().Format(time.RFC3339)
	cases := map[string]string{
		"no name":         fmt.Sprintf(`{"name":"","starts_at":%q,"ends_at":%q}`, future, future),
		"start after end": fmt.Sprintf(`{"name":"x","starts_at":%q,"ends_at":%q}`, future, past),
		"window in past":  fmt.Sprintf(`{"name":"x","starts_at":%q,"ends_at":%q}`, past, past),
	}
	for name, body := range cases {
		if rec := addMW(d, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s: want 400, got %d: %s", name, rec.Code, rec.Body.String())
		}
	}
}
