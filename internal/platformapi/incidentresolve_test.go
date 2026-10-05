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

// A person closes an incident with a reason; the record names them from the session, never a typed name.
// No reason is refused: "closed" with no reason cannot be told apart from "dismissed without looking".
func TestResolveIncident_NeedsAReasonAndRecordsWho(t *testing.T) {
	ctx := context.Background()
	st := store.NewMemory()
	_ = st.PutTenant(ctx, platform.Tenant{ID: "t1"})
	_ = st.PutUser(ctx, platform.User{ID: "u1", TenantID: "t1", Email: "ana@acme.com", Role: platform.RoleMember})
	_ = st.PutSession(ctx, platform.Session{Token: "s1", UserID: "u1", TenantID: "t1", ExpiresAt: time.Now().Add(time.Hour)})
	_ = st.PutIncident(ctx, platform.Incident{ID: "inc1", TenantID: "t1", RuleID: "cloudcdr::root_console_login", Status: platform.IncidentOpen, OpenedAt: time.Now()})
	d := Deps{Store: st}
	call := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest("POST", "/v1/incidents/inc1/resolve", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer s1")
		req.SetPathValue("id", "inc1")
		rec := httptest.NewRecorder()
		d.handleResolveIncident(rec, req, "t1")
		return rec
	}
	if rec := call(`{}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("no reason must be refused: %d", rec.Code)
	}
	rec := call(`{"reason":"expected: break-glass login by the on-call engineer"}`)
	var inc platform.Incident
	_ = json.Unmarshal(rec.Body.Bytes(), &inc)
	if rec.Code != 200 || inc.Status != platform.IncidentResolved || inc.ResolvedBy != "ana@acme.com" || inc.ResolutionNote == "" {
		t.Fatalf("resolve: %d %+v", rec.Code, inc)
	}
	if inc.AcknowledgedBy != "ana@acme.com" {
		t.Error("closing an incident is taking ownership of it")
	}
}
