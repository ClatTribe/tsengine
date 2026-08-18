package platformapi

import (
	"strings"
	"testing"
	"time"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// End-to-end wiring: a reportable finding → its incident carries the CERT-In six-hour
// countdown on GET /v1/incidents; the draft is retrievable; filing discharges the duty;
// and a NON-reportable incident is never annotated (the false-alarm refusal).
func TestCERTIn_WiredThroughIncidents(t *testing.T) {
	st := store.NewMemory()
	h := NewHandler(Deps{Store: st, Connectors: connector.NewRegistry(), Token: "platform-tok"})
	ctx := t.Context()

	// A finding annotated as a CERT-In reportable category (as the crosswalk would produce).
	_ = st.PutFinding(ctx, "t1", types.Finding{
		ID: "f-breach", Title: "Public bucket exposes PII", Severity: types.SeverityCritical,
		Compliance: &types.Compliance{CERTIn: []string{"Annexure I: Data breach / data leak"}},
	})
	// A finding with NO CERT-In annotation (memory-safety, say) — its incident must NOT be annotated.
	_ = st.PutFinding(ctx, "t1", types.Finding{ID: "f-noduty", Title: "Info leak note", Severity: types.SeverityLow})

	opened := time.Now().UTC().Add(-90 * time.Minute) // noticed 90m ago → 4h30 left
	_ = st.PutIncident(ctx, platform.Incident{ID: "inc-breach", TenantID: "t1", Title: "Public bucket exposes PII",
		Severity: "critical", Status: platform.IncidentOpen, FindingID: "f-breach", OpenedAt: opened})
	_ = st.PutIncident(ctx, platform.Incident{ID: "inc-noduty", TenantID: "t1", Title: "Info leak note",
		Severity: "low", Status: platform.IncidentOpen, FindingID: "f-noduty", OpenedAt: opened})

	// 1. GET /v1/incidents annotates the reportable one with a countdown, NOT the other.
	body := do(h, "GET", "/v1/incidents", "t1", "").Body.String()
	if !strings.Contains(body, `"certin"`) || !strings.Contains(body, `"minutes_left"`) {
		t.Error("a reportable incident must carry the CERT-In six-hour position")
	}
	if strings.Contains(body, "inc-noduty") && strings.Count(body, `"certin"`) != 1 {
		t.Error("a non-reportable incident must NOT get a CERT-In annotation (no false regulatory alarm)")
	}

	// 2. GET the draft for the reportable incident.
	draft := do(h, "GET", "/v1/incidents/inc-breach/certin-report", "t1", "")
	if draft.Code != 200 || !strings.Contains(draft.Body.String(), "within six hours") {
		t.Fatalf("draft not prepared: %d %s", draft.Code, draft.Body.String())
	}

	// 3. The non-reportable incident refuses a draft (plainly, not by inventing one).
	if bad := do(h, "GET", "/v1/incidents/inc-noduty/certin-report", "t1", ""); bad.Code != 400 {
		t.Errorf("a non-reportable incident must refuse a draft, got %d", bad.Code)
	}

	// 4. Filing requires a named human, and discharges the duty.
	if noName := do(h, "POST", "/v1/incidents/inc-breach/certin-report", "t1", `{}`); noName.Code != 400 {
		t.Errorf("filing without a name must be refused, got %d", noName.Code)
	}
	filed := do(h, "POST", "/v1/incidents/inc-breach/certin-report", "t1", `{"by":"Priya (CISO)"}`)
	if filed.Code != 200 {
		t.Fatalf("filing failed: %d %s", filed.Code, filed.Body.String())
	}
	incs, _ := st.ListIncidents(ctx, "t1")
	var inc platform.Incident
	for _, i := range incs {
		if i.ID == "inc-breach" {
			inc = i
		}
	}
	if inc.CertInReportedAt.IsZero() || inc.CertInReportedBy != "Priya (CISO)" {
		t.Error("filing must persist who filed and when")
	}
}
