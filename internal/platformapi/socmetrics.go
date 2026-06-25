package platformapi

import (
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/socmetrics"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// handleSOCMetrics returns the tenant's security-operations scorecard (SLA compliance %, MTTA/MTTR,
// open-incident aging) — the "how is the SOC performing" view. Pure-compute over the tenant's
// incidents + SLA policy; no side effects.
func (d Deps) handleSOCMetrics(w http.ResponseWriter, r *http.Request, tenantID string) {
	incs, err := d.Store.ListIncidents(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	// SLA policy is optional context; a fetch error just means the report has no SLA tracking.
	var sla *platform.SLAPolicy
	if t, terr := d.Store.GetTenant(r.Context(), tenantID); terr == nil {
		sla = t.SLA
	}
	writeJSON(w, http.StatusOK, socmetrics.Compute(incs, sla, time.Now().UTC()))
}
