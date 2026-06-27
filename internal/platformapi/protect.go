package platformapi

import (
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/protect"
)

// handleProtect returns the runtime-protection posture (Aikido /Protect parity) over the tenant's ingested
// in-app-firewall / RASP events (POST /v1/runtime/events, fed by an OSS sensor like Zen). Grounded (§10):
// the numbers are real ingested events; no events → active:false ("no runtime signal yet"). tsengine does
// not block — it surfaces what the sensor blocked + monitored.
func (d Deps) handleProtect(w http.ResponseWriter, r *http.Request, tenantID string) {
	events, err := d.Store.ListRuntimeEvents(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	respond(w, protect.Compute(events, time.Time{}, 10), nil)
}
