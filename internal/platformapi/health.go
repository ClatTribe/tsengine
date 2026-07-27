package platformapi

import (
	"context"
	"errors"
	"net/http"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
)

// health.go splits LIVENESS from READINESS.
//
// `GET /healthz` (in api.go) answers "is this process up?" — a static 200. That is the right
// answer for a restart-on-crash probe, but it is the WRONG signal for a load balancer: it stays
// green while the store is unreachable, so a dead database keeps the box in rotation serving
// errors.
//
// `GET /readyz` answers "can this process actually serve traffic?" by reaching the store. The
// probe is a scoped lookup for a sentinel id that cannot exist: a store that is reachable and
// answering returns store.ErrNotFound, which is SUCCESS here (it proves the query path works
// end to end without reading tenant data or depending on any tenant existing — important on a
// freshly-provisioned box). Any other error means the backend is genuinely unhealthy.
//
// Both endpoints are unauthenticated by design (a probe cannot hold a credential) and neither
// leaks tenant data — /readyz returns only a status and a duration.

// readyProbeID is a sentinel tenant id that must never exist. A store that answers "not found"
// for it has demonstrably executed a query.
const readyProbeID = "__readyz_probe__"

// readyProbeTimeout bounds the probe so a hung backend fails the check instead of hanging the
// probe itself (a hung /readyz reads as a timeout to the LB, but an explicit 503 is clearer and
// keeps the handler from piling up goroutines).
const readyProbeTimeout = 3 * time.Second

// handleReadyz reports whether the platform can serve: 200 when the store answers, 503 otherwise.
func (d Deps) handleReadyz(w http.ResponseWriter, r *http.Request) {
	if d.Store == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "unready", "store": "not configured",
		})
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), readyProbeTimeout)
	defer cancel()

	start := time.Now()
	_, err := d.Store.GetTenant(ctx, readyProbeID)
	took := time.Since(start)

	// ErrNotFound is the healthy answer: the store executed the query and correctly missed.
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		writeJSON(w, http.StatusServiceUnavailable, map[string]any{
			"status": "unready", "store": "unreachable", "error": err.Error(),
			"probe_ms": took.Milliseconds(),
		})
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status": "ready", "store": "ok", "probe_ms": took.Milliseconds(),
	})
}
