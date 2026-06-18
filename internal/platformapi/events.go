package platformapi

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
)

// stateEvent is the live dashboard snapshot pushed over SSE. It is intentionally small —
// the counts that drive the shell (Inbox badge, risk, "new since last scan") — so the
// browser can refresh the current view when any of them change. No timestamp field: it
// must be byte-identical when nothing changed, so we can suppress no-op emits.
type stateEvent struct {
	PendingApprovals int            `json:"pending_approvals"`
	OpenIncidents    int            `json:"open_incidents"`
	Findings         int            `json:"findings"`
	Severity         map[string]int `json:"severity"` // critical|high|medium|low|info → count
}

// tenantSnapshot reads the tenant's current state from the store (grounded — never
// invented). Tenant-scoped like every other store call.
func tenantSnapshot(ctx context.Context, st store.Store, tenantID string) (stateEvent, error) {
	findings, err := st.ListFindings(ctx, tenantID, store.FindingFilter{})
	if err != nil {
		return stateEvent{}, err
	}
	sev := map[string]int{}
	for _, f := range findings {
		sev[string(f.Severity)]++
	}
	approvals, err := st.PendingApprovals(ctx, tenantID)
	if err != nil {
		return stateEvent{}, err
	}
	incidents, err := st.ListIncidents(ctx, tenantID)
	if err != nil {
		return stateEvent{}, err
	}
	open := 0
	for _, i := range incidents {
		if i.Status == platform.IncidentOpen {
			open++
		}
	}
	return stateEvent{
		PendingApprovals: len(approvals),
		OpenIncidents:    open,
		Findings:         len(findings),
		Severity:         sev,
	}, nil
}

// handleEvents streams the tenant's live state to the browser over Server-Sent Events.
// Connection model: the host re-reads the store on a cadence and emits a `state` event
// only when the snapshot changes (a keepalive comment otherwise). This keeps the engine +
// write paths untouched — it's a read-only projection — while giving the console a live
// feed instead of per-navigation polling. The stream ends when the client disconnects
// (request context cancellation).
func (d Deps) handleEvents(w http.ResponseWriter, r *http.Request, tenantID string) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeJSON(w, http.StatusInternalServerError, errBody("streaming unsupported"))
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	w.Header().Set("X-Accel-Buffering", "no") // don't let a reverse proxy buffer the stream

	ctx := r.Context()
	last := ""
	emit := func() {
		snap, err := tenantSnapshot(ctx, d.Store, tenantID)
		if err != nil {
			// transient read error → keep the stream warm, try again next tick
			fmt.Fprint(w, ": error\n\n")
			flusher.Flush()
			return
		}
		b, _ := json.Marshal(snap)
		if string(b) == last {
			fmt.Fprint(w, ": keepalive\n\n")
			flusher.Flush()
			return
		}
		last = string(b)
		fmt.Fprintf(w, "event: state\ndata: %s\n\n", b)
		flusher.Flush()
	}

	emit() // push the initial state immediately on connect

	t := time.NewTicker(sseInterval())
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			emit()
		}
	}
}

// sseInterval is the server-side re-read cadence for the live feed. Opt-in override via
// TSENGINE_SSE_INTERVAL (a Go duration, e.g. "2s"); default 5s.
func sseInterval() time.Duration {
	if v := os.Getenv("TSENGINE_SSE_INTERVAL"); v != "" {
		if d, err := time.ParseDuration(v); err == nil && d > 0 {
			return d
		}
	}
	return 5 * time.Second
}
