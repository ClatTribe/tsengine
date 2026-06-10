// Package platformapi is the multi-tenant HTTP API for the autonomous security team
// platform (docs/autonomous-team.md §3.7). It wires the store + connectors + runner
// behind a small REST surface: receive provider webhooks (→ continuous re-scan), list
// a tenant's findings / engagements / connections, and read the HITL approval queue.
//
// Auth for the MVP is a static platform bearer token plus an X-Tenant-ID header that
// scopes every call; the store enforces isolation on that id. Real per-tenant OAuth
// sessions + the web dashboard come later — this is the API the front-end and Slack
// app consume.
package platformapi

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/ClatTribe/tsengine/internal/connector"
	"github.com/ClatTribe/tsengine/internal/runner"
	"github.com/ClatTribe/tsengine/internal/store"
	"github.com/ClatTribe/tsengine/pkg/platform"
	"github.com/ClatTribe/tsengine/pkg/types"
)

// Deps are the API's collaborators.
type Deps struct {
	Store      store.Store
	Connectors *connector.Registry
	Runner     *runner.Service
	Token      string // static platform bearer token (required)
}

// NewHandler returns the platform's HTTP handler.
func NewHandler(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/webhooks/{kind}", d.auth(d.handleWebhook))
	mux.HandleFunc("GET /v1/findings", d.auth(d.handleFindings))
	mux.HandleFunc("GET /v1/engagements", d.auth(d.handleEngagements))
	mux.HandleFunc("GET /v1/connections", d.auth(d.handleConnections))
	mux.HandleFunc("GET /v1/approvals", d.auth(d.handleApprovals))
	return mux
}

// auth enforces the platform bearer token and extracts the tenant id, passing it to
// the handler via context.
func (d Deps) auth(h func(w http.ResponseWriter, r *http.Request, tenantID string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Token == "" || r.Header.Get("Authorization") != "Bearer "+d.Token {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		tenantID := r.Header.Get("X-Tenant-ID")
		if tenantID == "" {
			writeJSON(w, http.StatusBadRequest, errBody("missing X-Tenant-ID"))
			return
		}
		h(w, r, tenantID)
	}
}

// handleWebhook turns a provider event into triggers and re-scans the matching assets.
func (d Deps) handleWebhook(w http.ResponseWriter, r *http.Request, tenantID string) {
	kind := r.PathValue("kind")
	conn, err := d.Connectors.Get(kind)
	if err != nil {
		writeJSON(w, http.StatusBadRequest, errBody(err.Error()))
		return
	}
	body, _ := io.ReadAll(io.LimitReader(r.Body, 8<<20))

	// find the tenant's active connection of this kind to attribute the event
	conns, _ := d.Store.ListConnections(r.Context(), tenantID)
	var matched bool
	var engagements int
	for _, c := range conns {
		if c.Kind != kind {
			continue
		}
		matched = true
		trigs, werr := conn.Watch(r.Context(), c, body)
		if werr != nil {
			writeJSON(w, http.StatusBadRequest, errBody(werr.Error()))
			return
		}
		for _, t := range trigs {
			if _, rerr := d.Runner.OnTrigger(r.Context(), t); rerr == nil {
				engagements++
			}
		}
	}
	if !matched {
		writeJSON(w, http.StatusNotFound, errBody("no "+kind+" connection for tenant"))
		return
	}
	writeJSON(w, http.StatusAccepted, map[string]int{"engagements_started": engagements})
}

func (d Deps) handleFindings(w http.ResponseWriter, r *http.Request, tenantID string) {
	f, err := d.Store.ListFindings(r.Context(), tenantID, store.FindingFilter{
		Severity: severityParam(r), Status: r.URL.Query().Get("status"),
	})
	respond(w, f, err)
}

func (d Deps) handleEngagements(w http.ResponseWriter, r *http.Request, tenantID string) {
	e, err := d.Store.ListEngagements(r.Context(), tenantID)
	respond(w, e, err)
}

func (d Deps) handleConnections(w http.ResponseWriter, r *http.Request, tenantID string) {
	c, err := d.Store.ListConnections(r.Context(), tenantID)
	respond(w, redactConnections(c), err)
}

func (d Deps) handleApprovals(w http.ResponseWriter, r *http.Request, tenantID string) {
	a, err := d.Store.PendingApprovals(r.Context(), tenantID)
	respond(w, a, err)
}

// --- helpers ---

func respond(w http.ResponseWriter, v any, err error) {
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, v)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func errBody(msg string) map[string]string { return map[string]string{"error": msg} }

func severityParam(r *http.Request) types.Severity {
	return types.Severity(r.URL.Query().Get("severity"))
}

// redactConnections strips the SecretRef before a connection ever leaves the API —
// the OAuth token reference must never reach a client.
func redactConnections(cs []platform.Connection) []platform.Connection {
	out := make([]platform.Connection, len(cs))
	for i, c := range cs {
		c.SecretRef = ""
		out[i] = c
	}
	return out
}
