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
	Desk       Decider  // optional: the HITL desk (approvals decide)
	GRC        Posturer // optional: the compliance system-of-record (posture)
	Vault      Sealer   // optional: seals OAuth tokens before persistence
	Token      string   // static platform bearer token (required)
	PublicURL  string   // base URL for OAuth redirect_uri (e.g. https://app.example)
	// SlackSigningSecret verifies Slack interactive (approve/reject) callbacks. Empty
	// → the Slack endpoint returns 501.
	SlackSigningSecret string
	// WebhookSecret authenticates inbound provider webhooks (GitHub HMAC / GitLab token).
	// Empty → verification is skipped (a startup warning is logged; dev only).
	WebhookSecret string
	NewID         func() string
}

// NewHandler returns the platform's HTTP handler.
func NewHandler(d Deps) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/tenants", d.platformAuth(d.handleCreateTenant)) // provisioning (no tenant header)
	mux.HandleFunc("POST /v1/webhooks/{kind}", d.auth(d.handleWebhook))
	mux.HandleFunc("GET /v1/findings", d.auth(d.handleFindings))
	mux.HandleFunc("GET /v1/findings/export", d.auth(d.handleFindingsExport))
	mux.HandleFunc("GET /v1/engagements", d.auth(d.handleEngagements))
	mux.HandleFunc("GET /v1/connections", d.auth(d.handleConnections))
	mux.HandleFunc("GET /v1/approvals", d.auth(d.handleApprovals))
	mux.HandleFunc("GET /v1/incidents", d.auth(d.handleIncidents))
	mux.HandleFunc("GET /v1/apps", d.auth(d.handleApps))
	mux.HandleFunc("POST /v1/rescan", d.auth(d.handleRescan))
	mux.HandleFunc("POST /v1/approvals/{id}", d.auth(d.handleApprovalDecide))
	mux.HandleFunc("GET /v1/connect/{kind}", d.auth(d.handleConnectURL))
	mux.HandleFunc("GET /v1/connect/{kind}/callback", d.handleConnectCallback) // OAuth redirect; tenant in state
	mux.HandleFunc("GET /v1/posture/{framework}", d.auth(d.handlePosture))
	mux.HandleFunc("GET /v1/compliance/{framework}/report", d.auth(d.handleComplianceReport))
	mux.HandleFunc("POST /v1/slack/interactive", d.handleSlackInteractive) // Slack-signed, not bearer-auth'd
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

// platformAuth enforces only the platform bearer token (no tenant scope) — for
// provisioning endpoints that create/operate across tenants.
func (d Deps) platformAuth(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if d.Token == "" || r.Header.Get("Authorization") != "Bearer "+d.Token {
			writeJSON(w, http.StatusUnauthorized, errBody("unauthorized"))
			return
		}
		h(w, r)
	}
}

// handleCreateTenant provisions a new tenant (the start of onboarding). Returns the
// tenant with its generated id, which the caller then uses as X-Tenant-ID.
func (d Deps) handleCreateTenant(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Name string `json:"name"`
		Plan string `json:"plan,omitempty"`
	}
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&body); err != nil || body.Name == "" {
		writeJSON(w, http.StatusBadRequest, errBody("a tenant needs a name"))
		return
	}
	t := platform.Tenant{ID: d.newID("ten"), Name: body.Name, Plan: body.Plan}
	if err := d.Store.PutTenant(r.Context(), t); err != nil {
		writeJSON(w, http.StatusInternalServerError, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusCreated, t)
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

	// authenticate the webhook before triggering ANY re-scan: a spoofed payload must not
	// be able to force scans. Verified against the shared secret when one is configured.
	if d.WebhookSecret != "" {
		if v, ok := conn.(connector.WebhookVerifier); ok {
			if err := v.VerifyWebhook(r.Header, body, d.WebhookSecret); err != nil {
				writeJSON(w, http.StatusUnauthorized, errBody("webhook verification failed"))
				return
			}
		}
	}

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

// handleApps returns the tenant's third-party OAuth app inventory (the SaaS/app
// inventory for compliance — all apps with access, not just the risky ones).
func (d Deps) handleApps(w http.ResponseWriter, r *http.Request, tenantID string) {
	apps, err := d.Store.ListThirdPartyApps(r.Context(), tenantID)
	respond(w, apps, err)
}

// handleRescan triggers an immediate re-scan of all the tenant's assets (the API behind
// the dashboard's "Scan now"). Returns how many assets were scanned.
func (d Deps) handleRescan(w http.ResponseWriter, r *http.Request, tenantID string) {
	if d.Runner == nil {
		writeJSON(w, http.StatusNotImplemented, errBody("scanning not configured"))
		return
	}
	n, err := d.Runner.RescanTenant(r.Context(), tenantID)
	if err != nil {
		writeJSON(w, http.StatusBadGateway, errBody(err.Error()))
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"assets_scanned": n})
}

// handleIncidents returns the tenant's OPEN incidents (the continuous-monitoring view:
// what's newly broken since a prior pass). ?status=all returns resolved ones too.
func (d Deps) handleIncidents(w http.ResponseWriter, r *http.Request, tenantID string) {
	all, err := d.Store.ListIncidents(r.Context(), tenantID)
	if err != nil {
		respond(w, nil, err)
		return
	}
	if r.URL.Query().Get("status") == "all" {
		respond(w, all, nil)
		return
	}
	open := make([]platform.Incident, 0, len(all))
	for _, i := range all {
		if i.Status == platform.IncidentOpen {
			open = append(open, i)
		}
	}
	respond(w, open, nil)
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
